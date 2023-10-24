"""Define project clients."""
import logging
from abc import ABC, abstractmethod
from datetime import date, datetime
from time import time
from types import MappingProxyType
from typing import Any
from urllib.parse import urljoin

import requests
from django.conf import settings
from django.http import HttpResponse
from django.utils import timezone
from requests import HTTPError, Response, Session
from requests.adapters import HTTPAdapter, Retry
from rest_framework import status
from rest_framework.exceptions import NotFound, PermissionDenied
from twilio.rest import Client as TwilioClient

from .exceptions import (
    BeeEarError,
    BeeProxyError,
    CustomAPIException,
    EhawkError,
    NotificationError,
    PendoClientError,
    PendoClientNotConfigured,
    ServiceUnavailableException,
    ToplyneError,
)

billing_portal_session = requests.Session()
logger = logging.getLogger(__name__)

GLOBAL_CLIENT_SESSIONS = MappingProxyType(
    {
        "BeeProxy": Session(),
        "BeeMultiparser": Session(),
        "Toplyne": Session(),
        "BeeCSAPI": Session(),
        "BeeHtmlTransformer": Session(),
        "PartnerStack": Session(),
        "Ehawk": Session(),
        "Zapier": Session(),
        "Bee Ear": Session(),
    }
)


class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, timeout, *args, **kwargs):
        self.timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


class HttpAdapterFactory(ABC):
    """Factory that represents a combination of a timeout and a retry strategy"""

    def __call__(self) -> HTTPAdapter:
        return TimeoutHTTPAdapter(timeout=self._get_timeout(), max_retries=self._get_retry_strategy())

    @abstractmethod
    def _get_timeout(self) -> int:
        """Returns the timeout in seconds"""

    @abstractmethod
    def _get_retry_strategy(self) -> Retry:
        """Returns the retry strategy"""


class StatelessFastServiceHTTPAdapter(HttpAdapterFactory):
    def _get_timeout(self) -> int:
        return 10

    def _get_retry_strategy(self) -> Retry:
        return Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "PATCH", "DELETE", "OPTIONS"],
            backoff_factor=1,
        )


class StatelessSlowServiceHTTPAdapter(HttpAdapterFactory):
    def _get_timeout(self) -> int:
        return 120

    def _get_retry_strategy(self) -> Retry:
        return Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "PATCH", "DELETE", "OPTIONS"],
            backoff_factor=1,
        )


class StatefulFastServiceHTTPAdapter(HttpAdapterFactory):
    def _get_timeout(self) -> int:
        return 10

    def _get_retry_strategy(self) -> Retry:
        return Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1,
        )


class StatefulSlowServiceHTTPAdapter(HttpAdapterFactory):
    def _get_timeout(self) -> int:
        return 30

    def _get_retry_strategy(self) -> Retry:
        return Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1,
        )


class TimeoutOnlyHTTPAdapter(HttpAdapterFactory):
    def _get_timeout(self) -> int:
        return 10

    def _get_retry_strategy(self) -> Retry:
        return Retry(total=0)


class BaseClient:
    """Implement some shared custom configuration of requests Session object"""

    service_name: str
    content_type: str
    adapter: HttpAdapterFactory
    base_url: str = ""
    base_auth: tuple = ()
    header_auth: dict[str, str] = {}
    error: CustomAPIException = CustomAPIException

    def __init__(self, headers: dict | None = None):
        self.headers = headers or {}
        self._update_headers()
        self.session = self._get_session()
        self.session.mount("https://", self.adapter())
        self.session.mount("http://", self.adapter())
        self._set_response_hooks()

    @staticmethod
    def _assert_status_hook(response: Response, *args, **kwargs) -> Response:
        response.raise_for_status()
        return response

    def _set_response_hooks(self) -> None:
        """Set response hook"""
        self.session.hooks["response"].append(self._assert_status_hook)

    def _get_session(self) -> Session:
        return GLOBAL_CLIENT_SESSIONS.get(self.service_name, Session())

    def _update_headers(self) -> None:
        self.headers.update({"content-type": self.content_type})
        if self.header_auth:
            self.headers.update(self.header_auth)

    def _request(
        self,
        method: str,
        url: str,
        query_params: dict | None = None,
        data: str | dict | None = None,
        payload: dict | None = None,
    ) -> Response:
        try:
            response = self.session.request(
                method,
                url=url,
                params=query_params,
                data=data,
                json=payload,
                headers=self.headers,
                auth=self.base_auth,  # type: ignore
            )
        except (requests.ConnectionError, requests.Timeout) as e:
            raise self.error(
                detail=f"{self.service_name} service not available",
                status_code=requests.codes.bad_gateway,
            ) from e
        except requests.exceptions.HTTPError as e:
            raise self.error(detail=e.response.reason, status_code=e.response.status_code) from e
        return response

    def _post(
        self,
        url: str,
        data: str | dict | None = None,
        payload: dict | None = None,
        query_params: dict | None = None,
    ) -> Response:
        return self._request("POST", url, data=data, payload=payload, query_params=query_params)

    def _get(self, url: str, query_params: dict | None = None) -> Response:
        return self._request("GET", url, query_params=query_params)


class BEEProxyClient(BaseClient):
    service_name = "BeeProxy"
    content_type = "application/json"
    adapter = StatelessFastServiceHTTPAdapter()
    base_url = settings.BEEPRO_PROXY_URL
    header_auth = {"BEE-PROXY-APIKEY": settings.BEEPRO_PROXY_API_KEY}
    error = BeeProxyError

    def message_path(self, data: dict) -> dict:
        url = urljoin(self.base_url, "api/v1/message-path/")
        try:
            response = self._post(url, payload=data)
            assert response.status_code == status.HTTP_200_OK
        except (self.error, AssertionError):
            return {}
        return response.json()

    def encode_id(self, value: int) -> str:
        url = urljoin(self.base_url, "api/v1/encode/id/")
        try:
            response = self._post(url, payload={"value": value})
            assert response.status_code == status.HTTP_200_OK
        except (self.error, AssertionError):
            return ""
        return response.json()

    def decode_id(self, value: str) -> int:
        url = urljoin(self.base_url, f"api/v1/decode/id/{value}")
        try:
            response = self._get(url)
            assert response.status_code == status.HTTP_200_OK
        except (self.error, AssertionError):
            return 0
        return response.json()

    def check_css_font(self, data: dict) -> bool:
        url = urljoin(self.base_url, "/api/v1/check-css-font/")
        try:
            response = self._post(url, payload=data)
        except self.error:
            return False
        return response.status_code == 200

    def parse_css_font_url(self, data: dict):
        url = urljoin(self.base_url, "/api/v1/parse-css-font-url/")
        response = self._post(url, payload=data)
        return response.json()


class ToplyneClient(BaseClient):
    service_name = "Toplyne"
    content_type = "application/json"
    adapter = StatefulFastServiceHTTPAdapter()
    base_url = settings.TOPLYNE_API_URL
    error = ToplyneError

    def __init__(self):
        headers = {"Authorization": f"Bearer {settings.TOPLYNE_API_TOKEN}"}
        super().__init__(headers)

    def send_single_seat_event(self, data: dict) -> dict:
        url = urljoin(self.base_url, "/v1/upload/accounts/events")
        payload = {"events": [data]}
        response = self._post(url, payload=payload)
        if response.status_code != status.HTTP_202_ACCEPTED:
            raise HTTPError(response=response)
        return response.json()

    def send_seat_events(self, data: list[dict]):
        if len(data) > 500:
            raise self.error("The max number of events you can insert per call is 500.", 400)
        url = urljoin(self.base_url, "/v1/upload/accounts/events")
        payload = {"events": data}
        response = self._post(url, payload=payload)
        if response.status_code != status.HTTP_202_ACCEPTED:
            raise HTTPError(response=response)
        return response.json()


class TDVClient(BaseClient):
    service_name = "TDV"
    content_type = "application/json"
    adapter = StatelessSlowServiceHTTPAdapter()
    base_url = settings.TDV_API_URL
    base_auth = (settings.TDV_USER, settings.TDV_PASSWORD)

    def get_seat_history(self, start_date: datetime, end_date: datetime) -> list[dict]:
        url = urljoin(self.base_url, "/json/bu_bee/toplyne/toplyne_seat_history")
        query = f"?dtBegin={start_date.isoformat()}&dtEnd={end_date.isoformat()}"
        url_with_query = url + query
        response = self._get(url_with_query)
        if response.status_code != status.HTTP_200_OK:
            raise HTTPError(response=response)
        data = response.json()
        return data["toplyne_seat_historyResponse"]["toplyne_seat_historyResult"]


class PartnerstackClient(BaseClient):
    """The Partnerstack client."""

    service_name = "PartnerStack"
    content_type = "application/json"
    adapter = StatefulSlowServiceHTTPAdapter()
    base_url = settings.PARTNERSTACK_CUSTOMER_URL
    base_auth = (settings.PARTNERSTACK_USER, settings.PARTNERSTACK_PASSWORD)

    def create_customer(self, data: dict) -> bool:
        """Submit data to Partnerstack"""
        try:
            self._post(self.base_url, payload=data)
        except self.error:
            return settings.PARTNERSTACK_IGNORE_ERRORS
        return True


class EhawkClient(BaseClient):
    """The Ehawk client."""

    service_name = "Ehawk"
    content_type = "application/x-www-form-urlencoded"
    adapter = StatelessFastServiceHTTPAdapter()
    base_url = settings.EHAWK_API_URL
    error = EhawkError

    def check_score(self, data: dict) -> dict:
        vetting_url = f"{settings.EHAWK_API_URL}/"
        data["apikey"] = settings.EHAWK_APY_KEY
        response = self._post(vetting_url, data=data)
        return response.json()

    def revet_score(self, data: dict) -> dict:
        vetting_url = f"{settings.EHAWK_API_URL}/"
        data["apikey"] = settings.EHAWK_APY_KEY
        data["revet"] = "true"
        response = self._post(vetting_url, data=data)
        return response.json()

    def get_new_alerts(self) -> dict:
        new_alerts_url = f"{settings.EHAWK_FEED_API_URL}/alert/list/"
        data = {"apikey": settings.EHAWK_APY_KEY}
        response = self._post(new_alerts_url, data=data)
        return response.json()

    def get_last_24h_alerts(self) -> dict:
        last_24h_alerts_url = f"{settings.EHAWK_FEED_API_URL}/alert/list24/"
        data = {"apikey": settings.EHAWK_APY_KEY}
        response = self._post(last_24h_alerts_url, data=data)
        return response.json()

    def email_domain_always_good(self, email_domain) -> dict:
        tag_url = f"{settings.EHAWK_FEED_API_URL}/tag/set/"
        data = {
            "apikey": settings.EHAWK_APY_KEY,
            "emaildomain": email_domain,
            "reason": "always good",
        }
        response = self._post(tag_url, data=data)
        return response.json()


class ZapierClient(BaseClient):
    """The Zapier client."""

    service_name = "Zapier"
    content_type = "application/json"
    adapter = StatefulFastServiceHTTPAdapter()
    base_url = settings.ZAPIER_BASE_URL

    def _post_with_log(self, url: str, payload: dict, sub_id: int) -> Response:
        try:
            response = self._post(url, payload=payload)
        except self.error as e:
            logger.info(f"Error while sending data to Zapier for subscription: {sub_id} - {e}")
            raise e
        else:
            logger.info(f"Data sent to Zapier for subscription: {sub_id} - Data: {payload}")
        return response

    def _send_user_data(self, payload: dict, sub_id: int) -> Response:
        url = self.base_url + settings.ZAPIER_SUBSCRIPTION_CRUD_ZAP_PATH
        response = self._post_with_log(url, payload, sub_id)
        return response.json()

    def _old_send_user_data(self, payload: dict, sub_id: int) -> Response:
        response = self._post_with_log(settings.OLD_ZAPIER_BASE_URL, payload, sub_id)
        return response.json()

    def send_subscription_crud(self, payload: dict, sub_id: int, old: bool) -> Response:
        return self._old_send_user_data(payload, sub_id) if old else self._send_user_data(payload, sub_id)

    def send_new_user_activated(self, payload: dict, sub_id: int) -> Response:
        url = self.base_url + settings.ZAPIER_NEW_USER_ZAP_PATH
        response = self._post_with_log(url, payload, sub_id)
        return response.json()

    def send_new_trial_activated(self, payload: dict, sub_id: int) -> Response:
        url = self.base_url + settings.ZAPIER_NEW_TRIAL_ZAP_PATH
        response = self._post_with_log(url, payload, sub_id)
        return response.json()


# TODO Port all the clients below to the new shared BaseClient


class BillingPortalClient:
    """The Billing Portal client."""

    headers = {"Authorization": f"Api-Key {settings.BILLING_PORTAL_API_KEY}"}

    def __init__(self):
        self.session = billing_portal_session

    def post(self, resource_uri, data):
        """Create data."""
        url = f"{settings.BILLING_PORTAL_API_BASE_URL}{resource_uri}"
        return self.session.post(url, headers=self.headers, json=data, timeout=40)

    def get(self, resource_uri):
        """Retrieve data."""
        url = f"{settings.BILLING_PORTAL_API_BASE_URL}{resource_uri}"
        return self.session.get(url, headers=self.headers, timeout=20)

    def put(self, resource_uri, data):
        """Update data."""
        url = f"{settings.BILLING_PORTAL_API_BASE_URL}{resource_uri}"
        return self.session.put(url, headers=self.headers, data=data, timeout=40)

    def delete(self, resource_uri, data):
        """Delete data."""
        url = f"{settings.BILLING_PORTAL_API_BASE_URL}{resource_uri}"
        return self.session.delete(url, headers=self.headers, data=data, timeout=20)


class SubscriptionClient(BillingPortalClient):
    """Billing Portal's Subscription client."""

    def post(self, data):
        """Create subscription."""
        return super().post(settings.BILLING_PORTAL_SUBSCRIPTION_URI, data)

    def get(self, subscription_id):
        """Retrieve subscription."""
        resource_uri = f"{settings.BILLING_PORTAL_SUBSCRIPTION_URI}{subscription_id}/"
        return super().get(resource_uri)

    def get_chargify(self, subscription_id):
        """Retrieve chargify subscription."""
        resource_uri = f"{settings.BILLING_PORTAL_CHARGIFY_SUBSCRIPTION_URI}{subscription_id}/"
        return super().get(resource_uri)

    def get_renewals(self, subscription_id):
        """Retrieve renewals."""
        resource_uri = (
            f"{settings.BILLING_PORTAL_SUBSCRIPTION_URI}{subscription_id}/"
            f"{settings.BILLING_PORTAL_GET_RENEWALS_URI}"
        )
        return super().get(resource_uri)

    def get_renewal_charges(self, subscription_id, current_add_users):
        """Retrieve renewal charges."""
        resource_uri = (
            f"{settings.BILLING_PORTAL_SUBSCRIPTION_URI}{subscription_id}/"
            f"{settings.BILLING_PORTAL_GET_RENEWAL_CHARGES_URI}"
            f"?current_add_users={current_add_users}"
        )
        return super().get(resource_uri)

    def get_invoices(self, subscription_id):
        """Retrieve invoices."""
        resource_uri = (
            f"{settings.BILLING_PORTAL_SUBSCRIPTION_URI}{subscription_id}/" f"{settings.BILLING_PORTAL_INVOICES_URI}"
        )
        return super().get(resource_uri)

    def put(self, subscription_id, data):
        """Update subscription."""
        resource_uri = f"{settings.BILLING_PORTAL_SUBSCRIPTION_URI}{subscription_id}/"
        return super().put(resource_uri, data)

    def put_account(self, subscription_id, data):
        """Update subscription."""
        resource_uri = (
            f"{settings.BILLING_PORTAL_SUBSCRIPTION_URI}{subscription_id}/{settings.BILLING_PORTAL_UPDATE_ACCOUNT_URI}"
        )
        return super().put(resource_uri, data)

    def put_additional(self, subscription_id, data):
        """Update subscription with additional charges."""
        resource_uri = (
            f"{settings.BILLING_PORTAL_SUBSCRIPTION_URI}"
            f"{subscription_id}/"
            f"{settings.BILLING_PORTAL_USER_QUANTITY_URI}"
        )
        return super().put(resource_uri, data)

    def delete(self, subscription_id, data):
        """Delete subscription."""
        resource_uri = f"{settings.BILLING_PORTAL_SUBSCRIPTION_URI}{subscription_id}/"
        return super().delete(resource_uri, data)

    def get_fee_breakdown(self, subscription_id):
        """Retrieve fee breakdown."""
        resource_uri = (
            f"{settings.BILLING_PORTAL_SUBSCRIPTION_URI}{subscription_id}/"
            f"{settings.BILLING_PORTAL_GET_FEE_BREAKDOWN_URI}"
        )
        return super().get(resource_uri)

    def cancel(self, subscription_id, data):
        """Send notification to Zuora when a subscription is set to Cancelled in BeePro."""
        resource_uri = (
            f"{settings.BILLING_PORTAL_SUBSCRIPTION_URI}{subscription_id}/"
            f"{settings.BILLING_PORTAL_DELETE_SUBSCRIPTION}"
        )
        return super().delete(resource_uri, data)

    def additional_plan(self, subscription_id, data):
        """Update subscription with additional charges."""
        resource_uri = (
            f"{settings.BILLING_PORTAL_SUBSCRIPTION_URI}{subscription_id}/"
            f"{settings.BILLING_PORTAL_ADD_ADDITIONAL_PLAN}"
        )
        return super().put(resource_uri, data)


class CatalogClient(BillingPortalClient):
    """Billing Portal's catalog client."""

    PLAN_NAMES_MAP = []

    def __init__(self, plan_names_map):
        CatalogClient.PLAN_NAMES_MAP = plan_names_map
        super().__init__()

    def get_plans(self):
        response = super().get(settings.BILLING_PORTAL_GET_CATALOG_URI)
        try:
            response.raise_for_status()
        except requests.HTTPError:
            raise ServiceUnavailableException
        plans = response.json()

        for plan in plans:
            seat_price = CatalogClient._get_seat_price(plan)
            plan["IncludedSeats"] = CatalogClient._get_included_seats(plan)
            plan["PerSeatPrice"] = seat_price
            plan["PerSeatPriceInCents"] = int(seat_price * 100) if seat_price else None
            plan["is_legacy"] = CatalogClient._get_legacy_status(plan)

        CatalogClient._append_free_plan(plans)

        return plans

    @staticmethod
    def _get_application_plan(handle):
        return CatalogClient.PLAN_NAMES_MAP.get(handle)

    @staticmethod
    def _get_included_seats(plan):
        application_plan = CatalogClient._get_application_plan(plan["Handle"])
        return settings.RESTRICTIONS["IncludedSeats"].get(application_plan)

    @staticmethod
    def _get_legacy_status(plan):
        application_plan = CatalogClient._get_application_plan(plan["Handle"])
        return application_plan in settings.LEGACY_PLANS

    @staticmethod
    def _get_seat_price(plan) -> float | None:
        try:
            return next(
                x["Pricing"][0]["Tiers"][0]["price"] for x in plan["ProductRatePlanCharges"] if x["UOM"] == "User"
            )
        except StopIteration:
            return None

    @staticmethod
    def _append_free_plan(plans):
        free_plan = {
            "ID": "",
            "Name": "Free",
            "Handle": "beepro_free",
            "Interval": -1,
            "IntervalUnit": "month",
            "Price": 0,
            "PriceInCents": 0,
            "Description": "",
            "ProductFamily": {"Name": "BEE"},
            "ProductRatePlanCharges": [],
            "IncludedSeats": 1,
            "PerSeatPrice": None,
            "PerSeatPriceInCents": None,
        }
        is_legacy = CatalogClient._get_legacy_status(free_plan)
        free_plan.update({"is_legacy": is_legacy})
        plans.append(free_plan)


class AlfredException(Exception):
    pass


class AlfredClient:
    """Alfred client."""

    def get_cdn_usage_for_customer(self, customer_id, date_from=None, date_to=None, full_year=False, graph=True):
        """Get CDN Usage for customer for the specified period."""
        url = f"{settings.BEE_ALFRED_URL}/api/beepro-cdn-traffic/{customer_id}/"
        return requests.get(
            url,
            params={
                "date_from": date_from,
                "date_to": date_to,
                "full_year": full_year,
                "graph": graph,
            },
        )

    def get_bulk_cdn_usage_for_customer(self, customer_list):
        """Get CDN Usage for customer for the specified period."""
        url = f"{settings.BEE_ALFRED_URL}/api/beepro-bulk-cdn-traffic/"
        return requests.post(url, json={"customers": customer_list})

    def manage_cdn_response(self, res):
        try:
            res.raise_for_status()
            return res.json()
        except Exception:
            return {}

    def get_monthly_cdn_usage_for_customer(self, customer_id):
        """Get CDN Usage for customer for the current month."""
        url = f"{settings.BEE_ALFRED_URL}/api/beepro-cdn-monthly-traffic/{customer_id}/"
        return requests.get(url)

    def get_customers_with_cdn_over_limit(self, usages_limit):
        """Get customers that have exceeded the CDN usages limit specified."""
        url = f"{settings.BEE_ALFRED_URL}/api/beepro-cdn-over-limit/?usages_limit={usages_limit}"
        return requests.get(url)


class PaymentClient(BillingPortalClient):
    """Billing Portal's catalog client."""

    def get_iframe_config(self, data):
        """Retrieve iframe config."""
        resource_uri = f"{settings.BILLING_PORTAL_GET_PAYMENTS_URI}{settings.BILLING_PORTAL_GET_IFRAME_CONFIG_URI}"
        return super().post(resource_uri, data)

    def set_new_payment(self, data):
        """Set new payment id."""
        resource_uri = f"{settings.BILLING_PORTAL_GET_PAYMENTS_URI}{settings.BILLING_PORTAL_SET_NEW_PAYMENT_URI}"
        return super().put(resource_uri, data)

    def create_test_payment(self):  # pragma: no cover
        """Create a new payment, only for tests"""
        if settings.BEE_ENV == "pro":
            raise PermissionDenied
        resource_uri = f"{settings.BILLING_PORTAL_GET_PAYMENTS_URI}{settings.BILLING_PORTAL_CREATE_TEST_PAYMENT_URI}"
        return super().post(resource_uri, data={})


class InvoiceClient(BillingPortalClient):
    """Billing Portal's catalog client."""

    def get_pdf(self, invoice_id):
        """Retrieve catalog."""
        resource_uri = f"{settings.BILLING_PORTAL_INVOICES_URI}" f"{invoice_id}/pdf/"
        return super().get(resource_uri)


class NotificationCenterClient:
    def send_notification(
        self, sender_id: int, recipient_id: int, customer_id: int, type: str, extra_fields: dict = {}
    ):
        data = {
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "customer_id": customer_id,
            "type": type,
            "extra_fields": extra_fields,
        }

        try:
            res = self.send(data)
        except (requests.ConnectionError, requests.Timeout):
            logger.error("NotificationClient Error: Connection Error")
            raise NotificationError

        if res.status_code != 201:
            raise NotificationError

        try:
            return res.json()["id"]
        except KeyError:
            raise NotificationError

    def send_bulk_notification(
        self, sender_id: int, customer_id: int, recipient_ids: list, type: str, extra_fields: dict = {}
    ):
        data = {
            "sender_id": sender_id,
            "recipient_ids": recipient_ids,
            "customer_id": customer_id,
            "type": type,
            "extra_fields": extra_fields,
        }
        try:
            res = self.send_bulk(data)
        except (requests.ConnectionError, requests.Timeout):
            logger.error("NotificationClient Error: Connection Error")
            return None

        if res.status_code != 201:
            logger.error(f"NotificationClient Error: status code {res.status_code}")
            return None
        return res

    def list_notifications(self, user_id: int, customer_id: int, params: dict):
        url = f"{settings.NOTIFICATION_CENTER_URL}/api/v1/notifications/{user_id}/{customer_id}/list/"
        return requests.get(url, params=params)

    def send(self, data: dict):
        url = f"{settings.NOTIFICATION_CENTER_URL}/api/v1/notifications/send/"
        return requests.post(url, json=data)

    def send_bulk(self, data: dict):
        url = f"{settings.NOTIFICATION_CENTER_URL}/api/v1/notifications/send-bulk/"
        return requests.post(url, json=data)

    def mark(self, data: dict):
        url = f"{settings.NOTIFICATION_CENTER_URL}/api/v1/notifications/mark/"
        return requests.post(url, json=data)

    def clean_old(self):
        url = f"{settings.NOTIFICATION_CENTER_URL}/api/v1/notifications/clean-old/"
        return requests.post(url)

    def delete_filtered(self, data: dict):
        url = f"{settings.NOTIFICATION_CENTER_URL}/api/v1/notifications/delete-filtered/"
        return requests.post(url, json=data)

    def transform_urls(self, data: dict, user_id: int, customer_id: int):
        for page_name in ["previous", "next"]:
            url = data[page_name]
            if url is not None:
                data[page_name] = self._replace_urls(url, user_id, customer_id)
        return data

    def _replace_urls(self, url: str, user_id: int, customer_id: int):
        return url.replace(
            f"{settings.NOTIFICATION_CENTER_URL}/api/v1/notifications/{user_id}/{customer_id}/list/",
            f"{settings.BACKEND_BASE_URL}/api/v1/customers/{customer_id}/notifications/list/",
        )


class PendoClient:
    def __init__(self) -> None:
        if None in [
            settings.PENDO_API_KEY,
            settings.PENDO_TRACK_EVENT_KEY,
            settings.PENDO_API_BASE_URL,
        ]:
            raise PendoClientNotConfigured()

        self.api_key = settings.PENDO_API_KEY
        self.track_event_key = settings.PENDO_TRACK_EVENT_KEY
        self.base_url = settings.PENDO_API_BASE_URL

    def _post(self, url: str, payload=None, key: str | None = None) -> dict:
        headers = {"x-pendo-integration-key": key}
        try:
            response = requests.post(url=url, headers=headers, json=payload)  # type: ignore
            response.raise_for_status()
        except (requests.ConnectionError, requests.Timeout):
            raise PendoClientError("Pendo service not available", status.HTTP_502_BAD_GATEWAY)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                raise NotFound from e
            error = e.response.json()
            raise PendoClientError(error, e.response.status_code)
        else:
            return response.json()

    def track_event(self, customer, name: str, properties: dict | None = None):
        user = customer.owner
        data = {
            "type": "track",
            "event": name,
            "visitorId": str(user.id),
            "accountId": customer.pendo_account_id,
            "timestamp": int(time() * 1000),
        }
        if properties:
            data["properties"] = properties

        url = urljoin(self.base_url, "data/track")
        response = requests.post(url, json=data, headers={"x-pendo-integration-key": self.track_event_key})
        if response.status_code != status.HTTP_200_OK:
            raise PendoClientError()

    def save_custom_metadata(self, custom_metadata: list):
        url = urljoin(self.base_url, "/api/v1/metadata/account/custom/value/")
        return self._post(url, custom_metadata, self.api_key)


class CertificatesManagerClient:
    def validate_certificates(self, domain):
        url = f"{settings.CERTIFICATES_MANAGER_URL}/validate-certificates/"
        return requests.post(url, json={"domain": domain})

    def bulk_validate_certificates(self, domains):
        url = f"{settings.CERTIFICATES_MANAGER_URL}/bulk-validate-certificates/"
        return requests.post(url, json={"domains": domains})


class TwilioCustomClient:  # pragma: no cover
    def send_sms(self, phone: str):
        return self._get_twilio_sms_service().verifications.create(to=phone, channel="sms")

    def check_sms_code(self, phone: str, code: str):
        return self._get_twilio_sms_service().verification_checks.create(to=phone, code=code)

    def _get_twilio_sms_service(self):
        twilio_client = TwilioClient(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        return twilio_client.verify.v2.services(settings.TWILIO_SMS_VERIFICATION_SERVICE_ID)


class AuthClient:
    def _get_client_credentials(self, product_handle: str) -> tuple[str | None, str | None]:
        """Returns plugin credentials to be used on bee-auth"""
        if product_handle == "nl":
            return settings.BEE_PRO_CLIENT_ID, settings.BEE_PRO_CLIENT_SECRET
        elif product_handle == "page":
            return settings.BEE_PRO_PAGE_CLIENT_ID, settings.BEE_PRO_PAGE_CLIENT_SECRET
        return None, None

    def get_auth_token_v1(self, product_handle, plugin_label):
        client_id, client_secret = self._get_client_credentials(product_handle)
        data = {
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
            "plugin_label": plugin_label,
        }
        return requests.post(settings.BEE_AUTH_ENDPOINT, data=data)

    def get_auth_token_v2(self, product_handle, brand, plugin_label):
        client_id, client_secret = self._get_client_credentials(product_handle)
        data = {
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
            "uid": f"{brand.customer_id}_{brand.pk}",
        }
        if plugin_label:
            data["plugin_label"] = plugin_label
        return requests.post(settings.BEE_AUTH_ENDPOINT_V2, json=data)


class BeeEarClient(BaseClient):
    service_name = "Bee Ear"
    content_type = "application/json"
    adapter = TimeoutOnlyHTTPAdapter()
    base_url = settings.BEE_EAR_BASE_URL
    application = settings.BEE_EAR_APPLICATION
    error = BeeEarError

    def track_event(self, name: str, data: dict[str, Any] = {}) -> Response:
        url = urljoin(self.base_url, "store/")
        data = {
            "application": self.application,
            "name": name,
            "data": data,
        }
        return self._post(url, payload=data)

    def get_event_count(
        self,
        name: str,
        start_date: date,
        end_date: date,
        data_filter: dict[str, Any] = {},
    ) -> int:
        url = urljoin(self.base_url, "count/")
        data = {
            "application": self.application,
            "name": name,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "data": data_filter,
        }
        response = self._post(url, payload=data)
        return response.json()["count"]


class DataServiceClient(BaseClient):
    class DataServiceHTTPAdapter(HttpAdapterFactory):
        def _get_timeout(self) -> int:
            return 10

        def _get_retry_strategy(self) -> Retry:
            return Retry(
                total=3,
                allowed_methods=["POST"],
                status_forcelist=[429, 500, 502, 503, 504],
                backoff_factor=1,
            )

    service_name = "Data Queue"
    content_type = "application/json"
    adapter = DataServiceHTTPAdapter()
    base_url = settings.DATA_SERVICE_URL
    header_auth = {"x-api-key": settings.DATA_SERVICE_API_KEY}

    def track_action(self, action_type: str, data: dict[str, Any]):
        if settings.DATA_SERVICE_CALLS_ENABLED:
            self._post(
                self.base_url,
                query_params={"type": action_type},
                payload={"ts": timezone.now().isoformat()} | data,
            )


class BeeHookClient(BaseClient):
    class HookServiceHTTPAdapter(HttpAdapterFactory):
        def _get_timeout(self) -> int:
            return 30

        def _get_retry_strategy(self) -> Retry:
            return Retry(
                total=1,
            )

    service_name = "(Web)Hooks"
    content_type = "application/json"
    adapter = HookServiceHTTPAdapter()
    base_url = settings.HOOK_SERVICE_BASE_URL

    def _transform_response(self, response: Response) -> HttpResponse:
        headers = response.headers
        if headers.get("Connection", None):
            del headers["Connection"]
        return HttpResponse(
            content=response.content,
            status=response.status_code,
            headers=headers,
        )

    def get_hook_list(self, brand_id: int) -> HttpResponse:
        response = self._get(f"{self.base_url}/brands/{brand_id}/hooks/")
        return self._transform_response(response)

    def new_hook(self, brand_id: int, payload: dict[str, Any]) -> HttpResponse:
        response = self._post(f"{self.base_url}/brands/{brand_id}/hooks/", payload=payload)
        return self._transform_response(response)

    def get_hook(self, brand_id: int, hook_id: int) -> HttpResponse:
        response = self._get(f"{self.base_url}/brands/{brand_id}/hooks/{hook_id}")
        return self._transform_response(response)

    def update_hook(self, brand_id: int, hook_id: int, payload: dict[str, Any]) -> HttpResponse:
        response = self._request(
            method="PATCH",
            url=f"{self.base_url}/brands/{brand_id}/hooks/{hook_id}",
            payload=payload,
        )
        return self._transform_response(response)

    def delete_hook(self, brand_id: int, hook_id: int) -> HttpResponse:
        response = self._request(method="DELETE", url=f"{self.base_url}/brands/{brand_id}/hooks/{hook_id}")
        return self._transform_response(response)

    def call_hook(self, brand_id: int, payload: dict[str, Any]) -> HttpResponse:
        response = self._post(f"{self.base_url}/brands/{brand_id}/hooks/call/", payload=payload)
        return self._transform_response(response)

    def call_test_hook(self, payload: dict[str, Any]) -> HttpResponse:
        response = self._post(f"{self.base_url}/hooks/call/test/", payload=payload)
        return self._transform_response(response)

    def get_event_list(self) -> HttpResponse:
        response = self._get(f"{self.base_url}/hooks/events/")
        return self._transform_response(response)
