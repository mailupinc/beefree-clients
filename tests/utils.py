"""Define test utils."""


import json
import re

from django.conf import settings
from django.utils.translation import gettext_lazy as _
from requests import HTTPError


def FreePlan(obj):
    return settings.FREE


def FreelancerPlan(obj):
    return settings.FREELANCER


def TeamPlan(obj):
    return settings.TEAM


def AgencyPlan(obj):
    return settings.AGENCY


def EnterprisePlan(obj):
    return settings.ENTERPRISE


class ResponseMock:
    """Define response mock."""

    requests = None

    def __init__(self, method, url, **kwargs):
        """Override initialisation."""
        if self.requests is None:
            raise SystemExit(_("Did you forget to pass a list of requests?"))
        requests_left = len(self.requests)
        for request in self.requests:
            if (
                self._uri_matches(request, url)
                and self._method_matches(request, method)
                and self._payloads_match(kwargs, request)
            ):
                self.text = self._get_mock_data(request)
                self.status_code = request["status_code"]
                self.method = request["method"]
                self.headers = kwargs.get("headers", {})
                break
            else:
                requests_left = requests_left - 1
        if not requests_left:
            raise SystemExit(_(f"Check your '{method.upper()}' mock for '{url}', with payload {str(kwargs)}"))

    def _is_valid_path(self, value):
        """Check whether value is valid path."""
        return type(value) in (str, tuple)

    def _get_mock_data(self, request):
        """Return mock data from file."""
        if self._is_valid_path(request["return_value"]):
            data_filepath = f'{settings.BASE_DIR}/{request["return_value"]}'
            if data_filepath.endswith(".json"):
                try:
                    with open(data_filepath) as file_data:
                        data = json.load(file_data)
                except FileNotFoundError as e:
                    raise SystemExit(e)
            elif data_filepath.endswith(".pdf"):
                with open(data_filepath, "rb") as file_data:
                    file_bytes = file_data.read()
                    self.content = file_bytes
                    data = request["return_value"]
            else:
                data = request["return_value"]
        else:
            data = request["return_value"]
        return json.dumps(data)

    def _payloads_match(self, kwargs, request):
        """Check whether payload matches."""
        payload_attrs = ("json", "data", "params")
        for attr in payload_attrs:
            payload_exists = attr in request and attr in kwargs
            payload_differs = payload_exists and request[attr] != kwargs[attr]
            if payload_differs:
                return False
        return True

    def _method_matches(self, request, method):
        """Check whether HTTP method matches."""
        return request["method"] == method.upper()

    def _uri_matches(self, request, url):
        """Check whether URI matches."""
        use_regexp = request.get("use_regexp", False)
        if use_regexp:
            pattern = re.compile(request.get("uri", ""))
            match = pattern.match(url)
            return bool(match)
        return "uri" in request and url.endswith(request["uri"])

    def raise_for_status(self):
        """Override raising exception for status."""
        if self.status_code >= 400:
            raise HTTPError("Mocked HTTP error", response=self)

    def json(self):
        """Override json loader."""
        return json.loads(self.text)


def mock_zapier_call(*args, **kwargs):
    return


def count_bucket_objs(objects, expected_count):
    count = 0
    for obj in objects:
        count += 1
    assert count == expected_count


def check_tag_set(s3, is_present, customer_path=None):
    tag = {"Key": "to-hide", "Value": "true"}
    for obj in s3.list_objects(Bucket=settings.CDN_STORAGE_BUCKET)["Contents"]:
        if customer_path and customer_path not in obj["Key"]:
            continue
        tags = s3.get_object_tagging(Bucket=settings.CDN_STORAGE_BUCKET, Key=obj["Key"])
        if is_present:
            assert tag in tags["TagSet"]
        else:
            assert tag not in tags["TagSet"]


def mocked_notification_center_send(return_value=None):
    if not return_value:
        return_value = {"id": 1}
    return {
        "uri": "https://pre-bee-notification-center.getbee.info/api/v1/notifications/send/",
        "method": "POST",
        "status_code": 201,
        "return_value": return_value,
    }


def mocked_notification_center_send_bulk(return_value=None):
    if not return_value:
        return_value = {"id": 1}
    return {
        "uri": "https://pre-bee-notification-center.getbee.info/api/v1/notifications/send-bulk/",
        "method": "POST",
        "status_code": 201,
        "return_value": return_value,
    }


def mocked_notification_center_delete_filtered(return_value=None):
    if not return_value:
        return_value = {"id": 1}
    return {
        "uri": "https://pre-bee-notification-center.getbee.info/api/v1/notifications/delete-filtered/",
        "method": "POST",
        "status_code": 200,
        "return_value": return_value,
    }


def mocked_send_email(return_value=None):
    if not return_value:
        return_value = {}
    return {"uri": "api/v2.0/Messages/SendTemplate", "method": "POST", "status_code": 200, "return_value": {}}


def mocked_call_hook(brand_id: int):
    return {
        "uri": f"/brands/{brand_id}/hooks/call/",
        "method": "POST",
        "status_code": 200,
        "return_value": {"success": True},
    }


def mocked_multiparser_email(return_value=None):
    if not return_value:
        return_value = '{"key":"value"}'
    return {
        "uri": "https://bee-multiparser.getbee.io/api/v3/parser/email?b=1",
        "method": "POST",
        "status_code": 200,
        "return_value": return_value,
    }


def mocked_connector_outlook(return_value=None):
    if not return_value:
        return_value = {
            "detail": "Outlook campaign created.",
            "preview_url": "https://outlook.live.com/owa/?ItemID=AQMkALcAGFqvAAAA&exvsurl=1&viewmodel=ReadMessageItem",
        }
    return {
        "uri": "https://pre-bee-connectors.getbee.info/api/outlook/campaigns/",
        "method": "POST",
        "params": "output=outlookWeb",
        "status_code": 200,
        "return_value": return_value,
    }
