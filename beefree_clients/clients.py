"""Define project clients."""
import json
import logging
from abc import ABC, abstractmethod
from types import MappingProxyType
from typing import Literal
from urllib.parse import urljoin

import requests
from requests import Response, Session
from requests.adapters import HTTPAdapter, Retry

from .exceptions import CustomAPIException, InvalidParserConfigurationError, ParserError, TransformerError

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

    def __init__(self, base_url: str, headers: dict | None = None):
        self.base_url = base_url
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


class BeeHtmlTransformerClient(BaseClient):
    """Bee HTML transformer wrapper class."""

    service_name = "BeeHtmlTransformer"
    content_type = "application/json"
    adapter = StatelessFastServiceHTTPAdapter()
    error = TransformerError

    def __init__(self, base_url, token: str):
        headers = {"Authorization": f"Bearer {token}"}
        super().__init__(base_url, headers)

    def transform_html(self, payload: dict, transformer_endpoint: str) -> str:
        if payload:
            url = self.base_url + transformer_endpoint
            transformer_response = self._post(url=url, payload=payload)
            response_json = transformer_response.json()
            transformed_html = response_json["html"]
        else:
            transformed_html = ""
        return transformed_html


class BeeMultiParser(BaseClient):
    service_name = "BeeMultiparser"
    content_type = "application/json"
    adapter = StatelessFastServiceHTTPAdapter()
    error = ParserError

    def __init__(
        self,
        base_url: str,
        message_type: Literal["email", "page"],
        base_auth: tuple = (),
        client_id: str | None = None,
        source: str | None = None,
        forwarded_for: str | None = None,
    ):
        self.message_type = message_type
        self.base_auth = base_auth
        headers = self._headers(client_id, source, forwarded_for)
        super().__init__(base_url, headers)

    def _headers(self, client_id, source, forwarded_for):
        if self.message_type not in ["email", "page"]:
            raise InvalidParserConfigurationError(self.message_type)
        headers = {"x-bee-clientid": client_id, "x-bee-source": source, "x-bee-forwarded-for": forwarded_for}
        return headers

    def parse_json(self, message_json: dict, query_params: dict | None = None) -> str:
        if self.message_type == "email":
            endpoint = "v3/parser/email?b=1"
        elif self.message_type == "page":
            endpoint = "v3/parser/pages"
        url = urljoin(self.base_url, endpoint)
        message_html = ""
        if message_json:
            json_string = json.dumps(message_json).encode("utf-8")
            response = self._post(url, data=json_string, query_params=query_params)
            message_html = response.text
        return message_html
