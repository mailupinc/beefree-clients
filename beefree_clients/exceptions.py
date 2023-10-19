from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import APIException
from rest_framework.status import HTTP_503_SERVICE_UNAVAILABLE


class CustomException(Exception):
    def __init__(self, message=None, code=None):
        self.message = message
        self.code = code


class NotificationError(Exception):
    pass


class CustomAPIException(APIException):
    default_code = "API Error"

    def __init__(self, detail, status_code):
        self.status_code = status_code
        super().__init__(detail)


class PendoClientNotConfigured(CustomException):
    """Custom error to handle Pendo configuration errors."""

    pass


class PendoClientError(CustomException):
    """Custom error to handle Pendo service errors."""

    pass


class EhawkError(CustomAPIException):
    """Custom error to handle Ehawk service errors."""

    default_code = "Ehwak Error"


class BeeProxyError(CustomAPIException):
    """Custom error to handle BeeProxy service errors."""

    default_code = "BeeProxy Error"


class BeeEarError(CustomAPIException):
    """Custom error to handle BEE Ear service errors."""

    default_code = "BEE Ear Error"


class ServiceUnavailableException(APIException):
    status_code = HTTP_503_SERVICE_UNAVAILABLE
    default_detail = _("Service unavailable.")
    default_code = "service_unavailable"


class ToplyneError(CustomAPIException):
    """Custom error to handle ToplyneError service errors."""

    default_code = "Toplyne Error"
