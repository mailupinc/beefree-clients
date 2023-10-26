import requests


class CustomClientException(Exception):
    detail = "API Error"
    status_code = requests.codes.internal_server_error

    def __init__(self, detail=None, status_code=None) -> None:
        if detail is not None:
            self.detail = detail
        if status_code is not None:
            self.status_code = status_code


class ParserError(CustomClientException):
    """Custom error to handle parser service errors."""

    default_code = "Parser Error"


class TransformerError(CustomClientException):
    """Custom error to handle tansformer service errors."""

    default_code = "Transformer Error"


class InvalidParserConfigurationError(Exception):
    """Custom error to handle else branch when unexpected configuration value is receviced."""

    def __init__(self, message_type):
        self.message = f"Message type unexpected [{message_type}]"
        self.code = 501
