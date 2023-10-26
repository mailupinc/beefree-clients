from rest_framework import status
from rest_framework.exceptions import APIException

# class CustomException(Exception):
#     def __init__(self, message=None, code=None):
#         self.message = message
#         self.code = code


class CustomAPIException(APIException):
    default_code = "API Error"

    def __init__(self, detail, status_code):
        self.status_code = status_code
        super().__init__(detail)


class ParserError(CustomAPIException):
    """Custom error to handle parser service errors."""

    default_code = "Parser Error"


class TransformerError(CustomAPIException):
    """Custom error to handle tansformer service errors."""

    default_code = "Transformer Error"


class InvalidParserConfigurationError(Exception):
    """Custom error to handle else branch when unexpected configuration value is receviced."""

    def __init__(self, message_type):
        self.message = f"Message type unexpected [{message_type}]"
        self.code = status.HTTP_501_NOT_IMPLEMENTED
