import logging
from unittest import TestCase, mock
from unittest.mock import call

import requests
from rest_framework import status

from beefree_clients.clients import ZapierClient
from beefree_clients.exceptions import CustomAPIException


class TestZapierClient(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        logging.disable(logging.NOTSET)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        logging.disable(logging.CRITICAL)

    def mocked_zapier_response(self, return_status, **kwargs):
        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

            def raise_for_status(self):
                if self.status_code != status.HTTP_200_OK:
                    raise requests.RequestException

        return MockResponse({"ok"}, return_status)

    def test_send_subscription_crud_success(self):
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_zapier:
            with self.assertLogs("beefree_clients.clients", level="INFO") as log:
                mock_zapier.side_effect = [self.mocked_zapier_response(status.HTTP_200_OK)]
                response = ZapierClient().send_subscription_crud({"key": "value"}, "A-999", False)
        assert response == {"ok"}
        assert "Data sent to Zapier for subscription: A-999" in log.output[0]
        mock_zapier.assert_called()
        assert mock_zapier.call_args == call(
            "POST",
            url="https://hooks.zapier.com/hooks/catch/6002268/oebygeo/",
            params=None,
            data=None,
            json={"key": "value"},
            headers={"content-type": "application/json"},
            auth=(),
        )

    def test_send_subscription_crud_fail(self):
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_zapier:
            with self.assertLogs("beefree_clients.clients", level="INFO") as log:
                with self.assertRaises(CustomAPIException):
                    response = mock.Mock
                    response.status_code = 401
                    response.reason = "Not Authenticated"
                    mock_zapier.side_effect = requests.HTTPError(response=response)
                    ZapierClient().send_subscription_crud({"key": "value"}, "A-999", True)
        assert "Error while sending data to Zapier for subscription: A-999" in log.output[0]
        mock_zapier.assert_called()
        assert mock_zapier.call_args == call(
            "POST",
            url="https://hooks.zapier.com/hooks/catch/fake/",
            params=None,
            data=None,
            json={"key": "value"},
            headers={"content-type": "application/json"},
            auth=(),
        )

    def test_send_new_user_activated_success(self):
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_zapier:
            with self.assertLogs("beefree_clients.clients", level="INFO") as log:
                mock_zapier.side_effect = [self.mocked_zapier_response(status.HTTP_200_OK)]
                response = ZapierClient().send_new_user_activated({"key": "value"}, "A-999")
        assert response == {"ok"}
        assert "Data sent to Zapier for subscription: A-999" in log.output[0]
        mock_zapier.assert_called()
        assert mock_zapier.call_args == call(
            "POST",
            url="https://hooks.zapier.com/hooks/catch/10076726/bl7ioe3/",
            params=None,
            data=None,
            json={"key": "value"},
            headers={"content-type": "application/json"},
            auth=(),
        )

    def test_send_new_user_activated_fail(self):
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_zapier:
            with self.assertLogs("beefree_clients.clients", level="INFO") as log:
                with self.assertRaises(CustomAPIException):
                    mock_zapier.side_effect = requests.ConnectionError
                    ZapierClient().send_new_user_activated({"key": "value"}, "A-999")
        assert "Error while sending data to Zapier for subscription: A-999" in log.output[0]
        mock_zapier.assert_called()
        assert mock_zapier.call_args == call(
            "POST",
            url="https://hooks.zapier.com/hooks/catch/10076726/bl7ioe3/",
            params=None,
            data=None,
            json={"key": "value"},
            headers={"content-type": "application/json"},
            auth=(),
        )

    def test_send_new_trial_activated_success(self):
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_zapier:
            with self.assertLogs("beefree_clients.clients", level="INFO") as log:
                mock_zapier.side_effect = [self.mocked_zapier_response(status.HTTP_200_OK)]
                response = ZapierClient().send_new_trial_activated({"key": "value"}, "A-999")
        assert response == {"ok"}
        assert "Data sent to Zapier for subscription: A-999 - Data: {'key': 'value'}" in log.output[0]
        mock_zapier.assert_called()
        assert mock_zapier.call_args == call(
            "POST",
            url="https://hooks.zapier.com/hooks/catch/10076726/bl7ioe3/",
            params=None,
            data=None,
            json={"key": "value"},
            headers={"content-type": "application/json"},
            auth=(),
        )

    def test_send_new_trial_activated_fail(self):
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_zapier:
            with self.assertLogs("beefree_clients.clients", level="INFO") as log:
                with self.assertRaises(CustomAPIException):
                    mock_zapier.side_effect = requests.Timeout
                    ZapierClient().send_new_trial_activated({"key": "value"}, "A-999")

        mock_zapier.assert_called()
        assert mock_zapier.call_args == call(
            "POST",
            url="https://hooks.zapier.com/hooks/catch/10076726/bl7ioe3/",
            params=None,
            data=None,
            json={"key": "value"},
            headers={"content-type": "application/json"},
            auth=(),
        )
        assert log.output == [
            "INFO:beefree_clients.clients:"
            "Error while sending data to Zapier for subscription: A-999 - Zapier service not available"
        ]
