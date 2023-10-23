from unittest import TestCase, mock

import requests

from beefree_clients.clients import PartnerstackClient


class TestPartnerstackClient(TestCase):
    def test_partnerstack_create_customer_ok(self):
        psc = PartnerstackClient()
        data = {"key1": "value1", "key2": "value2"}
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            mock_requests.return_value.status_code = 200
            response = psc.create_customer(data)
            assert response is True

    def test_partnerstack_create_customer_ko(self):
        psc = PartnerstackClient()
        data = {"key1": "value1", "key2": "value2"}
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            mock_requests.side_effect = requests.exceptions.ConnectionError()
            response = psc.create_customer(data)
            assert response is False
