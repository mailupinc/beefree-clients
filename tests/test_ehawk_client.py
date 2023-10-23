from unittest import TestCase, mock

import requests
from base import beepro_vcr
from django.conf import settings
from rest_framework import status

from beefree_clients.clients import EhawkClient
from beefree_clients.exceptions import EhawkError


class TestEHwakClient(TestCase):
    def test_check_score(self):
        data = {
            "email": "john.smith@yahoo.com",
            "ip": "2.233.113.68",
            "domain": "yahoo.com",
            "firstname": "John",
            "lastname": "Smith",
            "referrer": "https://beefree.io/",
            "useragent": "A User Agent",
        }
        ehawk_client = EhawkClient()
        with beepro_vcr.use_cassette("test_check_score.json") as cassette:
            response = ehawk_client.check_score(data)
            request = cassette.requests[0]
        assert request.url == f"{settings.EHAWK_API_URL}/"
        assert request.method == "POST"
        assert (
            request.body.decode() == "email=john.smith%40yahoo.com&ip=2.233.113.68&domain=yahoo.com&firstname=John"
            "&lastname=Smith&referrer=https%3A%2F%2Fbeefree.io%2F&useragent=A+User+Agent"
        )
        assert len(response) == 8
        assert response["score"] == {"risk": -97, "total": -97, "type": "Very High Risk"}

    def test_check_score_ko(self):
        data = {
            "email": "john.smith@yahoo.com",
            "ip": "2.233.113.68",
            "domain": "yahoo.com",
            "firstname": "John",
            "lastname": "Smith",
        }
        ehawk_client = EhawkClient()
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            mock_requests.side_effect = requests.exceptions.ConnectionError()
            with self.assertRaises(EhawkError):
                ehawk_client.check_score(data)

    def test_get_new_alerts(self):
        ehawk_client = EhawkClient()
        with beepro_vcr.use_cassette("test_get_new_alerts.json") as cassette:
            response = ehawk_client.get_new_alerts()
            request = cassette.requests[0]
        assert request.url == f"{settings.EHAWK_FEED_API_URL}/alert/list/"
        assert request.method == "POST"
        assert response["status"] == 200
        assert response["response"] == [
            {
                "transaction_id": "56fbed88a7c018",
                "type": "ip",
                "value": "10.1.1.1",
                "reason": "Phishing",
                "transaction_score": "-38",
                "alert_score_impact": "-70",
                "estimated_new_score": "-108",
                "username": "user1234",
                "transaction_fingerprint": "fb713c209",
                "transaction_date": "2016-04-10 06:00:00 (UTC)",
                "alert_date": "2016-06-10 10:00:00 (UTC)",
            }
        ]

    def test_get_new_alerts_ko(self):
        ehawk_client = EhawkClient()
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            response = mock.Mock
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            response.reason = "Internal server error"
            mock_requests.side_effect = requests.exceptions.HTTPError(response=response)
            with self.assertRaises(EhawkError):
                ehawk_client.get_new_alerts()

    def test_get_last_24h_alerts(self):
        ehawk_client = EhawkClient()
        with beepro_vcr.use_cassette("test_get_last_24h_alerts.json") as cassette:
            response = ehawk_client.get_last_24h_alerts()
            request = cassette.requests[0]
        assert request.url == f"{settings.EHAWK_FEED_API_URL}/alert/list24/"
        assert request.method == "POST"
        assert response["status"] == 200
        assert response["response"] == [
            {
                "transaction_id": "56fbed88a7c018",
                "type": "ip",
                "value": "10.1.1.1",
                "reason": "Phishing",
                "transaction_score": "-38",
                "alert_score_impact": "-70",
                "estimated_new_score": "-108",
                "username": "user1234",
                "transaction_fingerprint": "fb713c209",
                "transaction_date": "2016-04-10 06:00:00 (UTC)",
                "alert_date": "2016-06-10 10:00:00 (UTC)",
            }
        ]

    def test_get_last_24h_alerts_ko(self):
        ehawk_client = EhawkClient()
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            response = mock.Mock
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            response.reason = "Internal server error"
            mock_requests.side_effect = requests.exceptions.HTTPError(response=response)
            with self.assertRaises(EhawkError):
                ehawk_client.get_new_alerts()

    def test_revet_score(self):
        data = {
            "email": "john.smith@yahoo.com",
            "ip": "2.233.113.68",
            "domain": "yahoo.com",
            "firstname": "John",
            "lastname": "Smith",
            "referrer": "https://beefree.io/",
            "useragent": "A User Agent",
        }
        ehawk_client = EhawkClient()
        with beepro_vcr.use_cassette("test_revet_score.json") as cassette:
            response = ehawk_client.revet_score(data)
            request = cassette.requests[0]

        assert request.url == f"{settings.EHAWK_API_URL}/"
        assert request.method == "POST"
        assert (
            request.body.decode() == "email=john.smith%40yahoo.com&ip=2.233.113.68&domain=yahoo.com&firstname=John"
            "&lastname=Smith&referrer=https%3A%2F%2Fbeefree.io%2F&useragent=A+User+Agent"
            "&revet=true"
        )
        assert len(response) == 8
        assert response["score"] == {"risk": -15, "total": -15, "type": "Some Risk"}

    def test_revet_score_ko(self):
        data = {
            "email": "john.smith@yahoo.com",
            "ip": "2.233.113.68",
            "domain": "yahoo.com",
            "firstname": "John",
            "lastname": "Smith",
            "referrer": "https://beefree.io/",
            "useragent": "A User Agent",
        }
        ehawk_client = EhawkClient()
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            mock_requests.side_effect = requests.exceptions.ConnectionError()
            with self.assertRaises(EhawkError):
                ehawk_client.revet_score(data)

    def test_email_domain_always_good(self):
        ehawk_client = EhawkClient()
        with beepro_vcr.use_cassette("test_email_domain_always_good.json") as cassette:
            response = ehawk_client.email_domain_always_good("testago.com")
            request = cassette.requests[0]
        assert request.url == f"{settings.EHAWK_FEED_API_URL}/tag/set/"
        assert request.method == "POST"
        assert response["status"] == 200

    def test_email_domain_always_good_ko(self):
        ehawk_client = EhawkClient()
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            response = mock.Mock
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            response.reason = "Internal server error"
            mock_requests.side_effect = requests.exceptions.HTTPError(response=response)
            with self.assertRaises(EhawkError):
                ehawk_client.email_domain_always_good("test.com")
