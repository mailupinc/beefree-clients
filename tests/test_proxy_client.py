from unittest import TestCase, mock

import pytest
import requests
from base import beepro_vcr

from beefree_clients.clients import BEEProxyClient
from beefree_clients.exceptions import BeeProxyError


class TestBeeProxyClient(TestCase):
    def test_bee_proxy_client_instances_share_session(self):
        bpc1 = BEEProxyClient()
        bpc2 = BEEProxyClient()
        bpc3 = BEEProxyClient()

        assert bpc1.session == bpc2.session == bpc3.session

    def test_bee_proxy_client_message_path_ok(self):
        with beepro_vcr.use_cassette(
            "test_bee_proxy_client_message_path_ok.json",
            match_on=["method", "scheme", "host", "port", "path", "body"],
        ) as cassette:
            bpc = BEEProxyClient()
            message_data = {
                "customer_id": 1,
                "brand_id": 2,
                "project_id": 3,
                "message_id": 4,
            }

            response = bpc.message_path(message_data)

            assert response == "3T4B-VhC8-YI31-aR30"
            assert len(cassette.requests) == 1
            assert cassette.requests[0].url == "https://pre-bee-beepro-proxy.getbee.info/api/v1/message-path/"
            assert cassette.requests[0].method == "POST"
            assert cassette.requests[0].body == b'{"customer_id": 1, "brand_id": 2, "project_id": 3, "message_id": 4}'

    def test_bee_proxy_client_message_path_empty_if_proxy_error(self):
        with beepro_vcr.use_cassette(
            "test_bee_proxy_client_message_path_empty_if_proxy_error.json",
            match_on=["method", "scheme", "host", "port", "path", "body"],
        ) as cassette:
            bpc = BEEProxyClient()
            message_data = {
                "customer_id": 1,
                "brand_id": 2,
                "project_id": 3,
            }

            response = bpc.message_path(message_data)

            assert response == {}
            assert len(cassette.requests) == 1
            assert cassette.requests[0].url == "https://pre-bee-beepro-proxy.getbee.info/api/v1/message-path/"
            assert cassette.requests[0].method == "POST"
            assert cassette.requests[0].body == b'{"customer_id": 1, "brand_id": 2, "project_id": 3}'

    def test_bee_proxy_client_message_path_empty_if_proxy_ko(self):
        message_data = {
            "customer_id": 1,
            "brand_id": 2,
            "project_id": 3,
            "message_id": 4,
        }
        bpc = BEEProxyClient()
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            mock_requests.side_effect = requests.exceptions.ConnectionError()
            response = bpc.message_path(message_data)
            assert response == {}

    @beepro_vcr.use_cassette(match_on=["method", "scheme", "host", "port", "path", "body"])
    def test_bee_proxy_client_check_css_font_true(self):
        data = {"url": "https://fonts.googleapis.com/css?family=Tangerine"}
        bpc = BEEProxyClient()

        response = bpc.check_css_font(data)

        assert response is True

    @beepro_vcr.use_cassette(match_on=["method", "scheme", "host", "port", "path", "body"])
    def test_bee_proxy_client_check_css_font_false(self):
        data = {"url": "https://wrong.url"}
        bpc = BEEProxyClient()
        response = bpc.check_css_font(data)
        assert response is False

    @beepro_vcr.use_cassette(match_on=["method", "scheme", "host", "port", "path", "body"])
    def test_bee_proxy_client_parse_css_font_bad_url(self):
        data = {"url": "https://wrong.url"}
        bpc = BEEProxyClient()
        with pytest.raises(BeeProxyError):
            _ = bpc.parse_css_font_url(data)

    @beepro_vcr.use_cassette(match_on=["method", "scheme", "host", "port", "path", "body"])
    def test_bee_proxy_client_parse_css_font_ok(self):
        url = (
            "https://fonts.googleapis.com/css2?family=Montserrat+Alternates:ital,wght@0,100;0,200;0,300;0,400;1,100"
            "&family=Open+Sans:ital,wght@0,300;0,400;1,300&family=Rubik:wght@400;600;900"
        )
        data = {"url": url}
        bpc = BEEProxyClient()
        response = bpc.parse_css_font_url(data)
        assert len(response) == 9

    @beepro_vcr.use_cassette(match_on=["method", "scheme", "host", "port", "path", "body"])
    def test_bee_proxy_client_encode_id_ok(self):
        bpc = BEEProxyClient()
        encoded_id = bpc.encode_id(1234)
        assert encoded_id == "f62f"

    def test_bee_proxy_client_encode_id_ko(self):
        bpc = BEEProxyClient()
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            mock_requests.side_effect = requests.exceptions.ConnectionError()
            encoded_id = bpc.encode_id(1234)
            assert encoded_id == ""

    @beepro_vcr.use_cassette(match_on=["method", "scheme", "host", "port", "path", "body"])
    def test_bee_proxy_client_decode_id_ok(self):
        bpc = BEEProxyClient()
        encoded_id = bpc.decode_id("f62f")
        assert encoded_id == 1234

    def test_bee_proxy_client_decode_id_ko(self):
        bpc = BEEProxyClient()
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            mock_requests.side_effect = requests.exceptions.ConnectionError()
            encoded_id = bpc.decode_id("f62f")
            assert encoded_id == 0
