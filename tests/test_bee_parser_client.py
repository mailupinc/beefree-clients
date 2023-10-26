import json
import os
from unittest import TestCase, mock

import pytest
import requests
from base import beepro_vcr
from vcr import VCR

from beefree_clients.clients import BeeMultiParser
from beefree_clients.exceptions import InvalidParserConfigurationError, ParserError


class TestBeeParser(TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.path.dirname(os.path.dirname(__file__))
        with open(f"{path}/tests/data/message.json") as file:
            cls.json_content = json.loads(file.read())
        cls.req = mock.Mock()
        cls.source = "bee-beepro"
        cls.forwarded_for = "0.0.0.0"
        cls.email_client_id = "ClientIdForEmailBuilder"
        cls.page_client_id = "ClientIdForPageBuilder"
        cls.parser_base_url = "https://bee-multiparser.getbee.io/api/"
        cls.parser_auth = ("AuthBeePp", "65a4389571f5f6e801146ffd70903e56e9329d8d3ae38095bd88f2abbeaebe80")

    def test_parser__email__response_ok(self):
        with beepro_vcr.use_cassette(
            "test_parser__email__response_ok",
            serializer="yaml",
            path_transformer=VCR.ensure_suffix(".yaml"),
            match_on=["method", "scheme", "host", "port", "path", "body"],
        ) as cassette:
            parser = BeeMultiParser(
                self.parser_base_url, "email", self.parser_auth, self.email_client_id, self.source, self.forwarded_for
            )
            response = parser.parse_json(self.json_content)

        assert isinstance(response, str) is True
        assert response.startswith("<!DOCTYPE html>")
        assert len(cassette.requests) == 1
        assert cassette.requests[0].url == "https://bee-multiparser.getbee.io/api/v3/parser/email?b=1"
        assert cassette.requests[0].method == "POST"
        assert cassette.requests[0].body == json.dumps(self.json_content).encode()
        assert cassette.requests[0].headers["content-type"] == "application/json"
        assert cassette.requests[0].headers["x-bee-clientid"] == "ClientIdForEmailBuilder"
        assert cassette.requests[0].headers["x-bee-forwarded-for"] == "0.0.0.0"
        assert cassette.requests[0].headers["x-bee-source"] == "bee-beepro"

    def test_parser__page__response_ok(self):
        with beepro_vcr.use_cassette(
            "test_parser__page__response_ok",
            serializer="yaml",
            path_transformer=VCR.ensure_suffix(".yaml"),
            match_on=["method", "scheme", "host", "port", "path", "body"],
        ) as cassette:
            parser = BeeMultiParser(
                self.parser_base_url, "page", self.parser_auth, self.page_client_id, self.source, self.forwarded_for
            )
            response = parser.parse_json(self.json_content)

        assert isinstance(response, str) is True
        assert response.startswith("<!DOCTYPE html>")
        assert len(cassette.requests) == 1
        assert cassette.requests[0].url == "https://bee-multiparser.getbee.io/api/v3/parser/pages"
        assert cassette.requests[0].method == "POST"
        assert cassette.requests[0].body == json.dumps(self.json_content).encode()
        assert cassette.requests[0].headers["content-type"] == "application/json"
        assert cassette.requests[0].headers["x-bee-clientid"] == "ClientIdForPageBuilder"
        assert cassette.requests[0].headers["x-bee-forwarded-for"] == "0.0.0.0"
        assert cassette.requests[0].headers["x-bee-source"] == "bee-beepro"

    def test_parser__unknown_message_type__raises_exception(self):
        with self.assertRaises(InvalidParserConfigurationError) as exc:
            _ = BeeMultiParser(
                self.parser_base_url,
                "not-page-not-email",
                self.parser_auth,
                self.email_client_id,
                self.source,
                self.forwarded_for,
            )

        assert exc.exception.code == 501
        assert exc.exception.message == "Message type unexpected [not-page-not-email]"

    def test_parser__no_message__response_empty(self):
        with beepro_vcr.use_cassette(
            "test_parser__no_message__response_empty",
            serializer="yaml",
            path_transformer=VCR.ensure_suffix(".yaml"),
            match_on=["method", "scheme", "host", "port", "path", "body"],
        ) as cassette:
            parser = BeeMultiParser(
                self.parser_base_url, "page", self.parser_auth, self.email_client_id, self.source, self.forwarded_for
            )

            assert parser.parse_json({}) == ""
            assert parser.parse_json("") == ""
            assert parser.parse_json(None) == ""
            assert cassette.play_count == 0

    def test_parser__parser_error__timeout(self):
        parser = BeeMultiParser(
            self.parser_base_url, "page", self.parser_auth, self.email_client_id, self.source, self.forwarded_for
        )
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            mock_requests.side_effect = requests.exceptions.Timeout()
            with self.assertRaises(ParserError) as exc:
                _ = parser.parse_json(self.json_content)

        assert exc.exception.status_code == 502
        assert str(exc.exception.detail) == "BeeMultiparser service not available"

    @pytest.mark.skip("this behaviour is changed on parser side")
    @beepro_vcr.use_cassette(serializer="yaml", path_transformer=VCR.ensure_suffix(".yaml"))
    def test_parser__http_error(self):
        parser = BeeMultiParser(
            self.parser_base_url, "page", self.parser_auth, self.email_client_id, self.source, self.forwarded_for
        )
        with self.assertRaises(ParserError) as exc:
            parser.parse_json({"bad": "structure"})

        assert exc.exception.status_code == 400
        assert str(exc.exception.detail) == "Bad Request"

    @pytest.mark.skip("?")
    def test_name_of_the_parser_service_must_be_multiparser(self):
        # assert "bee-multiparser" in settings.BEE_PARSER_URL
        pass

    def test_bee_parser_client_instances_share_session(self):
        bmpc_1 = BeeMultiParser(
            self.parser_base_url, "email", self.parser_auth, self.email_client_id, self.source, self.forwarded_for
        )
        bmpc_2 = BeeMultiParser(
            self.parser_base_url, "page", self.parser_auth, self.page_client_id, self.source, self.forwarded_for
        )
        bmpc_3 = BeeMultiParser(
            self.parser_base_url, "email", self.parser_auth, self.email_client_id, self.source, self.forwarded_for
        )

        assert bmpc_1.session == bmpc_2.session == bmpc_3.session
