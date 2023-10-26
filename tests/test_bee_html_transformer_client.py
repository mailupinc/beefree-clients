from unittest import TestCase, mock

import requests

from beefree_clients.clients import BeeHtmlTransformerClient
from beefree_clients.exceptions import TransformerError


class TestBeeHtmlTransfomerClient(TestCase):
    def setUp(self) -> None:
        self.transformer_base_url = "http://pre-bee-html-transformer.getbee.info/api/v1/"

    def test_bee_transformer_ok(self):
        transformer_endpoint = "preheader/transform/"
        token = "a-token"
        transformer = BeeHtmlTransformerClient(self.transformer_base_url, token)
        transformer_payload = {"html": "html text", "preheader_text": "my-preheaader"}
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            mock_requests.return_value.status_code = 200
            transformer.transform_html(transformer_payload, transformer_endpoint)
            self.assertEqual(
                mock_requests.call_args,
                mock.call(
                    "POST",
                    url="http://pre-bee-html-transformer.getbee.info/api/v1/preheader/transform/",
                    params=None,
                    data=None,
                    json=transformer_payload,
                    headers={"Authorization": "Bearer a-token", "content-type": "application/json"},
                    auth=(),
                ),
            )

    def test_bee_transformer_connection_error(self):
        transformer_endpoint = "preheader/transform/"
        token = "a-token"
        transformer = BeeHtmlTransformerClient(self.transformer_base_url, token)
        transformer_payload = {"html": "html text", "preheader_text": "my-preheaader"}
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            mock_requests.side_effect = requests.exceptions.ConnectionError()
            with self.assertRaises(TransformerError):
                transformer.transform_html(transformer_payload, transformer_endpoint)

    def test_bee_transformer_bad_response(self):
        transformer_endpoint = "preheader/transform/"
        token = "a-token"
        transformer = BeeHtmlTransformerClient(self.transformer_base_url, token)
        transformer_payload = {"html": "html text", "preheader_text": "my-preheaader"}
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            response = mock.Mock
            response.status_code = 401
            response.reason = "Not Authenticated"
            mock_requests.side_effect = requests.exceptions.HTTPError(response=response)
            with self.assertRaises(TransformerError) as error:
                transformer.transform_html(transformer_payload, transformer_endpoint)
            error.exception.status_code = 401
