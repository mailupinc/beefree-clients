from unittest import TestCase, mock

import requests
from django.conf import settings
from rest_framework import status
from utils import ResponseMock

from beefree_clients.clients import NotificationCenterClient
from beefree_clients.exceptions import NotificationError


class TestNotificationCenterClient(TestCase):
    def mocked_notification_center_send(self, status_code, return_value):
        return {
            "uri": "https://pre-bee-notification-center.getbee.info/api/v1/notifications/send/",
            "method": "POST",
            "status_code": status_code,
            "return_value": return_value,
        }

    def mocked_notification_center_send_bulk(self, status_code, return_value):
        return {
            "uri": "https://pre-bee-notification-center.getbee.info/api/v1/notifications/send-bulk/",
            "method": "POST",
            "status_code": status_code,
            "return_value": return_value,
        }

    def test_transform_urls(self):
        previous = f"{settings.NOTIFICATION_CENTER_URL}/api/v1/notifications/1/2/list/"
        next = f"{settings.NOTIFICATION_CENTER_URL}/api/v1/notifications/1/2/list/?page=2"
        other = f"{settings.NOTIFICATION_CENTER_URL}/api/v1/notifications/1/2/list/?page=3"
        data = {"previous": previous, "next": next, "other": other}
        expected_previous_url = f"{settings.BACKEND_BASE_URL}/api/v1/customers/2/notifications/list/"
        expected_next_url = f"{settings.BACKEND_BASE_URL}/api/v1/customers/2/notifications/list/?page=2"
        actual_data = NotificationCenterClient().transform_urls(data, 1, 2)
        self.assertEqual(actual_data["previous"], expected_previous_url)
        self.assertEqual(actual_data["next"], expected_next_url)
        self.assertEqual(actual_data["other"], other)

    @mock.patch("beefree_clients.clients.requests.sessions.Session.request")
    def test_send_notification__success(self, mock):
        expected_notification_id = 1
        ResponseMock.requests = [
            self.mocked_notification_center_send(status.HTTP_201_CREATED, {"id": expected_notification_id})
        ]
        mock.side_effect = ResponseMock

        actual_notification_id = NotificationCenterClient().send_notification(
            sender_id=1, recipient_id=2, customer_id=4, type="mention"
        )

        self.assertEqual(actual_notification_id, expected_notification_id)
        self.assertEqual(len(mock.mock_calls), 1)
        res_data = mock.mock_calls[0].kwargs["json"]
        self.assertEqual(res_data["sender_id"], 1)
        self.assertEqual(res_data["recipient_id"], 2)
        self.assertEqual(res_data["customer_id"], 4)
        self.assertEqual(res_data["type"], "mention")
        self.assertEqual(res_data["extra_fields"], {})

    @mock.patch("beefree_clients.clients.requests.sessions.Session.request")
    def test_send_notification__status_error(self, mock):
        ResponseMock.requests = [self.mocked_notification_center_send(status.HTTP_400_BAD_REQUEST, {})]
        mock.side_effect = ResponseMock

        with self.assertRaises(NotificationError):
            NotificationCenterClient().send_notification(sender_id=1, recipient_id=2, customer_id=4, type="mention")

    @mock.patch("beefree_clients.clients.requests.sessions.Session.request")
    def test_send_notification__malformed_json(self, mock):
        ResponseMock.requests = [self.mocked_notification_center_send(status.HTTP_201_CREATED, {})]
        mock.side_effect = ResponseMock

        with self.assertRaises(NotificationError):
            NotificationCenterClient().send_notification(sender_id=1, recipient_id=2, customer_id=4, type="mention")

    @mock.patch("beefree_clients.clients.requests.sessions.Session.request")
    def test_send_notification__connection_error(self, mock):
        mock.side_effect = requests.exceptions.ConnectionError()

        with self.assertRaises(NotificationError):
            NotificationCenterClient().send_notification(sender_id=1, recipient_id=2, customer_id=4, type="mention")

    @mock.patch("beefree_clients.clients.requests.sessions.Session.request")
    def test_send_notification__timeout_error(self, mock):
        mock.side_effect = requests.exceptions.Timeout()

        with self.assertRaises(NotificationError):
            NotificationCenterClient().send_notification(sender_id=1, recipient_id=2, customer_id=4, type="mention")

    @mock.patch("beefree_clients.clients.requests.sessions.Session.request")
    def test_send_bulk_notification__success(self, mock):
        ResponseMock.requests = [self.mocked_notification_center_send_bulk(status.HTTP_201_CREATED, {"key": "value"})]
        mock.side_effect = ResponseMock

        res = NotificationCenterClient().send_bulk_notification(
            sender_id=1, customer_id=4, recipient_ids=[2], type="mention"
        )

        self.assertEqual(res.json(), {"key": "value"})
        self.assertEqual(len(mock.mock_calls), 1)
        res_data = mock.mock_calls[0].kwargs["json"]
        self.assertEqual(res_data["sender_id"], 1)
        self.assertEqual(res_data["recipient_ids"], [2])
        self.assertEqual(res_data["customer_id"], 4)
        self.assertEqual(res_data["type"], "mention")
        self.assertEqual(res_data["extra_fields"], {})

    @mock.patch("beefree_clients.clients.requests.sessions.Session.request")
    def test_send_bulk_notification__status_error(self, mock):
        ResponseMock.requests = [self.mocked_notification_center_send_bulk(status.HTTP_400_BAD_REQUEST, {})]
        mock.side_effect = ResponseMock

        res = NotificationCenterClient().send_bulk_notification(
            sender_id=1, customer_id=4, recipient_ids=[2], type="mention"
        )
        self.assertIsNone(res)

    @mock.patch("beefree_clients.clients.requests.sessions.Session.request")
    def test_send_bulk_notification__connection_error(self, mock):
        mock.side_effect = requests.exceptions.ConnectionError()

        res = NotificationCenterClient().send_bulk_notification(
            sender_id=1, customer_id=4, recipient_ids=[2], type="mention"
        )
        self.assertIsNone(res)

    @mock.patch("beefree_clients.clients.requests.sessions.Session.request")
    def test_send_bulk_notification__timeout_error(self, mock):
        mock.side_effect = requests.exceptions.Timeout()

        res = NotificationCenterClient().send_bulk_notification(
            sender_id=1, customer_id=4, recipient_ids=[2], type="mention"
        )
        self.assertIsNone(res)
