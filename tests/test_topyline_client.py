from unittest import TestCase, mock

import requests
from base import beepro_vcr

from beefree_clients.clients import ToplyneClient
from beefree_clients.exceptions import ToplyneError


class TestBeeToplyneClient(TestCase):
    def test_toplyne_send_single_event_ok(self):
        tpc = ToplyneClient()
        data = {
            "accountId": "PRO-1",
            "eventName": "Seats Update",
            "timestamp": 1670242516.143688,
            "eventProperties": {
                "paid_seats_update": 1,
                "total_paid_seats": 3,
                "free_seats_update": 0,
                "total_free_seats": 1,
                "plan": "beepro_team",
            },
        }
        with beepro_vcr.use_cassette(
            "test_toplyne_send_single_event.json",
            match_on=["method", "scheme", "host", "port", "path", "body"],
        ) as cassette:
            response = tpc.send_single_seat_event(data)
            assert response == {"status": "SUCCESS", "data": {"message": "Events uploaded."}}
            assert cassette.play_count == 1

    def test_toplyne_send_multiple_events_ok(self):
        tpc = ToplyneClient()
        data = [
            {
                "accountId": "PRO-1",
                "eventName": "Seats Update",
                "timestamp": 1670242516.143688,
                "eventProperties": {
                    "paid_seats_update": 1,
                    "total_paid_seats": 3,
                    "free_seats_update": 0,
                    "total_free_seats": 1,
                    "plan": "beepro_team",
                },
            },
            {
                "accountId": "PRO-2",
                "eventName": "Seats Update",
                "timestamp": 1670242516.143688,
                "eventProperties": {
                    "paid_seats_update": -1,
                    "total_paid_seats": 2,
                    "free_seats_update": 0,
                    "total_free_seats": 0,
                    "plan": "beepro_team",
                },
            },
            {
                "accountId": "PRO-3",
                "eventName": "Seats Update",
                "timestamp": 1670242516.143688,
                "eventProperties": {
                    "paid_seats_update": 0,
                    "total_paid_seats": 2,
                    "free_seats_update": -1,
                    "total_free_seats": 1,
                    "plan": "beepro_team",
                },
            },
        ]
        with beepro_vcr.use_cassette(
            "test_toplyne_send_multiple_events.json",
            match_on=["method", "scheme", "host", "port", "path", "body"],
        ) as cassette:
            response = tpc.send_seat_events(data)
            assert response == {"status": "SUCCESS", "data": {"message": "Events uploaded."}}
            assert cassette.play_count == 1

    def test_toplyne_send_multiple_events_ko_if_more_than_500(self):
        tpc = ToplyneClient()
        data = [{x: f"Value {x}"} for x in range(520)]
        with self.assertRaises(ToplyneError) as exc:
            tpc.send_seat_events(data)
        assert exc.exception.status_code == 400
        assert str(exc.exception) == "The max number of events you can insert per call is 500."

    def test_toplyne_send_single_event_ko(self):
        tpc = ToplyneClient()
        data = {}
        with mock.patch("beefree_clients.clients.requests.sessions.Session.request") as mock_requests:
            mock_requests.side_effect = requests.exceptions.Timeout()
            with self.assertRaises(ToplyneError) as exc:
                tpc.send_single_seat_event(data)
            assert exc.exception.status_code == 502
            assert str(exc.exception) == "Toplyne service not available"

    def test_toplyne_send_multiple_event_ko(self):
        tpc = ToplyneClient()
        data = [
            {
                "accountId": "PRO-1",
                "eventName": "Seats Update",
                "eventProperties": {
                    "paid_seats_update": 1,
                    "total_paid_seats": 3,
                    "free_seats_update": 0,
                    "total_free_seats": 1,
                    "plan": "beepro_team",
                },
            },
            {
                "accountId": "PRO-2",
                "eventName": "Seats Update",
                "timestamp": 1670242516.143688,
            },
        ]
        with beepro_vcr.use_cassette(
            "test_toplyne_send_multiple_event_ko.json",
            match_on=["method", "scheme", "host", "port", "path", "body"],
        ) as cassette:
            with self.assertRaises(ToplyneError) as exc:
                tpc.send_single_seat_event(data)
            assert exc.exception.status_code == 500
            assert cassette.play_count == 1
