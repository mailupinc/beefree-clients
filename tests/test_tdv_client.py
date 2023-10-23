from datetime import datetime
from unittest import TestCase

from base import beepro_vcr

from beefree_clients.clients import TDVClient


class TestTDVClient(TestCase):
    def test_tdv_get_seat_history_ok(self):
        tdvc = TDVClient()
        start_date = datetime.fromisoformat("2022-12-01T14:49:31")
        end_date = datetime.fromisoformat("2022-12-02T14:49:31")
        with beepro_vcr.use_cassette(
            "test_tdv_get_seat_history_ok.json",
            match_on=["method", "scheme", "host", "port", "path", "body"],
        ) as cassette:
            response = tdvc.get_seat_history(start_date, end_date)
            assert response
            assert isinstance(response, list) is True
            assert len(response) == 739
            assert cassette.play_count == 1
            assert (
                cassette.requests[0].url == "https://tdv.growens.io:9402/json/bu_bee/toplyne/toplyne_seat_history"
                "?dtBegin=2022-12-01T14:49:31&dtEnd=2022-12-02T14:49:31"
            )
