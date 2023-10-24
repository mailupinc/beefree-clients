import pytest


@pytest.fixture(autouse=True)
def mock_bee_ear_client(monkeypatch):
    def mock_track_event(*args, **kwargs):
        class MockResponse:
            status_code = 200

        return MockResponse()

    def mock_event_count(*args, **kwargs):
        return 0

    monkeypatch.setattr("beefree_clients.clients.BeeEarClient.track_event", mock_track_event)
    monkeypatch.setattr("beefree_clients.clients.BeeEarClient.get_event_count", mock_event_count)
