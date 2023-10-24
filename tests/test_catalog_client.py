from unittest.mock import Mock

import pytest
from base import beepro_vcr
from django.conf import settings
from requests import HTTPError

from beefree_clients.clients import CatalogClient
from beefree_clients.exceptions import ServiceUnavailableException


@pytest.fixture
def catalog_client_get_error(monkeypatch):
    def mock_get(*args, **kwargs):
        mock = Mock(status_code=503)
        mock.raise_for_status = Mock(side_effect=HTTPError("Error", response=mock))
        return mock

    monkeypatch.setattr("beefree_clients.clients.BillingPortalClient.get", mock_get)


@beepro_vcr.use_cassette()
def test_catalog_client_get_plans_ok():
    cc = CatalogClient(settings.PLAN_NAMES_MAP)
    plans = cc.get_plans()
    plan_handles = [plan["Handle"] for plan in plans]
    assert "beepro_free" in plan_handles
    assert len(plans) == 7


def test_catalog_client_get_plans_ko(catalog_client_get_error):
    with pytest.raises(ServiceUnavailableException):
        cc = CatalogClient(settings.PLAN_NAMES_MAP)
        cc.get_plans()
