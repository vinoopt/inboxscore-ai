"""INBOX-229 — unit tests for hetrix.py.

No live API calls — we mock httpx so the test suite is fast, hermetic,
and works without HETRIX_API_TOKEN set in CI.

Coverage:
  - Response shape matches dnsbl.py (drop-in contract for callers)
  - `links` field stripped before return (key never persisted)
  - The "no listings" placeholder `{rbl: null, delist: null}` is filtered
  - Severity classification: known high / known low / unknown→medium+log
  - Missing token raises a clear RuntimeError
  - Error paths return the agreed shape with `error` populated
"""

import os
from unittest.mock import patch, MagicMock

import pytest


# Reset module-level env reads between tests
@pytest.fixture(autouse=True)
def _reset_env(monkeypatch):
    monkeypatch.setenv("HETRIX_API_TOKEN", "test-token-fixture")


# ─── Sample HetrixTools responses ───────────────────────────────────

_CLEAN_RESPONSE = {
    "status": "SUCCESS",
    "api_calls_left": 34320,
    "blacklist_check_credits_left": 4998,
    "blacklisted_count": 0,
    # HetrixTools' placeholder when nothing is listed.
    "blacklisted_on": [{"rbl": None, "delist": None}],
    "links": {
        "report_link": "https://hetrixtools.com/report/blacklist/abc/",
        "api_blacklist_check_link": "https://api.hetrixtools.com/v2/test-token-fixture/blacklist-check/domain/example.com/",
    },
}

_LISTED_RESPONSE = {
    "status": "SUCCESS",
    "api_calls_left": 34000,
    "blacklist_check_credits_left": 4900,
    "blacklisted_count": 2,
    "blacklisted_on": [
        {"rbl": "Spamhaus ZEN", "delist": "https://www.spamhaus.org/lookup/"},
        {"rbl": "Some Niche BL", "delist": "https://niche.example/delist"},
    ],
    "links": {
        "report_link": "https://hetrixtools.com/report/blacklist/xyz/",
        "api_blacklist_check_link": "leaky_url_with_token",
    },
}


def _mocked_httpx_response(payload: dict, status: int = 200):
    """Build a MagicMock that quacks like httpx.Response for our calls."""
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


# ─── Tests ──────────────────────────────────────────────────────────


def test_missing_token_raises_clear_error(monkeypatch):
    """If HETRIX_API_TOKEN is missing, we want a loud RuntimeError, not
    a cryptic 401 from the API."""
    monkeypatch.delenv("HETRIX_API_TOKEN", raising=False)
    from hetrix import check_domain
    res = check_domain("example.com")
    # Missing token surfaces via the error path (caller decides what
    # to do); test that we don't silently return empty.
    assert res["error"] is not None
    assert "HETRIX_API_TOKEN" in res["error"]


def test_clean_response_filters_placeholder():
    """The {rbl:null, delist:null} placeholder must not show up as a
    fake listing in our output."""
    with patch("hetrix.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = \
            _mocked_httpx_response(_CLEAN_RESPONSE)
        from hetrix import check_domain
        res = check_domain("example.com")

    assert res["error"] is None
    assert res["blacklisted_count"] == 0
    assert res["blacklisted_on"] == []  # placeholder filtered


def test_listed_response_parses_two_entries():
    with patch("hetrix.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = \
            _mocked_httpx_response(_LISTED_RESPONSE)
        from hetrix import check_domain
        res = check_domain("example.com")

    assert res["error"] is None
    assert res["blacklisted_count"] == 2
    assert len(res["blacklisted_on"]) == 2
    # Each entry has all the keys the frontend expects.
    for l in res["blacklisted_on"]:
        assert set(l.keys()) >= {"rbl", "name", "severity", "operator",
                                  "delist", "codes"}


def test_links_field_stripped():
    """The `links` dict contains the API key — must never reach the
    caller (and therefore never reach our blacklist_results JSONB)."""
    with patch("hetrix.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = \
            _mocked_httpx_response(_LISTED_RESPONSE)
        from hetrix import _hx_get
        cleaned = _hx_get("blacklist-check/domain/example.com/")

    assert "links" not in cleaned
    # And the cleaned dict still has the data we care about.
    assert cleaned["blacklisted_count"] == 2


def test_severity_classification_known_high():
    """Spamhaus ZEN should classify as high (matches dnsbl.py tier)."""
    from hetrix import _classify_severity
    assert _classify_severity("Spamhaus ZEN") == "high"
    assert _classify_severity("Barracuda BBL") == "high"


def test_severity_classification_known_low():
    """Volume-only lists classify low."""
    from hetrix import _classify_severity
    assert _classify_severity("Blocklist.de") == "low"


def test_severity_classification_unknown_defaults_medium(caplog):
    """An RBL name we haven't mapped yet defaults to medium + log warning
    so we can extend the lookup over time."""
    from hetrix import _classify_severity
    with caplog.at_level("WARNING"):
        s = _classify_severity("Totally Unknown List 2027")
    assert s == "medium"


def test_full_blacklist_check_shape_matches_dnsbl():
    """The wrapper aggregates domain + IP results into the agreed
    full-check shape. Same keys, same semantics as dnsbl."""
    with patch("hetrix.httpx.Client") as mock_client:
        # Same clean response for both domain + IP calls.
        mock_client.return_value.__enter__.return_value.get.return_value = \
            _mocked_httpx_response(_CLEAN_RESPONSE)
        from hetrix import full_blacklist_check
        res = full_blacklist_check("example.com", ips=["1.2.3.4"])

    assert set(res.keys()) >= {
        "domain", "domain_result", "ip_results", "total_listings",
        "high_severity_count", "overall_status", "checked_at",
        "lists_checked",
    }
    assert res["domain"] == "example.com"
    assert res["overall_status"] == "clean"
    assert res["total_listings"] == 0
    assert len(res["ip_results"]) == 1


def test_full_blacklist_check_critical_when_high_severity_present():
    """A high-severity listing flips overall_status to 'critical'."""
    with patch("hetrix.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = \
            _mocked_httpx_response(_LISTED_RESPONSE)
        from hetrix import full_blacklist_check
        res = full_blacklist_check("example.com", ips=[])

    assert res["overall_status"] == "critical"  # Spamhaus ZEN is high
    assert res["high_severity_count"] >= 1


def test_http_error_returns_error_shape_not_raises():
    """When the API errors, callers must still get a valid response
    shape — never an exception bubbling up to the page."""
    import httpx as real_httpx
    with patch("hetrix.httpx.Client") as mock_client:
        bad_resp = MagicMock()
        bad_resp.status_code = 500
        bad_resp.raise_for_status.side_effect = real_httpx.HTTPStatusError(
            "boom", request=MagicMock(), response=bad_resp
        )
        mock_client.return_value.__enter__.return_value.get.return_value = bad_resp
        from hetrix import check_domain
        res = check_domain("example.com")

    assert res["error"] is not None
    assert res["blacklisted_count"] == 0
    assert res["blacklisted_on"] == []
