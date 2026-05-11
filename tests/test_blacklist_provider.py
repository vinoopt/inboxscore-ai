"""INBOX-229 phase 2 — tests for the dnsbl/hetrix provider selector.

Covers the three resolution paths (canary user > global flag > default
dnsbl) and the freshness gate that protects HetrixTools credits.
"""

from datetime import datetime, timezone, timedelta

import pytest


# ─── use_hetrix_for_user ────────────────────────────────────────────


def test_default_is_dnsbl(monkeypatch):
    """No env flags set → fall through to dnsbl."""
    monkeypatch.delenv("USE_HETRIX_BL", raising=False)
    monkeypatch.delenv("HETRIX_CANARY_USER_IDS", raising=False)
    from blacklist_provider import use_hetrix_for_user
    assert use_hetrix_for_user("any-user-id") is False
    assert use_hetrix_for_user(None) is False


def test_global_flag_flips_to_hetrix(monkeypatch):
    monkeypatch.setenv("USE_HETRIX_BL", "true")
    monkeypatch.delenv("HETRIX_CANARY_USER_IDS", raising=False)
    from blacklist_provider import use_hetrix_for_user
    assert use_hetrix_for_user("any-user-id") is True


def test_canary_user_gets_hetrix_even_with_flag_off(monkeypatch):
    """Canary list works regardless of the global flag — that's the
    whole point (test on Vinoop's account before flipping globally)."""
    monkeypatch.delenv("USE_HETRIX_BL", raising=False)
    monkeypatch.setenv("HETRIX_CANARY_USER_IDS", "vinoop-uuid,another-uuid")
    from blacklist_provider import use_hetrix_for_user
    assert use_hetrix_for_user("vinoop-uuid") is True
    assert use_hetrix_for_user("another-uuid") is True
    assert use_hetrix_for_user("not-in-canary") is False


def test_truthy_values_for_global_flag(monkeypatch):
    """Accept multiple common truthy spellings — "1", "true", "yes"."""
    from blacklist_provider import use_hetrix_for_user
    for val in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv("USE_HETRIX_BL", val)
        assert use_hetrix_for_user("u") is True, f"failed for {val!r}"
    for val in ("", "0", "false", "no", "off"):
        monkeypatch.setenv("USE_HETRIX_BL", val)
        assert use_hetrix_for_user("u") is False, f"failed for {val!r}"


# ─── get_full_blacklist_check_fn ────────────────────────────────────


def test_selector_returns_dnsbl_by_default(monkeypatch):
    monkeypatch.delenv("USE_HETRIX_BL", raising=False)
    monkeypatch.delenv("HETRIX_CANARY_USER_IDS", raising=False)
    from blacklist_provider import get_full_blacklist_check_fn
    fn = get_full_blacklist_check_fn("user")
    # Look at the module path — proves we got the right implementation
    assert "dnsbl" in fn.__module__


def test_selector_returns_hetrix_when_flag_on(monkeypatch):
    monkeypatch.setenv("USE_HETRIX_BL", "true")
    monkeypatch.setenv("HETRIX_API_TOKEN", "test-token")
    from blacklist_provider import get_full_blacklist_check_fn
    fn = get_full_blacklist_check_fn("user")
    assert "hetrix" in fn.__module__


# ─── Freshness gate ─────────────────────────────────────────────────


def test_skip_returns_false_for_dnsbl_path(monkeypatch):
    """dnsbl never skips — it's free, runs every monitor cycle."""
    monkeypatch.delenv("USE_HETRIX_BL", raising=False)
    monkeypatch.delenv("HETRIX_CANARY_USER_IDS", raising=False)
    from blacklist_provider import should_skip_blacklist_refresh
    # Even with an extremely fresh timestamp, dnsbl path runs every tick.
    fresh = datetime.now(timezone.utc).isoformat()
    assert should_skip_blacklist_refresh("u", "example.com", fresh) is False


def test_skip_when_hetrix_and_fresh(monkeypatch):
    """Hetrix + recently checked → skip the call."""
    monkeypatch.setenv("USE_HETRIX_BL", "true")
    from blacklist_provider import should_skip_blacklist_refresh
    just_now = datetime.now(timezone.utc).isoformat()
    assert should_skip_blacklist_refresh("u", "example.com", just_now) is True


def test_run_when_hetrix_and_stale(monkeypatch):
    """Hetrix + last check > 23h ago → run."""
    monkeypatch.setenv("USE_HETRIX_BL", "true")
    from blacklist_provider import should_skip_blacklist_refresh
    yesterday = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    assert should_skip_blacklist_refresh("u", "example.com", yesterday) is False


def test_run_when_no_existing_row(monkeypatch):
    """First-time check (no cached row) → must run."""
    monkeypatch.setenv("USE_HETRIX_BL", "true")
    from blacklist_provider import should_skip_blacklist_refresh
    assert should_skip_blacklist_refresh("u", "example.com", None) is False
    assert should_skip_blacklist_refresh("u", "example.com", "") is False


def test_run_when_unparseable_timestamp(monkeypatch):
    """Garbage in last_checked_at → fail safe by running (caller still
    has data; just refresh it)."""
    monkeypatch.setenv("USE_HETRIX_BL", "true")
    from blacklist_provider import should_skip_blacklist_refresh
    assert should_skip_blacklist_refresh("u", "d", "not-a-date") is False


def test_canary_user_freshness_gate_applies(monkeypatch):
    """Canary user gets hetrix → freshness gate applies to them too,
    even if USE_HETRIX_BL global flag is off."""
    monkeypatch.delenv("USE_HETRIX_BL", raising=False)
    monkeypatch.setenv("HETRIX_CANARY_USER_IDS", "canary-u")
    from blacklist_provider import should_skip_blacklist_refresh
    fresh = datetime.now(timezone.utc).isoformat()
    assert should_skip_blacklist_refresh("canary-u", "d", fresh) is True
    # Non-canary user on dnsbl: no freshness gate.
    assert should_skip_blacklist_refresh("other-u", "d", fresh) is False
