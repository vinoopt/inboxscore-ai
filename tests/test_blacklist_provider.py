"""INBOX-229 phase 3 — tests for the simplified blacklist provider.

As of phase 3, every caller in the product uses HetrixTools — there's
no canary list, no global flag flip, no fallback to dnsbl. The provider
helper survives only as the freshness-gate chokepoint and a future
routing injection point.

Coverage:
  - use_hetrix_for_user always returns True (regardless of env or user_id)
  - get_full_blacklist_check_fn always returns hetrix's function
  - Freshness gate: skip-when-fresh, run-when-stale, run-when-no-row,
    run-when-unparseable
"""

from datetime import datetime, timezone, timedelta

import pytest


# ─── use_hetrix_for_user ────────────────────────────────────────────


def test_always_returns_true_for_any_user(monkeypatch):
    """Phase 3: hetrix is the only provider. user_id is irrelevant."""
    monkeypatch.delenv("USE_HETRIX_BL", raising=False)
    monkeypatch.delenv("HETRIX_CANARY_USER_IDS", raising=False)
    from blacklist_provider import use_hetrix_for_user
    assert use_hetrix_for_user("any-user-id") is True
    assert use_hetrix_for_user(None) is True
    assert use_hetrix_for_user("") is True


def test_env_vars_are_irrelevant(monkeypatch):
    """Phase 3 strips env-driven routing. Setting USE_HETRIX_BL=false or
    deleting it does NOT bring dnsbl back — we always use hetrix."""
    monkeypatch.setenv("USE_HETRIX_BL", "false")
    monkeypatch.setenv("HETRIX_CANARY_USER_IDS", "")
    from blacklist_provider import use_hetrix_for_user
    assert use_hetrix_for_user("u") is True


# ─── get_full_blacklist_check_fn ────────────────────────────────────


def test_selector_always_returns_hetrix(monkeypatch):
    """The selector must point at hetrix's full_blacklist_check, no
    matter the env or user."""
    monkeypatch.delenv("USE_HETRIX_BL", raising=False)
    monkeypatch.delenv("HETRIX_CANARY_USER_IDS", raising=False)
    monkeypatch.setenv("HETRIX_API_TOKEN", "test-token")
    from blacklist_provider import get_full_blacklist_check_fn
    fn_anon = get_full_blacklist_check_fn(None)
    fn_user = get_full_blacklist_check_fn("some-user-id")
    # __module__ tells us which file the function lives in. Both must
    # resolve to hetrix.
    assert "hetrix" in fn_anon.__module__
    assert "hetrix" in fn_user.__module__


# ─── Freshness gate ─────────────────────────────────────────────────


def test_skip_when_fresh(monkeypatch):
    """Recent timestamp (within 23h) → skip the API call."""
    from blacklist_provider import should_skip_blacklist_refresh
    just_now = datetime.now(timezone.utc).isoformat()
    assert should_skip_blacklist_refresh("u", "example.com", just_now) is True


def test_run_when_stale(monkeypatch):
    """Last check > 23h ago → run."""
    from blacklist_provider import should_skip_blacklist_refresh
    yesterday = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    assert should_skip_blacklist_refresh("u", "example.com", yesterday) is False


def test_run_when_no_existing_row(monkeypatch):
    """First-time check (no cached row) → must run."""
    from blacklist_provider import should_skip_blacklist_refresh
    assert should_skip_blacklist_refresh("u", "example.com", None) is False
    assert should_skip_blacklist_refresh("u", "example.com", "") is False


def test_run_when_unparseable_timestamp(monkeypatch):
    """Garbage in last_checked_at → fail safe by running (caller still
    has data; just refresh it)."""
    from blacklist_provider import should_skip_blacklist_refresh
    assert should_skip_blacklist_refresh("u", "d", "not-a-date") is False


def test_freshness_gate_applies_regardless_of_user(monkeypatch):
    """Phase 3: freshness gate is universal now (used by the scheduler
    on every domain it scans, no per-user routing)."""
    from blacklist_provider import should_skip_blacklist_refresh
    fresh = datetime.now(timezone.utc).isoformat()
    assert should_skip_blacklist_refresh("any-user", "d", fresh) is True
    assert should_skip_blacklist_refresh(None, "d", fresh) is True


def test_z_suffix_iso_timestamp_parses(monkeypatch):
    """ISO timestamps from Supabase often end with 'Z' — make sure
    we handle that without falling into the unparseable branch."""
    from blacklist_provider import should_skip_blacklist_refresh
    fresh_z = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    assert should_skip_blacklist_refresh("u", "d", fresh_z) is True
