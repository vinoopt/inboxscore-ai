"""
INBOX-113: Tests for fixed UTC scan-slot scheduling.

Replaces the old rolling-24h cadence with fixed slots at 03:00 / 09:00 /
15:00 / 21:00 UTC so every timezone gets fresh data before business
hours start. These tests pin the slot logic so a future refactor can't
silently break it.
"""

import sys
import os
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from db import (
    SCHEDULED_SCAN_SLOTS_UTC,
    _most_recent_open_slot,
    get_domains_due_for_scan,
)


# ─── _most_recent_open_slot ────────────────────────────────────

class TestMostRecentOpenSlot:
    """Verify slot-resolution returns the right tz-AWARE UTC datetime."""

    def test_slots_are_3_9_15_21(self):
        """The four slots — codify so a refactor can't drift them."""
        assert SCHEDULED_SCAN_SLOTS_UTC == (3, 9, 15, 21)

    def test_just_after_first_slot(self):
        """At 03:30 UTC the most recent slot should be today 03:00 UTC."""
        now = datetime(2026, 4, 29, 3, 30, 0, tzinfo=timezone.utc)
        slot = _most_recent_open_slot(now)
        assert slot == datetime(2026, 4, 29, 3, 0, 0, tzinfo=timezone.utc)

    def test_between_slots(self):
        """At 12:00 UTC the most recent slot should be today 09:00 UTC."""
        now = datetime(2026, 4, 29, 12, 0, 0, tzinfo=timezone.utc)
        slot = _most_recent_open_slot(now)
        assert slot == datetime(2026, 4, 29, 9, 0, 0, tzinfo=timezone.utc)

    def test_just_after_last_slot(self):
        """At 21:30 UTC the most recent slot should be today 21:00 UTC."""
        now = datetime(2026, 4, 29, 21, 30, 0, tzinfo=timezone.utc)
        slot = _most_recent_open_slot(now)
        assert slot == datetime(2026, 4, 29, 21, 0, 0, tzinfo=timezone.utc)

    def test_before_first_slot_today(self):
        """At 02:00 UTC (before today's 03:00 slot), fall back to
        yesterday's 21:00 UTC slot. This avoids a gap right after midnight
        UTC where domains would otherwise look "not due"."""
        now = datetime(2026, 4, 29, 2, 0, 0, tzinfo=timezone.utc)
        slot = _most_recent_open_slot(now)
        assert slot == datetime(2026, 4, 28, 21, 0, 0, tzinfo=timezone.utc)

    def test_exactly_on_slot_boundary(self):
        """At 09:00:00 UTC exactly, the 09:00 slot is "open"."""
        now = datetime(2026, 4, 29, 9, 0, 0, tzinfo=timezone.utc)
        slot = _most_recent_open_slot(now)
        assert slot == datetime(2026, 4, 29, 9, 0, 0, tzinfo=timezone.utc)

    def test_returned_slot_is_tz_aware(self):
        """Defensive: slot must be tz-aware so caller can subtract from
        Supabase timestamps without crashing on naive/aware mismatch
        (the exact pattern that caused INBOX-1)."""
        now = datetime(2026, 4, 29, 12, 0, 0, tzinfo=timezone.utc)
        slot = _most_recent_open_slot(now)
        assert slot.tzinfo is not None


# ─── get_domains_due_for_scan ──────────────────────────────────

class TestDomainsDueForScan:
    """Mock get_monitored_domains + freeze 'now' so we can prove the
    slot logic decides correctly across a representative grid of
    last-scan times.

    Frozen 'now' for these tests: 2026-04-29 12:00:00 UTC.
    Most recent open slot for that 'now' is 2026-04-29 09:00:00 UTC.
    """

    NOW = datetime(2026, 4, 29, 12, 0, 0, tzinfo=timezone.utc)
    LAST_OPEN_SLOT = datetime(2026, 4, 29, 9, 0, 0, tzinfo=timezone.utc)

    def _patch_now_and_domains(self, domains):
        """Helper to patch datetime.now and get_monitored_domains."""
        # Patch datetime.now in db module
        class FrozenDT(datetime):
            @classmethod
            def now(cls, tz=None):
                return self.NOW
        return (
            patch("db.datetime", FrozenDT),
            patch("db.get_monitored_domains", return_value=domains),
            patch("db.get_supabase", return_value=object()),  # truthy
        )

    def test_never_scanned_is_due(self):
        """A domain with no last_monitored_at should be due immediately."""
        domains = [{"id": "d1", "domain": "example.com", "last_monitored_at": None}]
        p1, p2, p3 = self._patch_now_and_domains(domains)
        with p1, p2, p3:
            due = get_domains_due_for_scan()
        assert len(due) == 1
        assert due[0]["domain"] == "example.com"

    def test_scanned_before_open_slot_is_due(self):
        """Last scan = yesterday 21:00 UTC; current open slot = today 09:00.
        Last scan < open slot → due."""
        domains = [{
            "id": "d1", "domain": "example.com",
            "last_monitored_at": "2026-04-28T21:00:00+00:00",
        }]
        p1, p2, p3 = self._patch_now_and_domains(domains)
        with p1, p2, p3:
            due = get_domains_due_for_scan()
        assert len(due) == 1

    def test_scanned_after_open_slot_not_due(self):
        """Last scan = today 09:30 UTC; current open slot = today 09:00.
        Last scan > open slot → not due."""
        domains = [{
            "id": "d1", "domain": "example.com",
            "last_monitored_at": "2026-04-29T09:30:00+00:00",
        }]
        p1, p2, p3 = self._patch_now_and_domains(domains)
        with p1, p2, p3:
            due = get_domains_due_for_scan()
        assert len(due) == 0

    def test_scanned_exactly_at_slot_not_due(self):
        """Last scan = today 09:00:00 UTC; open slot = today 09:00:00.
        last_dt < open_slot is False (equal) → not due. Good — we don't
        want to re-scan a domain we just scanned at the slot boundary."""
        domains = [{
            "id": "d1", "domain": "example.com",
            "last_monitored_at": "2026-04-29T09:00:00+00:00",
        }]
        p1, p2, p3 = self._patch_now_and_domains(domains)
        with p1, p2, p3:
            due = get_domains_due_for_scan()
        assert len(due) == 0

    def test_voicenotes_repro(self):
        """Reproduce the exact case Vinoop reported. voicenotes.com last
        scanned 2026-04-28 13:36:39 UTC. At 'now' = 2026-04-29 12:00 UTC,
        the last open slot is today 09:00 UTC. Since 04-28 13:36 < 04-29
        09:00, the domain IS due. Under the OLD rolling-24h logic this
        domain would not be due until 13:36 UTC = 7:06 PM IST — that's
        the bug we fixed."""
        domains = [{
            "id": "vn", "domain": "voicenotes.com",
            "last_monitored_at": "2026-04-28T13:36:39+00:00",
        }]
        p1, p2, p3 = self._patch_now_and_domains(domains)
        with p1, p2, p3:
            due = get_domains_due_for_scan()
        assert len(due) == 1
        assert due[0]["domain"] == "voicenotes.com"

    def test_z_suffix_timestamp_parses(self):
        """Defensive: Supabase sometimes returns 'Z' instead of '+00:00'.
        Both should parse identically (matches INBOX-29 fix)."""
        domains = [{
            "id": "d1", "domain": "example.com",
            "last_monitored_at": "2026-04-28T21:00:00Z",
        }]
        p1, p2, p3 = self._patch_now_and_domains(domains)
        with p1, p2, p3:
            due = get_domains_due_for_scan()
        assert len(due) == 1

    def test_naive_datetime_is_treated_as_utc(self):
        """Defensive: a legacy or test-fixture naive datetime should be
        assumed UTC rather than crashing on the comparison (matches
        INBOX-29 defensive coercion)."""
        naive = datetime(2026, 4, 28, 21, 0, 0)  # no tzinfo
        domains = [{
            "id": "d1", "domain": "example.com",
            "last_monitored_at": naive,
        }]
        p1, p2, p3 = self._patch_now_and_domains(domains)
        with p1, p2, p3:
            due = get_domains_due_for_scan()
        assert len(due) == 1
