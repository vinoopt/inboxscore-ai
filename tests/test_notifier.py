"""
INBOX-144 (2026-05-21) — tests for notifier.py.

Covers:
  • Eligibility: severity != 'critical' is skipped, email_mode == 'off'
    is skipped, plan not in {trial, pro, legacy_pro} is skipped, no
    email on file is skipped.
  • Idempotency: duplicate UNIQUE-constraint hit returns 'duplicate'
    without calling MailerCloud.
  • Template rendering: every supported alert type renders without
    raising. Specific assertions for blacklist (single + multi list),
    score_drop (above + below 40), DMARC weakened, generic fallback.
  • Blocklist URL substitution: known list → dynamic URL, unknown list
    → empty (renderer skips the link).
  • MailerCloud API: SUCCESS / error paths.

These tests mock Supabase + the HTTP call so no real DB or API calls
happen. The mocks check that notifier behaves correctly given each
state.
"""

import json
import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Set required env vars BEFORE importing notifier so module-level
# constants pick them up.
os.environ.setdefault("MAILERCLOUD_API_KEY", "test-key-fake")
os.environ.setdefault("ALERT_SENDER_EMAIL", "help@inboxscore.test")
os.environ.setdefault("ALERT_SENDER_NAME", "InboxScore Test")
os.environ.setdefault("APP_BASE_URL", "https://inboxscore.test")

import notifier  # noqa: E402
import blocklists  # noqa: E402


# ─── Fixtures ────────────────────────────────────────────────────────


def _alert(
    *, alert_id="alert-uuid-1", alert_type="blacklist_added",
    severity="critical", title="example.com listed on Spamhaus ZEN",
    message="example.com appeared on Spamhaus ZEN.",
    domain="example.com", raw_data=None,
):
    return {
        "id": alert_id, "type": alert_type, "severity": severity,
        "title": title, "message": message, "domain": domain,
        "raw_data": raw_data or {}, "created_at": "2026-05-20T15:32:00+00:00",
    }


def _mock_eligible_user():
    """Patch lookups so the user is eligible to receive emails."""
    user_row = {
        "id": "user-abc", "email": "test@example.com",
        "name": "Test User", "first_name": "Test",
    }
    sb = MagicMock()
    sb.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = MagicMock(data=[user_row])
    sb.table.return_value.insert.return_value.execute.return_value = MagicMock(data=[{"id": "log-uuid-1"}])
    sb.table.return_value.update.return_value.eq.return_value.execute.return_value = MagicMock(data=[{}])
    return sb


def _patch_eligibility(
    *, plan="pro", email_mode="critical_rt", user_row=None, log_insert=None,
):
    """Returns a context-manager stack patching all the eligibility deps."""
    sb = MagicMock()
    row = user_row if user_row is not None else {
        "id": "user-abc", "email": "test@example.com",
        "name": "Test User", "first_name": "Test",
    }
    sb.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = MagicMock(data=[row] if row else [])
    log_data = log_insert if log_insert is not None else [{"id": "log-uuid-1"}]
    sb.table.return_value.insert.return_value.execute.return_value = MagicMock(data=log_data)
    sb.table.return_value.update.return_value.eq.return_value.execute.return_value = MagicMock(data=[{}])

    return [
        patch("notifier.get_supabase", return_value=sb),
        patch("notifier.get_user_plan", return_value=plan),
        patch("notifier.get_user_preferences", return_value={"email_mode": email_mode}),
    ]


def _enter_patches(patches):
    for p in patches:
        p.start()
    return patches


def _exit_patches(patches):
    for p in patches:
        p.stop()


# ─── Eligibility ─────────────────────────────────────────────────────


class TestEligibility:
    def test_non_critical_severity_skipped(self):
        patches = _enter_patches(_patch_eligibility())
        try:
            result = notifier.send_alert_email(
                "user-abc", _alert(severity="warning"),
            )
        finally:
            _exit_patches(patches)
        assert result["status"] == "skipped"
        assert result["reason"] == "not_critical"

    def test_info_severity_skipped(self):
        patches = _enter_patches(_patch_eligibility())
        try:
            result = notifier.send_alert_email("user-abc", _alert(severity="info"))
        finally:
            _exit_patches(patches)
        assert result["status"] == "skipped"

    def test_email_mode_off_skipped(self):
        patches = _enter_patches(_patch_eligibility(email_mode="off"))
        try:
            result = notifier.send_alert_email("user-abc", _alert())
        finally:
            _exit_patches(patches)
        assert result["status"] == "skipped"
        assert result["reason"] == "email_mode_off"

    def test_stub_plan_skipped(self):
        patches = _enter_patches(_patch_eligibility(plan="stub"))
        try:
            result = notifier.send_alert_email("user-abc", _alert())
        finally:
            _exit_patches(patches)
        assert result["status"] == "skipped"
        assert result["reason"] == "plan_not_emailable"

    def test_no_user_skipped(self):
        # Patch _lookup_user to None directly — simulates user row not
        # found in DB. (Using user_row=None in _patch_eligibility means
        # 'use default user row' which is the opposite of what we want.)
        patches = _enter_patches(_patch_eligibility())
        patches.append(patch("notifier._lookup_user", return_value=None))
        patches[-1].start()
        try:
            result = notifier.send_alert_email("user-abc", _alert())
        finally:
            _exit_patches(patches)
        assert result["status"] == "skipped"
        assert result["reason"] == "no_user"

    def test_no_email_skipped(self):
        patches = _enter_patches(_patch_eligibility(user_row={
            "id": "user-abc", "email": None, "name": "Test",
        }))
        try:
            result = notifier.send_alert_email("user-abc", _alert())
        finally:
            _exit_patches(patches)
        assert result["status"] == "skipped"
        assert result["reason"] == "no_email"

    def test_bad_input_returns_skipped(self):
        result = notifier.send_alert_email("user-abc", None)
        assert result["status"] == "skipped"
        result = notifier.send_alert_email("user-abc", {"no_id": True})
        assert result["status"] == "skipped"


# ─── Idempotency ─────────────────────────────────────────────────────


class TestIdempotency:
    def test_duplicate_log_returns_duplicate(self):
        # Simulate UNIQUE constraint violation on the pre-flight INSERT
        sb = MagicMock()
        sb.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = MagicMock(data=[{
            "id": "user-abc", "email": "test@example.com", "name": "T",
        }])
        sb.table.return_value.insert.return_value.execute.side_effect = Exception(
            "duplicate key value violates unique constraint"
        )
        patches = [
            patch("notifier.get_supabase", return_value=sb),
            patch("notifier.get_user_plan", return_value="pro"),
            patch("notifier.get_user_preferences", return_value={"email_mode": "critical_rt"}),
        ]
        _enter_patches(patches)
        try:
            result = notifier.send_alert_email("user-abc", _alert())
        finally:
            _exit_patches(patches)
        assert result["status"] == "duplicate"


# ─── Template rendering ──────────────────────────────────────────────


class TestRendering:
    def test_blacklist_single_list(self):
        rendered = notifier._render_email(
            _alert(
                alert_type="blacklist_added",
                title="Domain blacklist — now failing",
                raw_data={
                    "blacklists_listed": ["Spamhaus ZEN"],
                    "blacklists_count": 1,
                    "blacklist_type": "domain",
                },
            ),
            "Test",
        )
        assert "Spamhaus ZEN" in rendered["subject"]
        assert "example.com" in rendered["subject"]
        assert "Spamhaus ZEN" in rendered["html"]
        # The dynamic delisting URL with the domain substituted
        assert "check.spamhaus.org/listed/?searchterm=example.com" in rendered["html"]
        # Plain text version is non-empty + carries the title
        assert "example.com was listed on Spamhaus ZEN" in rendered["text"]

    def test_blacklist_multi_list(self):
        rendered = notifier._render_email(
            _alert(
                alert_type="blacklist_added",
                raw_data={
                    "blacklists_listed": ["Spamhaus ZEN", "Barracuda", "SURBL"],
                    "blacklists_count": 3,
                    "ip": "1.2.3.4",
                },
            ),
            "Test",
        )
        # Subject + title reference the count
        assert "3 blocklists" in rendered["subject"]
        assert "3 blocklists" in rendered["html"]
        # Steps include delisting URLs for each list
        # Spamhaus accepts both → uses domain (we don't have IP type for Spamhaus ZEN)
        assert "check.spamhaus.org" in rendered["html"]
        # Barracuda is IP-only → uses the IP we provided
        assert "rip=1.2.3.4" in rendered["html"]

    def test_blacklist_no_raw_data_fallback(self):
        """If raw_data lacks the list, renderer falls back to a generic
        blacklist email that still works."""
        rendered = notifier._render_email(
            _alert(alert_type="blacklist_added", raw_data={}), "Test",
        )
        assert "subject" in rendered
        assert rendered["html"]
        assert "example.com" in rendered["html"]

    def test_score_drop_above_40(self):
        rendered = notifier._render_email(
            _alert(
                alert_type="score_drop",
                title="example.com score dropped to 58",
                raw_data={
                    "old_score": 62, "new_score": 58, "score_delta": -4,
                    "new_band": "Needs Work", "direction": "down",
                    "failing_checks": ["spf", "gmail_spam_rate"],
                },
            ),
            "Test",
        )
        assert "58" in rendered["subject"]
        assert "dropped to 58" in rendered["html"]
        assert "62" in rendered["html"]
        # Mentions the 60 threshold
        assert "60" in rendered["html"]

    def test_score_drop_below_40(self):
        rendered = notifier._render_email(
            _alert(
                alert_type="score_drop",
                raw_data={
                    "old_score": 42, "new_score": 35, "score_delta": -7,
                    "new_band": "At Risk", "direction": "down",
                },
            ),
            "Test",
        )
        assert "35" in rendered["subject"]
        # "Serious risk" copy variant for sub-40 scores
        assert "serious risk" in rendered["html"].lower()
        assert "Pause active sending" in rendered["html"]

    def test_dmarc_weakened(self):
        rendered = notifier._render_email(
            _alert(
                alert_type="dmarc_change",
                title="DMARC policy weakened: reject → quarantine",
                raw_data={
                    "old_policy": "reject", "new_policy": "quarantine",
                    "weakened": True,
                },
            ),
            "Test",
        )
        assert "weakened" in rendered["subject"].lower()
        assert "reject" in rendered["html"]
        assert "quarantine" in rendered["html"]
        # Security-incident framing
        assert "security incident" in rendered["html"]

    def test_dmarc_failure_no_policy_change(self):
        """If DMARC check just transitioned pass→fail (no policy change
        in raw_data), renderer uses the failure variant."""
        rendered = notifier._render_email(
            _alert(alert_type="dmarc_change", raw_data={}),
            "Test",
        )
        assert "failing" in rendered["subject"].lower() or "failing" in rendered["html"].lower()

    def test_spf_failure(self):
        rendered = notifier._render_email(
            _alert(alert_type="spf_change"), "Test",
        )
        assert "SPF" in rendered["html"]
        assert "failing" in rendered["html"].lower()

    def test_generic_fallback(self):
        """Unknown alert type uses the generic renderer."""
        rendered = notifier._render_email(
            _alert(alert_type="future_type_we_haven't_built"),
            "Test",
        )
        assert rendered["html"]
        assert "Critical" in rendered["html"]

    def test_unknown_blocklist_no_url(self):
        """When the blocklist isn't in our lookup, the email still
        renders — just without a dynamic delisting URL."""
        rendered = notifier._render_email(
            _alert(
                alert_type="blacklist_added",
                raw_data={
                    "blacklists_listed": ["NewListXYZ"],
                    "blacklists_count": 1,
                },
            ),
            "Test",
        )
        assert "NewListXYZ" in rendered["subject"]
        # Generic "Contact ... removal process" text fallback
        assert "removal process" in rendered["html"]


# ─── Blocklist lookup ────────────────────────────────────────────────


class TestBlocklistLookup:
    @pytest.mark.parametrize("name,expected_substring", [
        ("Spamhaus ZEN", "check.spamhaus.org"),
        ("Barracuda", "barracudacentral.org"),
        ("URIBL", "lookup.uribl.com"),
        ("PhishTank", "phishtank.com"),
    ])
    def test_known_blocklist_has_dynamic_url(self, name, expected_substring):
        url = blocklists.render_delisting_url(name, "example.com", "1.2.3.4")
        assert expected_substring in url

    def test_unknown_blocklist_returns_empty(self):
        url = blocklists.render_delisting_url("NotAKnownList", "example.com")
        assert url == ""

    def test_ip_substituted_for_ip_only_lists(self):
        url = blocklists.render_delisting_url("Barracuda", "example.com", "1.2.3.4")
        assert "1.2.3.4" in url
        assert "example.com" not in url

    def test_domain_substituted_for_domain_only_lists(self):
        url = blocklists.render_delisting_url("URIBL", "example.com", "1.2.3.4")
        assert "example.com" in url


# ─── MailerCloud API call ────────────────────────────────────────────


class TestMailerCloudCall:
    def _build_payload(self):
        return notifier._build_payload(
            to_email="user@example.com", to_name="User",
            subject="Test", html_body="<p>test</p>", text_body="test",
            message_id="alert-fake-1",
        )

    def test_payload_shape(self):
        p = self._build_payload()
        assert p["version"] == "1.0"
        assert p["email"]["from"] == "help@inboxscore.test"
        assert p["email"]["fromName"] == "InboxScore Test"
        assert p["email"]["replyTo"] == ["help@inboxscore.test"]
        assert p["email"]["recipients"]["to"][0]["email"] == "user@example.com"
        assert p["metadata"]["campaignType"] == "TRANSACTIONAL"
        assert p["metadata"]["messageId"] == "alert-fake-1"

    def test_api_success_returns_sent(self):
        class FakeResp:
            def __init__(self, body):
                self._body = body
            def read(self):
                return json.dumps(self._body).encode()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        with patch("notifier.urllib.request.urlopen",
                   return_value=FakeResp({"status": "SUCCESS", "statusCode": 1000, "message": "NA"})):
            result = notifier._call_mailercloud(self._build_payload())
        assert result["status"] == "sent"
        assert result["message_id"] == "alert-fake-1"

    def test_api_error_returns_failed(self):
        class FakeResp:
            def __init__(self, body):
                self._body = body
            def read(self):
                return json.dumps(self._body).encode()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        with patch("notifier.urllib.request.urlopen",
                   return_value=FakeResp({"status": "ERROR", "statusCode": 9011, "message": "Sender address not verified"})):
            result = notifier._call_mailercloud(self._build_payload())
        assert result["status"] == "failed"
        assert result["error_code"] == "9011"
        assert "not verified" in result["error_message"]

    def test_http_error_returns_failed(self):
        import urllib.error
        with patch("notifier.urllib.request.urlopen",
                   side_effect=urllib.error.HTTPError(
                       "url", 401, "Unauthorized", {}, MagicMock(read=lambda: b'{"error":"bad key"}')
                   )):
            result = notifier._call_mailercloud(self._build_payload())
        assert result["status"] == "failed"
        assert result["error_code"] == "401"

    def test_missing_api_key_returns_failed(self):
        with patch("notifier.MAILERCLOUD_API_KEY", ""):
            result = notifier._call_mailercloud(self._build_payload())
        assert result["status"] == "failed"
        assert result["error_code"] == "no_api_key"


# ─── End-to-end through send_alert_email ─────────────────────────────


class TestEndToEnd:
    def test_full_send_path(self):
        """Eligible user + valid alert + MailerCloud SUCCESS = 'sent'."""
        patches = _enter_patches(_patch_eligibility())

        class FakeResp:
            def read(self):
                return json.dumps({"status": "SUCCESS", "statusCode": 1000}).encode()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        try:
            with patch("notifier.urllib.request.urlopen", return_value=FakeResp()):
                result = notifier.send_alert_email("user-abc", _alert())
        finally:
            _exit_patches(patches)
        assert result["status"] == "sent"
        assert result["message_id"].startswith("alert-")

    def test_full_send_path_api_failure_marked_failed(self):
        patches = _enter_patches(_patch_eligibility())

        class FakeResp:
            def read(self):
                return json.dumps({"status": "ERROR", "statusCode": 9003, "message": "Auth failed"}).encode()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        try:
            with patch("notifier.urllib.request.urlopen", return_value=FakeResp()):
                result = notifier.send_alert_email("user-abc", _alert())
        finally:
            _exit_patches(patches)
        assert result["status"] == "failed"
