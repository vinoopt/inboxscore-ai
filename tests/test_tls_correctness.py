"""
Regression suite for INBOX-24 — TLS check actually verifies what it claims.

Two real bugs fixed:

  L3 — when port 25 was unreachable (Render blocks outbound SMTP), the
       previous implementation pattern-matched the MX hostname against
       a list of known providers and awarded a full 10/10. A domain
       whose MX said "google.com" got perfect TLS credit with zero
       evidence of a handshake. Now that same path returns info at
       5/10 (known provider) or 3/10 (unknown), clearly labelled as
       unverified.

  L4 — when the real STARTTLS handshake DID run, certificate
       verification was explicitly disabled (check_hostname=False,
       verify_mode=CERT_NONE). Expired, self-signed, or hostname-
       mismatched certs produced a pass. Now we run with CERT_REQUIRED
       + hostname verification, and on failure we extract the specific
       reason (expired / mismatched / self-signed / unknown CA) and
       return warn with a targeted fix_steps list.

These tests exercise the paths via targeted patching of socket /
ssl / safe_dns_query — no real network traffic.
"""

from __future__ import annotations

import os
import ssl
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import checks  # noqa: E402


def _mx_only_stub(domain_to_mx: dict[str, list[str]]):
    """safe_dns_query stub returning MX (and nothing else) for the given domain."""
    def stub(query: str, record_type: str):
        if record_type == "MX":
            return domain_to_mx.get(query, [])
        return []
    return stub


# --------------------------------------------------------------------
# L3 — port 25 blocked: no more 10/10 pattern-match
# --------------------------------------------------------------------

class TestPort25BlockedFallback:
    """Previous code: pattern-match MX → 10/10. Now: info + partial credit only."""

    def _block_port_25(self):
        """Make every socket.create_connection call raise as if port 25 was firewalled."""
        return patch("checks.socket.create_connection",
                     side_effect=OSError("Connection refused — port 25 blocked"))

    def test_google_workspace_no_longer_gets_full_points_on_name_alone(self):
        with patch.object(checks, "safe_dns_query",
                          side_effect=_mx_only_stub({"acme.test": ["10 aspmx.l.google.com"]})), \
             self._block_port_25():
            result = checks.check_tls("acme.test")

        assert result.status == "info", (
            "INBOX-24 L3 regression: Google-hosted MX with port 25 blocked must "
            f"return status='info', not {result.status!r}. The old 10/10 pass "
            "on a hostname match was a lie — we had no TLS evidence."
        )
        assert result.points == 5, (
            "Known-provider + port-25-blocked is partial credit (5/10), "
            "not full credit. 10/10 without evidence is the bug we closed."
        )
        assert result.max_points == 10
        assert "Google Workspace" in (result.detail or "")
        assert "could not be verified" in (result.detail or "").lower() or \
               "unverified" in (result.detail or "").lower() or \
               "partial credit" in (result.detail or "").lower()
        raw = result.raw_data or {}
        assert raw.get("inferred_provider") == "Google Workspace"
        assert raw.get("verification") == "unverified_port_25_blocked"

    def test_unknown_provider_with_port_25_blocked_gets_lower_info_score(self):
        with patch.object(checks, "safe_dns_query",
                          side_effect=_mx_only_stub({"acme.test": ["10 mail.selfhosted.example"]})), \
             self._block_port_25():
            result = checks.check_tls("acme.test")

        assert result.status == "info"
        assert result.points == 3, (
            "Unknown-provider + port-25-blocked is 3/10, lower than known-provider "
            "(5/10) — we have even less evidence."
        )
        assert (result.raw_data or {}).get("verification") == "unverified_unknown_provider"


# --------------------------------------------------------------------
# L4 — strict cert verification is actually on now
# --------------------------------------------------------------------

def _fake_smtp_starttls_sock():
    """A MagicMock socket that walks through a successful STARTTLS exchange.

    Response sequence (each .recv() call gets the next one):
      1. "220 smtp.example.com ESMTP ..."    (banner)
      2. "250-smtp.example.com\r\n250-STARTTLS\r\n250 OK"  (EHLO response)
      3. "220 Ready to start TLS"            (STARTTLS response)
    """
    sock = MagicMock()
    sock.recv.side_effect = [
        b"220 smtp.example.com ESMTP\r\n",
        b"250-smtp.example.com Hello\r\n250-STARTTLS\r\n250 OK\r\n",
        b"220 Ready to start TLS\r\n",
    ]
    return sock


def _valid_cert_returning_context(days_until_expiry: int = 90, tls_version: str = "TLSv1.3"):
    """Return (patch_ctx, mock_ssl_sock) for a successful strict-verify handshake."""
    not_after = (datetime.now(timezone.utc) + timedelta(days=days_until_expiry))
    not_after_str = not_after.strftime("%b %d %H:%M:%S %Y GMT")
    mock_ssl_sock = MagicMock()
    mock_ssl_sock.version.return_value = tls_version
    mock_ssl_sock.getpeercert.return_value = {
        "subject": ((("commonName", "smtp.example.com"),),),
        "issuer": ((("commonName", "Let's Encrypt R3"),),),
        "notAfter": not_after_str,
    }
    return mock_ssl_sock


class TestStrictCertVerification:
    """L4 — CERT_REQUIRED + hostname verification, and cert shape captured."""

    def test_valid_cert_tls13_gets_full_points(self):
        sock = _fake_smtp_starttls_sock()
        ssl_sock = _valid_cert_returning_context(days_until_expiry=90, tls_version="TLSv1.3")
        with patch.object(checks, "safe_dns_query",
                          side_effect=_mx_only_stub({"acme.test": ["10 smtp.example.com"]})), \
             patch("checks.socket.create_connection", return_value=sock), \
             patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.return_value = ssl_sock
            result = checks.check_tls("acme.test")

        assert result.status == "pass"
        assert result.points == 10
        raw = result.raw_data or {}
        assert raw.get("verification") == "strict_verified"
        assert raw.get("tls_version") == "TLSv1.3"
        assert raw.get("days_until_expiry") is not None

    def test_cert_expiring_within_30_days_degrades_to_warn(self):
        sock = _fake_smtp_starttls_sock()
        # notAfter is parsed with day-level resolution; a 10-day target will
        # typically compute as 9 days once wall-clock time has ticked during
        # the test. We care about the <30 threshold, not the exact number.
        ssl_sock = _valid_cert_returning_context(days_until_expiry=10)
        with patch.object(checks, "safe_dns_query",
                          side_effect=_mx_only_stub({"acme.test": ["10 smtp.example.com"]})), \
             patch("checks.socket.create_connection", return_value=sock), \
             patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.return_value = ssl_sock
            result = checks.check_tls("acme.test")

        assert result.status == "warn"
        assert result.points == 7
        # Detail should mention expiry — don't pin to a specific day count.
        assert "expires in" in (result.detail or "")
        raw = result.raw_data or {}
        assert raw.get("days_until_expiry") is not None
        assert 0 <= raw.get("days_until_expiry") < 30

    def test_expired_cert_returns_warn_not_pass(self):
        sock = _fake_smtp_starttls_sock()
        with patch.object(checks, "safe_dns_query",
                          side_effect=_mx_only_stub({"acme.test": ["10 smtp.example.com"]})), \
             patch("checks.socket.create_connection", return_value=sock), \
             patch("ssl.create_default_context") as mock_ctx:
            # Raise cert verification error on wrap_socket
            mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(
                "certificate has expired"
            )
            result = checks.check_tls("acme.test")

        assert result.status == "warn", (
            "INBOX-24 L4 regression: expired cert must return warn, not pass. "
            "The old CERT_NONE code let expired certs score full credit."
        )
        assert result.points == 4
        raw = result.raw_data or {}
        assert raw.get("verification") == "failed"
        assert raw.get("failure_reason") == "expired"

    def test_hostname_mismatch_returns_warn_with_correct_reason(self):
        sock = _fake_smtp_starttls_sock()
        with patch.object(checks, "safe_dns_query",
                          side_effect=_mx_only_stub({"acme.test": ["10 smtp.example.com"]})), \
             patch("checks.socket.create_connection", return_value=sock), \
             patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(
                "hostname 'smtp.example.com' doesn't match certificate's subjectAltName"
            )
            result = checks.check_tls("acme.test")

        assert result.status == "warn"
        assert result.points == 4
        raw = result.raw_data or {}
        assert raw.get("failure_reason") == "hostname_mismatch"

    def test_self_signed_cert_returns_warn_with_correct_reason(self):
        sock = _fake_smtp_starttls_sock()
        with patch.object(checks, "safe_dns_query",
                          side_effect=_mx_only_stub({"acme.test": ["10 smtp.example.com"]})), \
             patch("checks.socket.create_connection", return_value=sock), \
             patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(
                "self-signed certificate"
            )
            result = checks.check_tls("acme.test")

        assert result.status == "warn"
        assert result.points == 4
        raw = result.raw_data or {}
        assert raw.get("failure_reason") == "self_signed"


# --------------------------------------------------------------------
# Edge — no MX at all (already handled correctly pre-INBOX-24 but covered)
# --------------------------------------------------------------------

class TestNoMxBranch:
    def test_no_mx_returns_info_zero(self):
        with patch.object(checks, "safe_dns_query",
                          side_effect=_mx_only_stub({"acme.test": []})):
            result = checks.check_tls("acme.test")

        assert result.status == "info"
        assert result.points == 0
        assert result.max_points == 10
