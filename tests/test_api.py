"""
Tests for InboxScore API endpoints
Tests HTTP endpoints with mocked backends
"""

import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ─── HEALTH ENDPOINT ────────────────────────────────────────────

class TestHealthEndpoint:
    """Test the /api/health endpoint"""

    def test_health_returns_ok(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data


# ─── SCAN ENDPOINT ──────────────────────────────────────────────

class TestScanEndpoint:
    """Test the /api/scan endpoint"""

    def test_scan_valid_domain(self, client, mock_db):
        """Scanning a valid domain should return score and checks"""
        response = client.post("/api/scan", json={"domain": "google.com"})
        assert response.status_code == 200
        data = response.json()
        assert "domain" in data
        assert "score" in data
        assert "checks" in data
        assert isinstance(data["score"], int)
        assert 0 <= data["score"] <= 100
        assert len(data["checks"]) > 0

    def test_scan_invalid_domain(self, client, mock_db):
        """Scanning an invalid domain should return 400"""
        response = client.post("/api/scan", json={"domain": "notadomain"})
        assert response.status_code == 400

    def test_scan_empty_domain(self, client, mock_db):
        """Empty domain should return 400"""
        response = client.post("/api/scan", json={"domain": ""})
        assert response.status_code == 400

    def test_scan_strips_protocol(self, client, mock_db):
        """Domain with https:// should be cleaned"""
        response = client.post("/api/scan", json={"domain": "https://google.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["domain"] == "google.com"

    def test_scan_strips_www(self, client, mock_db):
        """Domain with www. should be cleaned"""
        response = client.post("/api/scan", json={"domain": "www.google.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["domain"] == "google.com"

    def test_scan_response_structure(self, client, mock_db):
        """Verify complete response structure"""
        response = client.post("/api/scan", json={"domain": "google.com"})
        data = response.json()

        # Required top-level keys
        assert "domain" in data
        assert "score" in data
        assert "summary" in data
        assert "checks" in data
        assert "scan_time" in data
        assert "scanned_at" in data

        # Each check should have the right structure
        for check in data["checks"]:
            assert "name" in check
            assert "category" in check
            assert "status" in check
            assert "title" in check
            assert "detail" in check
            assert "points" in check
            assert "max_points" in check
            assert check["status"] in ["pass", "warn", "fail", "info"]
            assert check["category"] in ["authentication", "reputation", "infrastructure"]

    def test_scan_all_checks_present(self, client, mock_db):
        """All 15 check types should be in the response.
           INBOX-42 added domain_blacklists; INBOX-95 added google_safe_browsing."""
        response = client.post("/api/scan", json={"domain": "google.com"})
        data = response.json()

        # Note: check_sender_detection's CheckResult uses name="senders"
        # (legacy, pre-dates INBOX-42). Keep as-is — renaming would be a
        # separate breaking change across clients.
        expected_checks = {
            "mx_records", "spf", "dkim", "dmarc", "blacklists",
            "domain_blacklists",  # INBOX-42
            "tls", "reverse_dns", "bimi", "mta_sts", "tls_rpt",
            "senders", "domain_age", "ip_reputation",
            "google_safe_browsing",  # INBOX-95
        }
        actual_checks = {c["name"] for c in data["checks"]}
        assert expected_checks == actual_checks


# ─── STATIC PAGES ───────────────────────────────────────────────

class TestStaticPages:
    """Test that static HTML pages load correctly"""

    def test_homepage_loads(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_dashboard_loads(self, client):
        response = client.get("/dashboard")
        assert response.status_code == 200

    def test_domains_loads(self, client):
        response = client.get("/domains")
        assert response.status_code == 200

    def test_alerts_loads(self, client):
        response = client.get("/alerts")
        assert response.status_code == 200

    def test_settings_loads(self, client):
        response = client.get("/settings")
        assert response.status_code == 200

    def test_email_health_loads(self, client):
        response = client.get("/postmaster")
        assert response.status_code == 200

    def test_login_loads(self, client):
        response = client.get("/login")
        assert response.status_code == 200

    def test_signup_loads(self, client):
        response = client.get("/signup")
        assert response.status_code == 200


# ─── EMAIL HEALTH PAGE ────────────────────────────────────────────

class TestEmailHealthPage:
    """Test the Email Health page content and structure"""

    def test_email_health_contains_title(self, client):
        """Page should contain the Email Health title"""
        response = client.get("/postmaster")
        assert response.status_code == 200
        content = response.text
        assert "Email Health" in content

    def test_email_health_has_submenu(self, client):
        """Page should have the surviving 4-section submenu (INBOX-82 Phase 2:
        Overview moved to Dashboard, Yahoo/AOL removed because CFL data is too
        thin to be useful)."""
        response = client.get("/postmaster")
        content = response.text
        assert "eh-submenu" in content
        assert "Google Postmaster" in content
        assert "Microsoft SNDS" in content
        assert "Blacklist Monitor" in content
        assert "IP Reputation" in content

    def test_email_health_has_all_sections(self, client):
        """Page should have the 4 surviving content section IDs (INBOX-82
        Phase 2 dropped Overview + Yahoo)."""
        response = client.get("/postmaster")
        content = response.text
        assert 'id="eh-sec-google"' in content
        assert 'id="eh-sec-microsoft"' in content
        assert 'id="eh-sec-blacklist"' in content
        assert 'id="eh-sec-reputation"' in content

    def test_email_health_overview_section_removed(self, client):
        """INBOX-82 Phase 2: the Overview tab is gone — the Dashboard now
        plays this role. Guard against accidental re-introduction."""
        response = client.get("/postmaster")
        content = response.text
        assert 'id="eh-sec-overview"' not in content, (
            "Overview section was removed in INBOX-82 Phase 2 — Dashboard "
            "absorbed its role. Don't re-introduce."
        )

    def test_email_health_google_section_active_by_default(self, client):
        """INBOX-89: After Phase 2 cleanup, the Google section needs the
        `active` class so the right pane renders content on first visit.
        Previously the submenu item was active but the section div wasn't,
        leaving a blank panel."""
        response = client.get("/postmaster")
        content = response.text
        assert 'class="eh-section active" id="eh-sec-google"' in content, (
            "eh-sec-google must default to .active so the right pane "
            "renders Google Postmaster content on first load (INBOX-89)."
        )

    def test_email_health_reads_url_domain_param(self, client):
        """INBOX-89: The Dashboard's 'View its health page →' link uses
        ?domain=X to deep-link into the right monitored domain. The page
        must read this param and select the matching domain in the
        dropdown rather than always defaulting to the first one."""
        response = client.get("/postmaster")
        content = response.text
        assert "URLSearchParams" in content
        assert "get('domain')" in content, (
            "Email Health must read the ?domain= URL param so deep-links "
            "from the Dashboard / scan results work (INBOX-89)."
        )

    def test_email_health_yahoo_section_removed(self, client):
        """INBOX-82 Phase 2: Yahoo/AOL section dropped because CFL data is
        too thin to render useful intelligence (INBOX-79). The Dashboard's
        Provider Status card explains this to users."""
        response = client.get("/postmaster")
        content = response.text
        assert 'id="eh-sec-yahoo"' not in content, (
            "Yahoo section was removed in INBOX-82 Phase 2."
        )
        # The Yahoo CFL link still belongs on the Dashboard's Provider
        # Status card, just not as an Email Health sub-page.
        assert 'switchEhSection(\'yahoo\'' not in content, (
            "Yahoo nav reference still present in Email Health (INBOX-82)."
        )

    def test_email_health_has_google_postmaster_tabs(self, client):
        """Google Postmaster section should have 6 internal tabs (Compliance,
        Spam, Feedback Loop, Authentication, Encryption, Delivery Errors).

        INBOX-102 normalised the labels to Title Case ("Compliance Status",
        "Delivery Errors") so they read consistently with each other."""
        response = client.get("/postmaster")
        content = response.text
        assert "gpm-tab" in content
        # The 6 tabs were split out of the old 5-tab 'Spam & Feedback' in v1.14.
        # INBOX-102: Title Case normalisation.
        assert "Compliance Status" in content
        assert ">Spam<" in content
        assert "Feedback Loop" in content
        assert "Authentication" in content
        assert "Encryption" in content
        # "Delivery Errors" (plural) after INBOX-102.
        assert "Delivery Error" in content  # substring match still holds

    def test_email_health_has_provider_states(self, client):
        """Surviving provider sections (Google + Microsoft) keep their
        multi-state UI (data / disconnected / nodata / free).

        INBOX-82 Phase 2: Yahoo provider states removed with the Yahoo
        section."""
        response = client.get("/postmaster")
        content = response.text
        assert 'id="gpm-state-data"' in content
        assert 'id="gpm-state-disconnected"' in content
        assert 'id="gpm-state-nodata"' in content
        assert 'id="gpm-state-free"' in content
        assert 'id="ms-state-data"' in content
        assert 'id="ms-state-disconnected"' in content
        # Yahoo states must NOT be present (INBOX-82 Phase 2)
        assert 'id="yahoo-state-data"' not in content
        assert 'id="yahoo-state-disconnected"' not in content

    def test_email_health_has_sidebar_link(self, client):
        """Email Health page sidebar should have active link"""
        response = client.get("/postmaster")
        content = response.text
        # INBOX-110: email-health route gone; sidebar shows 4 provider links instead
        assert 'href="/postmaster"' in content

    def test_email_health_has_javascript(self, client):
        """Page should contain the interactive JavaScript functions"""
        response = client.get("/postmaster")
        content = response.text
        assert "switchEhSection" in content
        assert "switchGpmTab" in content
        assert "animateGpmSpam" in content
        assert "animateEmailHealthTrends" in content


# ─── SIDEBAR CONSISTENCY ───────────────────────────────────────────

class TestSidebarConsistency:
    """Verify Email Health link appears in sidebar on all pages"""

    def test_dashboard_has_email_health_link(self, client):
        response = client.get("/dashboard")
        assert 'href="/postmaster"' in response.text

    def test_domains_has_email_health_link(self, client):
        response = client.get("/domains")
        assert 'href="/postmaster"' in response.text

    def test_alerts_has_email_health_link(self, client):
        response = client.get("/alerts")
        assert 'href="/postmaster"' in response.text

    def test_settings_has_email_health_link(self, client):
        response = client.get("/settings")
        assert 'href="/postmaster"' in response.text


# ─── DOMAIN VALIDATION ──────────────────────────────────────────

class TestDomainValidation:
    """Test domain input cleaning and validation"""

    def test_trailing_slash_removed(self, client, mock_db):
        response = client.post("/api/scan", json={"domain": "example.com/"})
        assert response.status_code == 200
        assert response.json()["domain"] == "example.com"

    def test_path_removed(self, client, mock_db):
        response = client.post("/api/scan", json={"domain": "example.com/page/test"})
        assert response.status_code == 200
        assert response.json()["domain"] == "example.com"

    def test_uppercase_lowered(self, client, mock_db):
        response = client.post("/api/scan", json={"domain": "EXAMPLE.COM"})
        assert response.status_code == 200
        assert response.json()["domain"] == "example.com"

    def test_whitespace_stripped(self, client, mock_db):
        response = client.post("/api/scan", json={"domain": "  example.com  "})
        assert response.status_code == 200
        assert response.json()["domain"] == "example.com"
