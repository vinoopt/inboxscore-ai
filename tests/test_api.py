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

    def test_scan_all_13_checks_present(self, client, mock_db):
        """All 13 check types should be in the response"""
        response = client.post("/api/scan", json={"domain": "google.com"})
        data = response.json()

        expected_checks = {
            "mx_records", "spf", "dkim", "dmarc", "blacklists",
            "tls", "reverse_dns", "bimi", "mta_sts", "tls_rpt",
            "senders", "domain_age", "ip_reputation",
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
        response = client.get("/email-health")
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
        response = client.get("/email-health")
        assert response.status_code == 200
        content = response.text
        assert "Email Health" in content

    def test_email_health_has_submenu(self, client):
        """Page should have the 6-section submenu"""
        response = client.get("/email-health")
        content = response.text
        assert "eh-submenu" in content
        assert "Overview" in content
        assert "Google Postmaster" in content
        assert "Microsoft SNDS" in content
        assert "Yahoo" in content
        assert "Blacklist Monitor" in content
        assert "IP Reputation" in content

    def test_email_health_has_all_sections(self, client):
        """Page should have all 6 content section IDs"""
        response = client.get("/email-health")
        content = response.text
        assert 'id="eh-sec-overview"' in content
        assert 'id="eh-sec-google"' in content
        assert 'id="eh-sec-microsoft"' in content
        assert 'id="eh-sec-yahoo"' in content
        assert 'id="eh-sec-blacklist"' in content
        assert 'id="eh-sec-reputation"' in content

    def test_email_health_has_google_postmaster_tabs(self, client):
        """Google Postmaster section should have 5 internal tabs"""
        response = client.get("/email-health")
        content = response.text
        assert "gpm-tab" in content
        assert "Spam &amp; Feedback" in content or "Spam & Feedback" in content
        assert "Authentication" in content
        assert "Encryption" in content
        assert "Compliance" in content

    def test_email_health_has_provider_states(self, client):
        """Sections should have multiple provider states (data, disconnected, etc.)"""
        response = client.get("/email-health")
        content = response.text
        assert 'id="gpm-state-data"' in content
        assert 'id="gpm-state-disconnected"' in content
        assert 'id="gpm-state-nodata"' in content
        assert 'id="gpm-state-free"' in content
        assert 'id="ms-state-data"' in content
        assert 'id="ms-state-disconnected"' in content
        assert 'id="yahoo-state-data"' in content
        assert 'id="yahoo-state-disconnected"' in content

    def test_email_health_has_sidebar_link(self, client):
        """Email Health page sidebar should have active link"""
        response = client.get("/email-health")
        content = response.text
        assert 'href="/email-health" class="active"' in content

    def test_email_health_has_javascript(self, client):
        """Page should contain the interactive JavaScript functions"""
        response = client.get("/email-health")
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
        assert 'href="/email-health"' in response.text

    def test_domains_has_email_health_link(self, client):
        response = client.get("/domains")
        assert 'href="/email-health"' in response.text

    def test_alerts_has_email_health_link(self, client):
        response = client.get("/alerts")
        assert 'href="/email-health"' in response.text

    def test_settings_has_email_health_link(self, client):
        response = client.get("/settings")
        assert 'href="/email-health"' in response.text


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
