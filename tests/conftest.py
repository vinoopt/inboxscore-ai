"""
InboxScore Test Configuration
Provides fixtures for mocking DNS, HTTP, and database calls
"""

import sys
import os
import pytest
from unittest.mock import patch, MagicMock

# Add parent directory to path so we can import app modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ─── MOCK DNS RESPONSES ─────────────────────────────────────────
# Pre-built DNS response data for different test scenarios

MOCK_DNS = {
    # Good domain — everything configured properly
    "good.com": {
        "MX": ["10 mail1.good.com.", "20 mail2.good.com."],
        "TXT": ['"v=spf1 include:_spf.google.com -all"'],
        "A": ["198.51.100.25"],
        "_dmarc.good.com:TXT": ['"v=DMARC1; p=reject; rua=mailto:dmarc@good.com"'],
        "default._domainkey.good.com:TXT": ['"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0123456789abcdefghij"'],
        "mail1.good.com:A": ["198.51.100.25"],
        "mail2.good.com:A": ["198.51.100.26"],
    },
    # Bad domain — nothing configured
    "bad.com": {
        "MX": None,
        "TXT": None,
        "A": None,
    },
    # Partial domain — SPF soft fail, no DKIM, DMARC none
    "partial.com": {
        "MX": ["10 mail.partial.com."],
        "TXT": ['"v=spf1 include:sendgrid.net ~all"'],
        "A": ["203.0.113.10"],
        "_dmarc.partial.com:TXT": ['"v=DMARC1; p=none"'],
        "mail.partial.com:A": ["203.0.113.10"],
    },
}


def mock_safe_dns_query(qname, rdtype, timeout=5):
    """Mock DNS resolver that returns pre-configured responses"""
    qname = str(qname).rstrip(".")

    # Extract domain from qname for lookup
    # Try specific key first (e.g., "_dmarc.good.com:TXT")
    specific_key = f"{qname}:{rdtype}"
    for domain_data in MOCK_DNS.values():
        if specific_key in domain_data:
            return domain_data[specific_key]

    # Try base domain lookup
    parts = qname.split(".")
    for i in range(len(parts)):
        base = ".".join(parts[i:])
        if base in MOCK_DNS:
            data = MOCK_DNS[base]
            # Check specific key
            if specific_key in data:
                return data[specific_key]
            # Check generic rdtype
            if rdtype in data:
                return data[rdtype]

    return None


@pytest.fixture
def mock_dns():
    """Fixture that patches safe_dns_query across the app"""
    with patch("app.safe_dns_query", side_effect=mock_safe_dns_query):
        yield mock_safe_dns_query


@pytest.fixture
def mock_db():
    """Fixture that disables all database operations"""
    with patch("app.is_db_available", return_value=False), \
         patch("app.save_scan", return_value=None), \
         patch("app.check_rate_limit", return_value={"allowed": True, "scans_used": 0, "max_scans": 999}):
        yield


@pytest.fixture
def mock_auth():
    """Fixture that provides a mock authenticated user"""
    mock_user = {"id": "test-user-123", "email": "test@example.com"}
    with patch("app.get_user_from_token", return_value={"success": True, "user": mock_user}):
        yield mock_user


@pytest.fixture
def client():
    """FastAPI test client with all external services mocked"""
    from fastapi.testclient import TestClient

    # Mock scheduler to prevent startup issues
    with patch("app.scheduler") as mock_sched:
        mock_sched.start = MagicMock()
        mock_sched.shutdown = MagicMock()

        from app import app
        with TestClient(app) as c:
            yield c
