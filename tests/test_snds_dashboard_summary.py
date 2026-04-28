"""
INBOX-125 — backend test for /api/snds/dashboard-summary

Asserts the 4 distinct states the endpoint returns based on
connection + per-domain IP-mapping + recent metrics state.
"""

from unittest.mock import patch


def _auth_user_patches(user_id="user-1"):
    """Helper — context for: valid token + Pro plan + user resolved."""
    user = {"id": user_id, "email": "test@example.com"}
    return [
        patch("app.get_user_from_token", return_value={"success": True, "user": user}),
        patch("app.get_user_plan", return_value="pro"),
    ]


def _enter_all(stack, items):
    return [stack.enter_context(p) for p in items]


def test_disconnected_when_no_snds_connection(client):
    """User has no SNDS connection at all → state=disconnected."""
    from contextlib import ExitStack

    with ExitStack() as stack:
        _enter_all(stack, _auth_user_patches())
        stack.enter_context(patch("app.get_snds_connection", return_value=None))

        resp = client.get(
            "/api/snds/dashboard-summary?domain=example.com",
            headers={"Authorization": "Bearer fake"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["state"] == "disconnected"
        assert body["summary"] is None
        assert body["mapped_ip_count"] == 0


def test_no_ips_mapped_when_connection_exists_but_no_mapping(client):
    """Connection exists but user_ip_domains has no rows for this domain."""
    from contextlib import ExitStack

    with ExitStack() as stack:
        _enter_all(stack, _auth_user_patches())
        stack.enter_context(patch(
            "app.get_snds_connection",
            return_value={"snds_key": "k", "ip_count": 10, "last_sync_at": "2026-04-28T07:00:00Z"},
        ))
        stack.enter_context(patch("app.get_ips_for_domain", return_value=[]))

        resp = client.get(
            "/api/snds/dashboard-summary?domain=example.com",
            headers={"Authorization": "Bearer fake"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["state"] == "no_ips_mapped"
        assert body["summary"] is None
        assert body["mapped_ip_count"] == 0
        assert body["last_sync_at"] == "2026-04-28T07:00:00Z"


def test_no_recent_data_when_mapped_but_no_metrics(client):
    """IPs mapped but db_get_snds_metrics returns nothing for those IPs."""
    from contextlib import ExitStack

    with ExitStack() as stack:
        _enter_all(stack, _auth_user_patches())
        stack.enter_context(patch(
            "app.get_snds_connection",
            return_value={"snds_key": "k", "ip_count": 5, "last_sync_at": "2026-04-25T07:00:00Z"},
        ))
        stack.enter_context(patch(
            "app.get_ips_for_domain",
            return_value=["1.2.3.4", "5.6.7.8"],
        ))
        # Returns metrics for OTHER IPs not in mapped set, or empty list.
        stack.enter_context(patch("app.db_get_snds_metrics", return_value=[]))

        resp = client.get(
            "/api/snds/dashboard-summary?domain=example.com",
            headers={"Authorization": "Bearer fake"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["state"] == "no_recent_data"
        assert body["summary"] is None
        assert body["mapped_ip_count"] == 2


def test_ok_state_with_aggregated_summary(client):
    """Happy path — IPs mapped + Microsoft data flowing."""
    from contextlib import ExitStack

    with ExitStack() as stack:
        _enter_all(stack, _auth_user_patches())
        stack.enter_context(patch(
            "app.get_snds_connection",
            return_value={"snds_key": "k", "ip_count": 3, "last_sync_at": "2026-04-28T07:00:00Z"},
        ))
        stack.enter_context(patch(
            "app.get_ips_for_domain",
            return_value=["1.2.3.4", "5.6.7.8"],
        ))
        stack.enter_context(patch(
            "app.db_get_snds_metrics",
            return_value=[
                {"ip_address": "1.2.3.4", "metric_date": "2026-04-27", "filter_result": "GREEN", "complaint_rate": "< 0.1%", "trap_hits": 0},
                {"ip_address": "1.2.3.4", "metric_date": "2026-04-28", "filter_result": "GREEN", "complaint_rate": "0.05%", "trap_hits": 0},
                {"ip_address": "5.6.7.8", "metric_date": "2026-04-28", "filter_result": "YELLOW", "complaint_rate": "0.25%", "trap_hits": 2},
                # IP not in mapped set — should be filtered out
                {"ip_address": "9.9.9.9", "metric_date": "2026-04-28", "filter_result": "RED", "complaint_rate": "5%", "trap_hits": 100},
            ],
        ))

        resp = client.get(
            "/api/snds/dashboard-summary?domain=example.com",
            headers={"Authorization": "Bearer fake"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["state"] == "ok"
        assert body["summary"]["has_data"] is True
        # Worst status across mapped IPs is YELLOW (5.6.7.8)
        assert body["summary"]["status_label"] == "YELLOW"
        assert body["summary"]["status_color"] == "warn"
        # Latest row per IP: 1.2.3.4 → 0.05%, 5.6.7.8 → 0.25% → avg ~0.15%
        assert "%" in body["summary"]["complaint_rate"]
        # Trap hits: latest per IP → 0 + 2 = 2 (the unmapped 9.9.9.9 ignored)
        assert body["summary"]["trap_hits"] == "2"
        assert body["mapped_ip_count"] == 2


def test_400_when_domain_param_missing(client):
    """Endpoint requires domain query param."""
    from contextlib import ExitStack

    with ExitStack() as stack:
        _enter_all(stack, _auth_user_patches())
        resp = client.get(
            "/api/snds/dashboard-summary",
            headers={"Authorization": "Bearer fake"},
        )
        assert resp.status_code == 400


def test_401_when_no_auth_header(client):
    """Endpoint requires Bearer token."""
    resp = client.get("/api/snds/dashboard-summary?domain=example.com")
    assert resp.status_code == 401
