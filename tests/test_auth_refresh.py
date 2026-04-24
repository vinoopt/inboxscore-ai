"""
Regression suite for INBOX-31 — public Supabase API for session refresh.

The previous implementation called `client.auth._refresh_access_token(...)`,
an underscore-prefixed private method that Supabase reserves the right
to rename or remove at any minor version bump. This test locks the
public contract in: our refresh_session() must call the public
`auth.refresh_session` method, and must handle the three response
shapes (success / null-session / library exception).
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import auth  # noqa: E402


def _fake_client_with_refresh(*, response=None, raise_exc: Exception | None = None):
    """Build a mock Supabase client whose auth.refresh_session is observable."""
    client = MagicMock()
    if raise_exc is not None:
        client.auth.refresh_session.side_effect = raise_exc
    else:
        client.auth.refresh_session.return_value = response
    return client


class TestRefreshSessionUsesPublicAPI:
    """The key invariant: we call the PUBLIC refresh_session, not the underscore variant."""

    def test_success_returns_new_token_pair(self):
        session_mock = MagicMock()
        session_mock.access_token = "new-access-token"
        session_mock.refresh_token = "new-refresh-token"
        session_mock.expires_in = 3600
        response = MagicMock(session=session_mock)

        client = _fake_client_with_refresh(response=response)

        with patch.object(auth, "get_auth_client", return_value=client):
            result = auth.refresh_session("old-refresh-token")

        assert result == {
            "success": True,
            "session": {
                "access_token": "new-access-token",
                "refresh_token": "new-refresh-token",
                "expires_in": 3600,
            },
        }

        # Critical: we called the PUBLIC API, by name, with the refresh
        # token as a kwarg. If a future refactor drops this call or
        # resurrects the underscore variant, this assertion fires.
        client.auth.refresh_session.assert_called_once_with(refresh_token="old-refresh-token")
        # And we did NOT call the private underscore API.
        assert not client.auth._refresh_access_token.called, (
            "INBOX-31 regression: someone re-introduced the call to "
            "auth._refresh_access_token. Use auth.refresh_session instead — "
            "underscore-prefixed methods are private and can vanish in a "
            "supabase-py minor bump."
        )

    def test_null_session_returns_error(self):
        # Some Supabase error paths return an AuthResponse with session=None.
        response = MagicMock(session=None)
        client = _fake_client_with_refresh(response=response)

        with patch.object(auth, "get_auth_client", return_value=client):
            result = auth.refresh_session("bad-or-expired-token")

        assert result["success"] is False
        assert "could not refresh" in result["error"].lower()

    def test_exception_becomes_graceful_error(self):
        # Library raises (e.g. network failure or 401 from Supabase).
        client = _fake_client_with_refresh(raise_exc=Exception("upstream 401"))

        with patch.object(auth, "get_auth_client", return_value=client):
            result = auth.refresh_session("bad-token")

        assert result["success"] is False
        # User-facing message should be user-friendly, not expose the upstream error.
        assert "upstream 401" not in result["error"]
        assert "log in again" in result["error"].lower() or "session expired" in result["error"].lower()

    def test_no_client_returns_unavailable(self):
        with patch.object(auth, "get_auth_client", return_value=None):
            result = auth.refresh_session("any-token")

        assert result["success"] is False
        assert "unavailable" in result["error"].lower()
