"""
InboxScore - Authentication Module
Handles signup, login, logout, password reset via Supabase Auth
"""

import os
from supabase import create_client, Client
try:
    from supabase_auth.errors import AuthApiError
except ImportError:
    from gotrue.errors import AuthApiError

# ─── AUTH CLIENT (uses anon key for user-facing auth) ─────────────

_auth_client: Client | None = None
_auth_init_failed = False


def get_auth_client() -> Client:
    """Get Supabase client configured for auth (uses anon/publishable key)"""
    global _auth_client, _auth_init_failed

    if _auth_init_failed:
        return None

    if _auth_client is None:
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_ANON_KEY")  # Anon key for user auth

        if not url or not key:
            print("⚠️  SUPABASE_URL or SUPABASE_ANON_KEY not set — auth disabled")
            _auth_init_failed = True
            return None

        try:
            _auth_client = create_client(url, key)
        except Exception as e:
            print(f"⚠️  Supabase auth client failed: {e}")
            _auth_init_failed = True
            return None

    return _auth_client


def is_auth_available() -> bool:
    """Check if auth is configured"""
    return get_auth_client() is not None


# ─── AUTH OPERATIONS ──────────────────────────────────────────────

def sign_up(email: str, password: str, name: str = None) -> dict:
    """
    Register a new user.
    Returns: {"success": True, "user": {...}} or {"success": False, "error": "..."}
    """
    client = get_auth_client()
    if not client:
        return {"success": False, "error": "Authentication service unavailable"}

    try:
        # Build user metadata
        metadata = {}
        if name:
            metadata["name"] = name

        response = client.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "data": metadata
            }
        })

        if response.user:
            return {
                "success": True,
                "user": {
                    "id": response.user.id,
                    "email": response.user.email,
                    "created_at": str(response.user.created_at),
                },
                "message": "Account created. Please check your email to verify your account."
            }
        else:
            return {"success": False, "error": "Signup failed — please try again"}

    except AuthApiError as e:
        error_msg = str(e)
        if "already registered" in error_msg.lower() or "already been registered" in error_msg.lower():
            return {"success": False, "error": "An account with this email already exists"}
        elif "password" in error_msg.lower():
            return {"success": False, "error": "Password must be at least 6 characters"}
        else:
            return {"success": False, "error": error_msg}
    except Exception as e:
        print(f"Signup error: {e}")
        return {"success": False, "error": "Something went wrong. Please try again."}


def sign_in(email: str, password: str) -> dict:
    """
    Log in a user.
    Returns: {"success": True, "session": {...}, "user": {...}} or {"success": False, "error": "..."}
    """
    client = get_auth_client()
    if not client:
        return {"success": False, "error": "Authentication service unavailable"}

    try:
        response = client.auth.sign_in_with_password({
            "email": email,
            "password": password,
        })

        if response.session:
            return {
                "success": True,
                "session": {
                    "access_token": response.session.access_token,
                    "refresh_token": response.session.refresh_token,
                    "expires_in": response.session.expires_in,
                    "token_type": response.session.token_type,
                },
                "user": {
                    "id": response.user.id,
                    "email": response.user.email,
                    "name": response.user.user_metadata.get("name", ""),
                }
            }
        else:
            return {"success": False, "error": "Login failed — please try again"}

    except AuthApiError as e:
        error_msg = str(e)
        if "invalid" in error_msg.lower() or "credentials" in error_msg.lower():
            return {"success": False, "error": "Invalid email or password"}
        elif "not confirmed" in error_msg.lower():
            return {"success": False, "error": "Please verify your email before logging in"}
        else:
            return {"success": False, "error": error_msg}
    except Exception as e:
        print(f"Login error: {e}")
        return {"success": False, "error": "Something went wrong. Please try again."}


def reset_password(email: str) -> dict:
    """
    Send password reset email.
    Returns: {"success": True} or {"success": False, "error": "..."}
    """
    client = get_auth_client()
    if not client:
        return {"success": False, "error": "Authentication service unavailable"}

    try:
        client.auth.reset_password_email(email, {
            "redirect_to": "https://inboxscore.ai/reset-password"
        })

        # Always return success to avoid email enumeration
        return {
            "success": True,
            "message": "If an account exists with this email, you'll receive a password reset link."
        }

    except Exception as e:
        print(f"Password reset error: {e}")
        # Still return success to prevent email enumeration
        return {
            "success": True,
            "message": "If an account exists with this email, you'll receive a password reset link."
        }


def get_user_from_token(access_token: str) -> dict:
    """
    Validate an access token and return user info.
    Returns: {"success": True, "user": {...}} or {"success": False, "error": "..."}
    """
    client = get_auth_client()
    if not client:
        return {"success": False, "error": "Authentication service unavailable"}

    try:
        response = client.auth.get_user(access_token)

        if response.user:
            return {
                "success": True,
                "user": {
                    "id": response.user.id,
                    "email": response.user.email,
                    "name": response.user.user_metadata.get("name", ""),
                    "created_at": str(response.user.created_at),
                }
            }
        else:
            return {"success": False, "error": "Invalid or expired token"}

    except AuthApiError as e:
        return {"success": False, "error": "Invalid or expired token"}
    except Exception as e:
        print(f"Token validation error: {e}")
        return {"success": False, "error": "Invalid or expired token"}


def refresh_session(refresh_token: str) -> dict:
    """
    Refresh an expired access token.
    Returns: {"success": True, "session": {...}} or {"success": False, "error": "..."}
    """
    client = get_auth_client()
    if not client:
        return {"success": False, "error": "Authentication service unavailable"}

    try:
        response = client.auth._refresh_access_token(refresh_token)

        if response.session:
            return {
                "success": True,
                "session": {
                    "access_token": response.session.access_token,
                    "refresh_token": response.session.refresh_token,
                    "expires_in": response.session.expires_in,
                }
            }
        else:
            return {"success": False, "error": "Could not refresh session"}

    except Exception as e:
        print(f"Refresh error: {e}")
        return {"success": False, "error": "Session expired. Please log in again."}
