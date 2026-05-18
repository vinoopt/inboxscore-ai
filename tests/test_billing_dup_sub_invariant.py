"""
INBOX-267 — Single-active-subscription invariant tests.

Covers the 5 layers of defense-in-depth that prevent the duplicate
subscription bug Vinoop discovered on vinoop@luvia.com.

  Layer 1 — UI gating (frontend, manual check)
  Layer 2 — API guard in /api/billing/checkout (tested here)
  Layer 3 — Stripe idempotency key on Session.create (tested here)
  Layer 4 — Webhook reconciler in customer.subscription.created (tested here)
  Layer 5 — DB partial unique index + orphan audit table (migration-level,
            not unit-tested — verified via migration replay in CI)
"""

import sys
import os
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import billing


# ─── Layer 2: list_active_subscriptions helper ────────────────────


def _make_stripe_sub(sub_id: str, status: str, created: int = 1000):
    """Build a minimal MagicMock that quacks like a Stripe Subscription."""
    sub = MagicMock()
    sub.id = sub_id
    sub.status = status
    sub.created = created
    return sub


@patch("billing._ensure_initialized")
@patch("billing.stripe")
def test_list_active_subscriptions_returns_live_subs_oldest_first(
    mock_stripe, _mock_init
):
    """All live subs are returned, sorted oldest-first."""
    subs = [
        _make_stripe_sub("sub_C_old", "active", created=100),
        _make_stripe_sub("sub_B_mid", "trialing", created=200),
        _make_stripe_sub("sub_A_new", "active", created=300),
        _make_stripe_sub("sub_canceled", "canceled", created=50),  # excluded
    ]
    list_result = MagicMock()
    list_result.auto_paging_iter.return_value = iter(subs)
    mock_stripe.Subscription.list.return_value = list_result

    result = billing.list_active_subscriptions("cus_test")

    assert len(result) == 3
    assert [s.id for s in result] == ["sub_C_old", "sub_B_mid", "sub_A_new"]
    # Verify canceled is excluded
    assert "sub_canceled" not in [s.id for s in result]


@patch("billing._ensure_initialized")
@patch("billing.stripe")
def test_list_active_subscriptions_returns_empty_when_no_subs(
    mock_stripe, _mock_init
):
    """Customer with no subscriptions returns empty list — happy path
    that allows /api/billing/checkout to proceed normally."""
    list_result = MagicMock()
    list_result.auto_paging_iter.return_value = iter([])
    mock_stripe.Subscription.list.return_value = list_result

    result = billing.list_active_subscriptions("cus_fresh")

    assert result == []


@patch("billing._ensure_initialized")
@patch("billing.stripe")
def test_list_active_subscriptions_excludes_canceled_and_expired(
    mock_stripe, _mock_init
):
    """canceled + incomplete_expired must be excluded — those subs
    are dead from the duplicate-detection perspective."""
    subs = [
        _make_stripe_sub("sub_canceled", "canceled"),
        _make_stripe_sub("sub_expired", "incomplete_expired"),
        _make_stripe_sub("sub_active", "active"),
    ]
    list_result = MagicMock()
    list_result.auto_paging_iter.return_value = iter(subs)
    mock_stripe.Subscription.list.return_value = list_result

    result = billing.list_active_subscriptions("cus_mixed")

    assert len(result) == 1
    assert result[0].id == "sub_active"


def test_live_subscription_statuses_constant_complete():
    """The set of statuses treated as 'live' must cover every state
    where Stripe still considers the sub billable."""
    expected = {"active", "trialing", "past_due", "unpaid", "incomplete"}
    assert billing.LIVE_SUBSCRIPTION_STATUSES == expected


# ─── Layer 3: idempotency key on Checkout Session.create ──────────


@patch("billing._ensure_initialized")
@patch("billing.lookup_price")
@patch("billing.stripe")
def test_create_checkout_session_includes_idempotency_key(
    mock_stripe, mock_lookup, _mock_init
):
    """Every Checkout Session.create call must pass an idempotency_key
    that derives from (user_id, price_lookup_key, day)."""
    mock_price = MagicMock()
    mock_price.id = "price_test"
    mock_lookup.return_value = mock_price

    billing.create_checkout_session(
        user_id="user_test",
        customer_id="cus_test",
        price_lookup_key="pro_monthly_usd",
        success_url="https://x.test/ok",
        cancel_url="https://x.test/cancel",
        idempotency_suffix="20260518",  # fixed for deterministic test
    )

    call_kwargs = mock_stripe.checkout.Session.create.call_args.kwargs
    assert "idempotency_key" in call_kwargs
    assert call_kwargs["idempotency_key"] == (
        "checkout-user_test-pro_monthly_usd-20260518"
    )


@patch("billing._ensure_initialized")
@patch("billing.lookup_price")
@patch("billing.stripe")
def test_create_checkout_session_idempotency_key_differs_per_price(
    mock_stripe, mock_lookup, _mock_init
):
    """Monthly vs yearly must get different idempotency keys — a user
    legitimately switching between them within the same day should
    NOT collide."""
    mock_price = MagicMock()
    mock_price.id = "price_test"
    mock_lookup.return_value = mock_price

    billing.create_checkout_session(
        user_id="user_test", customer_id="cus_test",
        price_lookup_key="pro_monthly_usd",
        success_url="x", cancel_url="x",
        idempotency_suffix="20260518",
    )
    monthly_key = mock_stripe.checkout.Session.create.call_args.kwargs[
        "idempotency_key"
    ]

    billing.create_checkout_session(
        user_id="user_test", customer_id="cus_test",
        price_lookup_key="pro_yearly_usd",
        success_url="x", cancel_url="x",
        idempotency_suffix="20260518",
    )
    yearly_key = mock_stripe.checkout.Session.create.call_args.kwargs[
        "idempotency_key"
    ]

    assert monthly_key != yearly_key


# ─── Layer 4: cancel_subscription helper ──────────────────────────


@patch("billing._ensure_initialized")
@patch("billing.stripe")
def test_cancel_subscription_passes_reason_to_stripe(mock_stripe, _mock_init):
    """The reason string must be recorded in Stripe's cancellation
    details so ops can audit reconciler actions in the dashboard."""
    cancelled_sub = MagicMock()
    cancelled_sub.to_dict.return_value = {"id": "sub_dup", "status": "canceled"}
    mock_stripe.Subscription.cancel.return_value = cancelled_sub

    result = billing.cancel_subscription("sub_dup", reason="duplicate_of_sub_keeper")

    call_kwargs = mock_stripe.Subscription.cancel.call_args.kwargs
    assert "cancellation_details" in call_kwargs
    assert "duplicate_of_sub_keeper" in (
        call_kwargs["cancellation_details"]["comment"]
    )
    assert result["id"] == "sub_dup"
