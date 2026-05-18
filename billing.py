"""
InboxScore — Stripe billing module (INBOX-205)

Single source of truth for all Stripe API interactions. Endpoints
(/api/billing/checkout, /api/billing/portal) and the webhook handler
(/api/webhooks/stripe) import from here — they never call stripe.*
directly. Keeping all SDK use behind this one module makes:

- Mocking trivial for tests (one import to patch)
- API-version pinning consistent (set once at module load)
- Logging + observability centralised
- Future migrations (e.g., adding Razorpay) easier — just add a
  parallel module and route via a feature flag, not a wholesale rewrite

Architecture decisions (from PAYMENT-PLAN.md §3 and §12):

- All amounts USD only. Stripe Tax adds VAT/GST automatically based
  on customer location (UK VAT registered via Luvia Digital LTD).
- Prices referenced by lookup_key (`pro_monthly_usd`, `pro_yearly_usd`)
  not raw price IDs — survives price-rotation, lets us swap prices
  in the dashboard without redeploying code.
- Operating entity: Luvia Digital LTD UK. See
  /Users/vinoopthayatt/Library/Application Support/Claude/local-agent-mode-sessions/.../memory/project_inboxscore_billing_entity.md
- Customer creation idempotent — caller passes existing
  stripe_customer_id (from profiles.stripe_customer_id) if known.
  No customer is ever duplicated for the same user.
- Trial: 14 days, no payment_method collected at signup. After day 14
  Stripe will try to charge → fail → transition sub to
  'incomplete_expired' → our webhook handler (INBOX-207) flips the
  user to 'stub' state.
- Webhook signature verification uses Stripe's official helper; we
  pass the RAW request body (bytes) — not JSON-parsed — because
  signature is computed over the bytes.

Module fails loud on import if env is misconfigured (see _init_stripe).
This is intentional — bad billing config should crash the app at boot,
not at first checkout when a real user is trying to pay.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

import stripe
# In stripe-python 8.0+, StripeError moved from `stripe.error` (which
# is now an internal alias to `stripe._error` and not a real submodule
# you can import from) to the top-level `stripe` package. Importing
# `from stripe.error import StripeError` raises ModuleNotFoundError.
from stripe import StripeError


logger = logging.getLogger(__name__)


# ─── Constants ────────────────────────────────────────────────────

# Trial duration. Locked at 14 days per PAYMENT-PLAN.md §5.
# If we ever A/B test 7 vs 14 vs 30, change this AND
# PAYMENT-PLAN.md AND the marketing copy together.
TRIAL_DAYS = 14

# Lookup-key catalogue. These match the values set in Stripe
# dashboard (Phase 0 Step 4 of the runbook) and never change. If the
# underlying price ID rotates, the lookup_key stays the same and our
# code keeps working.
LOOKUP_KEY_MONTHLY = "pro_monthly_usd"
LOOKUP_KEY_YEARLY = "pro_yearly_usd"

# Stripe API version pinning. MUST match the version configured on the
# webhook endpoint (Phase 0 Step 7). Keeping the SDK + webhook in sync
# prevents surprise payload-shape changes when Stripe ships new versions.
#
# To verify: Stripe Dashboard → Developers → Webhooks → [endpoint] →
# "API version". The string here MUST equal that exactly.
#
# Format: YYYY-MM-DD or YYYY-MM-DD.codename. If you ever see Stripe
# reject this with "Invalid API version", check the dashboard pinning
# and update both at once. Auditing on 2026-05-15 confirmed the
# expected format; the actual date should be verified against the
# dashboard at every Phase 0 review.
STRIPE_API_VERSION = "2026-04-22.dahlia"


# ─── Initialization ───────────────────────────────────────────────
#
# Lazy initialisation pattern (changed 2026-05-13). Original design
# eager-initialised at module import to fail loud on missing env.
# That broke CI + tests where no real Stripe keys are set — pytest
# would crash before any test ran. New approach:
#   1. Module imports cleanly even without env vars
#   2. The FIRST time any public function is called, _ensure_initialized
#      runs the env check + sets stripe.api_key
#   3. If env missing, RuntimeError is raised at call time with a
#      clear message — same loud failure, just deferred to use
#
# Production behaviour is identical (first request after boot triggers
# the check, fails loud if misconfigured). Test/CI behaviour is now
# importable for unit tests that mock the SDK.

_initialized = False


def _ensure_initialized() -> None:
    """Idempotent Stripe SDK setup. Safe to call repeatedly."""
    global _initialized
    if _initialized:
        return
    key = os.environ.get("STRIPE_SECRET_KEY")
    if not key:
        raise RuntimeError(
            "STRIPE_SECRET_KEY env var is missing. Set it in Render → "
            "Environment per docs/STRIPE-PHASE-0-RUNBOOK.md Step 8. "
            "Without it, no billing flow can work."
        )
    stripe.api_key = key
    stripe.api_version = STRIPE_API_VERSION
    # Quiet the underlying Stripe SDK's verbose request logging — we
    # do our own structured logging at the call sites.
    logging.getLogger("stripe").setLevel(logging.WARNING)
    _initialized = True


def get_webhook_secret() -> str:
    """Read the Stripe webhook signing secret (whsec_*) from env."""
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET")
    if not secret:
        raise RuntimeError(
            "STRIPE_WEBHOOK_SECRET env var is missing. Set it in "
            "Render → Environment with the value shown on the Stripe "
            "webhook endpoint detail page (Phase 0 Step 7)."
        )
    return secret


def get_stripe_mode() -> str:
    """
    Return 'test' or 'live' based on the STRIPE_SECRET_KEY prefix.

    Stripe convention: sk_test_* for sandbox, sk_live_* for production.
    Used by the frontend (/api/user/plan) to conditionally show test-
    card hints during the test-mode window, then auto-hide them once
    we cut over to live keys. No manual UI change needed at cutover.

    Returns 'unknown' if env is misconfigured — caller treats that as
    'don't show test-mode hints, to be safe'.
    """
    key = os.environ.get("STRIPE_SECRET_KEY", "")
    if key.startswith("sk_test_"):
        return "test"
    if key.startswith("sk_live_"):
        return "live"
    return "unknown"


# ─── Helpers ──────────────────────────────────────────────────────

def lookup_price(lookup_key: str) -> stripe.Price:
    """
    Resolve a lookup_key → active Stripe Price object.

    Raises RuntimeError if no active price matches. Active prices
    are the only ones customers can be billed against — archived ones
    won't show.

    Used at every checkout/trial path so that price-ID rotation
    in the dashboard never breaks the billing flow.
    """
    _ensure_initialized()
    prices = stripe.Price.list(
        lookup_keys=[lookup_key],
        active=True,
        limit=1,
    )
    if not prices.data:
        raise RuntimeError(
            f"No active Stripe price with lookup_key='{lookup_key}'. "
            "Check Stripe dashboard → Products → InboxScore Pro and "
            "confirm both monthly + yearly prices exist with the "
            "expected lookup_keys."
        )
    return prices.data[0]


# ─── Customer management ──────────────────────────────────────────

def get_or_create_customer(
    user_id: str,
    email: str,
    name: Optional[str] = None,
    existing_customer_id: Optional[str] = None,
) -> stripe.Customer:
    """
    Idempotent Stripe Customer creation.

    Resolution order:
      1. If existing_customer_id provided → retrieve and return it.
         (This is the common path — profiles.stripe_customer_id is
         populated after first signup, so subsequent calls skip the
         create.)
      2. Otherwise → create a new Customer with user_id in metadata,
         using idempotency_key keyed on user_id so retries don't
         duplicate.

    Args:
        user_id: Internal user UUID (matches profiles.id)
        email: User's email — used as Stripe's display field
        name: Optional display name
        existing_customer_id: If profiles.stripe_customer_id is
            already populated, pass it here to skip the create call

    Returns:
        stripe.Customer object
    """
    _ensure_initialized()
    if existing_customer_id:
        try:
            return stripe.Customer.retrieve(existing_customer_id)
        except StripeError as e:
            # Customer may have been deleted in Stripe (rare — usually
            # a sandbox reset). Fall through to create a fresh one.
            logger.warning(
                "Failed to retrieve Stripe customer %s for user %s — "
                "falling back to create. Reason: %s",
                existing_customer_id, user_id, e,
            )

    logger.info("Creating Stripe customer for user_id=%s", user_id)
    return stripe.Customer.create(
        email=email,
        name=name,
        metadata={
            "user_id": user_id,
            "source": "inboxscore",
        },
        idempotency_key=f"customer-create-{user_id}",
    )


# ─── Trial subscription ───────────────────────────────────────────

def create_trial_subscription(
    user_id: str,
    email: str,
    name: Optional[str] = None,
) -> stripe.Subscription:
    """
    Create a 14-day Pro trial subscription with NO payment method.

    Called from the signup handler in app.py (INBOX-209). The flow:

      1. Create (or retrieve) a Stripe Customer for the user
      2. Create a Subscription on the monthly Pro price with
         trial_period_days=14 and payment_behavior='default_incomplete'
         — this means Stripe won't try to charge during the trial
      3. Return — caller writes the resulting subscription details to
         the local `subscriptions` table (status='trialing', plan='pro',
         trial_end=…) so feature-gating works immediately

    On day 14, Stripe will attempt to charge the (non-existent) card,
    fail, and transition the subscription to 'incomplete_expired'.
    Our webhook handler then flips the local row to status='stub'
    and the user lands in the Stub Free dashboard state.

    Args:
        user_id: Internal user UUID
        email: User's email
        name: Optional display name

    Returns:
        stripe.Subscription object with status='trialing'
    """
    _ensure_initialized()
    customer = get_or_create_customer(user_id, email, name)
    price = lookup_price(LOOKUP_KEY_MONTHLY)

    logger.info(
        "Creating trial subscription for user_id=%s customer=%s price=%s",
        user_id, customer.id, price.id,
    )

    return stripe.Subscription.create(
        customer=customer.id,
        items=[{"price": price.id}],
        trial_period_days=TRIAL_DAYS,
        # Don't fail the create if no payment method on file. Stripe
        # will retry charging on day 14; if no card by then, the sub
        # transitions to incomplete_expired and our webhook handles
        # the rest.
        payment_behavior="default_incomplete",
        payment_settings={
            "save_default_payment_method": "on_subscription",
        },
        # Stripe Tax adds VAT/GST per customer's location at invoice
        # time. UK customers pay $49 + 20% = $58.80; US customers $49.
        automatic_tax={"enabled": True},
        expand=["latest_invoice.payment_intent"],
        metadata={
            "user_id": user_id,
            "source": "signup_trial",
        },
        idempotency_key=f"trial-sub-{user_id}",
    )


# ─── Checkout sessions ────────────────────────────────────────────

def create_checkout_session(
    user_id: str,
    customer_id: str,
    price_lookup_key: str,
    success_url: str,
    cancel_url: str,
    idempotency_suffix: Optional[str] = None,
) -> stripe.checkout.Session:
    """
    Create a Stripe-hosted Checkout Session.

    Two use cases:
      1. Trial → Paid conversion. User is on a trial sub, clicks
         "Add card to keep Pro", lands here, completes payment.
         The trial sub gets updated with the new payment_method.
      2. Stub → Pro reactivation. Lapsed user comes back, clicks
         "Reactivate Pro" from Stub state, lands here, completes
         payment. A fresh subscription starts immediately (no trial).

    Both paths skip the trial period — one trial per customer per
    lifetime. The trial was used at signup.

    Args:
        user_id: Internal user UUID (mirrored in metadata)
        customer_id: Existing stripe_customer_id from profiles
        price_lookup_key: 'pro_monthly_usd' or 'pro_yearly_usd'
        success_url: Where Stripe redirects after successful payment
        cancel_url: Where Stripe redirects if user clicks Cancel

    Returns:
        stripe.checkout.Session — caller redirects browser to .url
    """
    _ensure_initialized()
    price = lookup_price(price_lookup_key)

    # INBOX-267 Layer 3: idempotency key on Checkout Session create.
    # Same (user_id, price, day) within Stripe's 24h idempotency window
    # returns the SAME Session — prevents duplicates from double-clicks,
    # network retries, browser back/forward replay. The day suffix lets
    # a user legitimately retry on the next day if their first attempt
    # truly failed. Caller can override idempotency_suffix for testing.
    import datetime as _dt
    day_suffix = idempotency_suffix or _dt.datetime.utcnow().strftime("%Y%m%d")
    idempotency_key = f"checkout-{user_id}-{price_lookup_key}-{day_suffix}"

    logger.info(
        "Creating checkout session for user_id=%s customer=%s price=%s idem=%s",
        user_id, customer_id, price.id, idempotency_key,
    )

    return stripe.checkout.Session.create(
        customer=customer_id,
        line_items=[{"price": price.id, "quantity": 1}],
        mode="subscription",
        # No trial_period_days key here → Stripe charges immediately.
        # One trial per customer (per Stripe's idempotency). This
        # checkout path is conversion or reactivation, not a fresh
        # trial. Passing trial_period_days=0 is REJECTED by Stripe
        # ('minimum trial period days is 1') — omit the key entirely
        # to get the 'charge now' behaviour. (Caught by Vinoop test
        # 2026-05-13.)
        subscription_data={
            "metadata": {
                "user_id": user_id,
                "source": "checkout",
            },
        },
        success_url=success_url,
        cancel_url=cancel_url,
        # VAT / GST collection — see Phase 0 Step 6.
        automatic_tax={"enabled": True},
        # Allow Stripe to update the customer's address from what they
        # type at checkout. Needed for accurate VAT routing.
        customer_update={"address": "auto", "name": "auto"},
        # Required for VAT — Stripe Tax needs a billing address.
        billing_address_collection="required",
        # Show the user's tax ID field at checkout. Lets B2B customers
        # enter their VAT number → invoice is reverse-charge for EU
        # B2B sales (Stripe Tax handles the math).
        tax_id_collection={"enabled": True},
        # expires_at intentionally omitted — Stripe defaults to 24h
        # which is plenty. Passing expires_at=None used to be in here
        # but Stripe rejected it as an invalid timestamp (Vinoop hit
        # this 2026-05-13 while testing).
        idempotency_key=idempotency_key,
    )


# ─── Customer Portal ──────────────────────────────────────────────

def create_portal_session(
    customer_id: str,
    return_url: str,
) -> stripe.billing_portal.Session:
    """
    Create a Stripe-hosted Customer Portal session.

    The portal is configured in the dashboard (Phase 0 Step 5):
      - View invoices, update payment method, update billing details
      - Cancel subscription (at end of period — not immediate)
      - Switch between monthly ↔ yearly (with proration on upgrade,
        end-of-period on downgrade)
      - View Tax IDs

    Args:
        customer_id: stripe_customer_id from profiles.stripe_customer_id
        return_url: Where Stripe redirects after the user finishes —
            typically `https://inboxscore.ai/settings/billing`

    Returns:
        stripe.billing_portal.Session — caller redirects browser to .url
    """
    _ensure_initialized()
    logger.info(
        "Creating customer portal session for customer=%s",
        customer_id,
    )
    return stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=return_url,
    )


# ─── Subscription retrieval (for webhook handlers) ────────────────

def retrieve_subscription(subscription_id: str) -> Dict[str, Any]:
    """
    Fetch a Stripe Subscription by ID and return it as a plain dict.

    Used by webhook handlers (notably checkout.session.completed and
    customer.subscription.created) that receive just the subscription
    ID and need the full current state — status, items, current period
    dates, trial_end — to mirror into our subscriptions table.

    Returning a plain dict (not the SDK object) keeps the callers free
    of stripe.* imports and makes the upsert path uniform regardless
    of where the dict came from (webhook payload vs. direct fetch).

    Args:
        subscription_id: 'sub_*' id

    Returns:
        Subscription as dict, ready to pass to
        db.upsert_subscription_from_stripe()
    """
    _ensure_initialized()
    sub = stripe.Subscription.retrieve(subscription_id)
    return sub.to_dict() if hasattr(sub, "to_dict") else dict(sub)


# ─── INBOX-267: Single-active-subscription invariant ──────────────
#
# Helpers used by Layers 2 (API guard) and 4 (webhook reconciler) of
# the 5-layer defense-in-depth fix for the duplicate-subscription bug.
#
# Stripe doesn't dedupe subscriptions — a single Customer can carry
# unlimited subscriptions. For InboxScore (one sub per user, ever),
# we have to enforce the invariant ourselves at multiple layers.

# Statuses we consider "live" for the purpose of duplicate detection.
# Includes 'past_due' because that's still a billable subscription —
# Stripe is just retrying after a failed charge. 'unpaid' is also
# live in the sense that Stripe still owns it.
LIVE_SUBSCRIPTION_STATUSES = {
    "active",
    "trialing",
    "past_due",
    "unpaid",
    "incomplete",
}


def list_active_subscriptions(customer_id: str) -> list:
    """
    Return all subscriptions on this customer whose status is in
    LIVE_SUBSCRIPTION_STATUSES, sorted oldest-first (by created).

    Used by:
      - Layer 2 (API guard): /api/billing/checkout calls this before
        creating a new Checkout Session. If the list is non-empty,
        the request is rejected with 409 and a portal_url is returned.
      - Layer 4 (webhook reconciler): customer.subscription.created
        calls this to detect siblings; if >1, cancels the older.

    Args:
        customer_id: Stripe customer ID

    Returns:
        list of stripe.Subscription objects (oldest first)
    """
    _ensure_initialized()
    # List up to 100 subs for the customer. We don't paginate — if a
    # customer somehow has >100 subs, that's a much bigger problem we
    # want to crash on, not silently truncate.
    subs = stripe.Subscription.list(customer=customer_id, status="all", limit=100)
    live = [s for s in subs.auto_paging_iter()
            if getattr(s, "status", None) in LIVE_SUBSCRIPTION_STATUSES]
    live.sort(key=lambda s: getattr(s, "created", 0))
    return live


def cancel_subscription(subscription_id: str, reason: str = "duplicate_cleanup") -> Dict[str, Any]:
    """
    Cancel a Stripe subscription immediately (not at period end).

    Used by Layer 4 (webhook reconciler) to remove duplicate
    subscriptions discovered when customer.subscription.created fires
    and finds a sibling already active on the same customer.

    Args:
        subscription_id: 'sub_*' id to cancel
        reason: free-text reason logged in subscription.metadata

    Returns:
        The cancelled subscription as a dict
    """
    _ensure_initialized()
    logger.warning(
        "Cancelling subscription %s — reason=%s",
        subscription_id, reason,
    )
    sub = stripe.Subscription.cancel(
        subscription_id,
        # cancellation_details lets us tag the reason in Stripe so it
        # shows up in the dashboard and webhook payload for audit.
        cancellation_details={
            "comment": f"InboxScore reconciler: {reason}",
        },
    )
    return sub.to_dict() if hasattr(sub, "to_dict") else dict(sub)


# ─── Webhook signature verification ───────────────────────────────

def verify_webhook(payload: bytes, signature_header: str) -> Dict[str, Any]:
    """
    Verify a Stripe webhook request and return the parsed Event.

    Raises stripe.error.SignatureVerificationError if:
      - The signature header is missing/malformed
      - The payload was tampered with
      - The timestamp is outside the tolerance window (default 5min)

    Caller (/api/webhooks/stripe in INBOX-207) catches this exception
    and returns HTTP 400 to Stripe. Stripe will retry the delivery.

    Args:
        payload: The RAW request body bytes — NOT json-parsed. The
            signature is computed over the bytes, so any parsing/
            re-serialization breaks verification.
        signature_header: The value of the 'Stripe-Signature' header
            on the request

    Returns:
        Parsed event dict (the Stripe Event object as a plain dict).
        Caller inspects event['type'] to route to the right handler.
    """
    _ensure_initialized()
    secret = get_webhook_secret()
    return stripe.Webhook.construct_event(
        payload=payload,
        sig_header=signature_header,
        secret=secret,
    )


# ─── Public API surface ───────────────────────────────────────────
#
# Importers should call these top-level functions, not stripe.* directly.
# This makes mocking trivial in tests: patch billing.<func> per call.

__all__ = [
    "TRIAL_DAYS",
    "LOOKUP_KEY_MONTHLY",
    "LOOKUP_KEY_YEARLY",
    "STRIPE_API_VERSION",
    "lookup_price",
    "get_or_create_customer",
    "create_trial_subscription",
    "create_checkout_session",
    "create_portal_session",
    "retrieve_subscription",
    "list_active_subscriptions",
    "cancel_subscription",
    "LIVE_SUBSCRIPTION_STATUSES",
    "verify_webhook",
    "get_webhook_secret",
    "get_stripe_mode",
]
