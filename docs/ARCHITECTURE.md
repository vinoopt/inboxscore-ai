# InboxScore.ai — Architecture

**Version:** 1.0 (2026-04-27)
**Maintainer:** Vinoop + AI pair
**Audience:** anyone (or any AI session) coming into this codebase fresh

This is the canonical mental model for the product. It's intended to bring someone up to speed in 15 minutes. Read this first before reading code.

---

## 1. Mission and product

InboxScore.ai is an **email deliverability scoring + monitoring SaaS**. A user puts in a domain, the app runs ~15 checks against the domain (SPF, DKIM, DMARC, MX, TLS, blacklists, reverse DNS, MTA-STS, BIMI, domain age, Google Safe Browsing, etc.), produces a 0-100 score, and surfaces actionable fixes.

Beyond one-off scans, the Pro tier adds continuous monitoring: connect Google Postmaster Tools and Microsoft SNDS, get daily-refreshed deliverability metrics (spam rate, auth pass rate, reputation), and get alerts when something degrades.

**Pricing model:** Free (one-off scans + limited monitoring) and Pro (continuous monitoring, real Postmaster/SNDS data, history, alerts). Pricing/plans defined in the `profiles.plan` column.

**Live URL:** https://inboxscore.ai
**Repo:** https://github.com/vinoopt/inboxscore-ai
**Hosting:** Render (Starter $7/mo, auto-deploy from GitHub main, gated by CI)
**Database / auth:** Supabase project `jxqxvexoduynwpywhevr` (us-west-2 / Oregon)

---

## 2. System architecture (one paragraph)

A single FastAPI app (`app.py`) running on Render serves the whole product — both the marketing/static HTML pages and the JSON API. State lives in Supabase Postgres (with Supabase auth for users). Background workers run inside the same FastAPI process via APScheduler (no separate worker dyno). External integrations are called directly from request handlers or scheduled jobs: Google Postmaster v2, Microsoft SNDS, Google Safe Browsing v4, HetrixTools (blacklists), Resend (email — env vars not set yet, INBOX-6), Sentry (errors), Stripe (planned for Pro billing — INBOX-10).

```
┌────────────────────────────────────────────────────────────────┐
│                  Render service (single process)               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ FastAPI app.py                                           │  │
│  │   ├── Static pages (FileResponse from /static)           │  │
│  │   ├── /api/* JSON endpoints                              │  │
│  │   ├── auth.py (Supabase JWT verification)                │  │
│  │   ├── checks.py (15 deliverability checks)               │  │
│  │   ├── scan_service.py (run_full_scan orchestrator)       │  │
│  │   ├── monitor.py (run_monitoring_cycle every 15 min)     │  │
│  │   ├── postmaster_scheduler.py (daily 06:00 UTC)          │  │
│  │   ├── snds_scheduler.py (daily 07:00 UTC)                │  │
│  │   ├── heartbeat.py + watchdog_tick (every 5 min)         │  │
│  │   └── middleware.py (request_id + structured logging)    │  │
│  └────┬─────────────────────────────────────────────────────┘  │
└───────┼────────────────────────────────────────────────────────┘
        │
        ├──→ Supabase (Postgres + Auth)
        ├──→ Google Postmaster Tools v2 API
        ├──→ Microsoft SNDS (CSV download)
        ├──→ Google Safe Browsing v4 API
        ├──→ HetrixTools (blacklist lookups)
        ├──→ Sentry (error tracking)
        └──→ Render API (CI deploy gating, env-var management)
```

CI: GitHub Actions runs pytest + ruff. On green, CI calls Render's deploy API to trigger a build (autoDeploy is **off** — CI is the gate). See `reference_inboxscore_ci.md` memory for the trigger pattern.

---

## 3. Repository layout

```
inboxscore/
├── app.py                    # FastAPI entrypoint, all route definitions
├── auth.py                   # Supabase JWT verification, user lookup
├── db.py                     # All Supabase queries (single source of truth)
├── checks.py                 # 15 deliverability check functions
├── scan_service.py           # run_full_scan + generate_summary
├── monitor.py                # run_monitoring_cycle (15-min interval)
├── postmaster.py             # Google Postmaster v2 API client
├── postmaster_scheduler.py   # Daily 06:00 UTC sync
├── snds.py                   # Microsoft SNDS CSV client
├── snds_scheduler.py         # Daily 07:00 UTC sync
├── heartbeat.py              # Cycle heartbeats + watchdog
├── hetrix.py                 # HetrixTools blacklist client
├── pdf_report.py             # PDF generation for scan reports
├── middleware.py             # request_id + structured logging
├── logging_config.py         # JSON log formatter
├── static/                   # All HTML pages (vanilla HTML/CSS/JS — no SPA framework)
├── migrations/               # SQL migrations (001..009 today)
├── tests/                    # pytest suite (302 tests as of today)
└── docs/                     # This file + audits + decisions
```

**No build step.** HTML/CSS/JS is hand-written, served as-is via FastAPI's FileResponse. There is no React/Vue/Svelte/etc. This was a deliberate choice — fast iteration, low surface area, no transpilation cache to break.

---

## 4. Authentication and user model

### 4.1 Auth flow

1. User signs up via `/api/auth/signup` → Supabase creates a row in `auth.users` and we create a corresponding row in `public.profiles`
2. Login via `/api/auth/login` returns a JWT access token + refresh token. Frontend stores them in `localStorage` (or `sessionStorage` if "Remember me" is off)
3. Every authenticated API call sends `Authorization: Bearer <jwt>`
4. `auth.get_user_from_token(token)` validates the JWT against Supabase and returns the user record
5. `db.get_user_plan(user_id)` resolves the plan from `profiles.plan`. Plans: `free`, `pro`, `growth`, `enterprise`

### 4.2 Plan gating

The `_require_pro_plan(user_id)` helper raises 403 if the plan isn't in `("pro", "growth", "enterprise")`. Used by all Postmaster + SNDS endpoints.

### 4.3 Known auth gotchas

- **INBOX-84 — duplicate profile rows.** The schema does not enforce `UNIQUE(email)` on `profiles`. A signup race or a manual AI-edit-gone-wrong has produced duplicate rows for at least one account (Vinoop). Different endpoints can resolve to different rows of the same user, leading to confusing UI (sidebar says "Free", but Postmaster page shows real Pro data because the data-fetch endpoint resolved to a different row). **Migration 010 will add the unique constraint** after a dedupe pass — see ticket.
- **INBOX-19 — embedded GitHub PAT in `.git/config`.** Local hygiene issue, not a runtime bug, but flagged in case anyone clones from Vinoop's machine.

---

## 5. Pages — one section each

The product has 10 HTML pages. Here's what each does, what data it needs, and the key endpoints it calls.

### 5.1 Marketing (`/`)
**File:** `static/index.html`
**Purpose:** public-facing landing page. Contains the "Try it free" scan form.
**Triggers:** `POST /api/scan` with `{domain: "..."}` → runs a one-off scan, no auth required.
**Notes:** also has the marketing site nav, pricing teaser. Receives GA4 events for funnel tracking.

### 5.2 Auth pages (`/signup`, `/login`, `/forgot-password`)
**Files:** `static/{signup, login, forgot-password}.html`
**Endpoints:** `POST /api/auth/signup`, `POST /api/auth/login`, `POST /api/auth/forgot-password`. After auth, frontend stores JWT and redirects to `/dashboard`.

### 5.3 Dashboard (`/dashboard`)
**File:** `static/dashboard.html`
**Purpose:** the home screen for authenticated users. Shows score hero, DNS/auth diagnostic tiles, Domain Safety, Active Alerts, Provider Status, Recent Scans, Score Trend bar chart, plus a "Scan new domain" input.
**Key elements:**
- Score Hero (single domain) or Portfolio table (multiple domains)
- 7 diagnostic tiles (SPF, DKIM, DMARC, MX, Reverse DNS, TLS, MTA-STS) — INBOX-82 trim
- Domain Safety (3 tiles: Google Safe Browsing, Domain Age, Sending domain blacklists) — INBOX-95
- Score Trend: 7-day bar chart with fixed slots, local-timezone keys (INBOX-99)
- Recent Scans list

**Endpoints called:** `/api/user/domains`, `/api/user/scans`, `/api/scan` (POST), `/api/scans/{id}`, plus per-domain `/api/domains/{domain}/scans` for history.

**Render path:** `dashShowView('dashboard')` → `dhRenderSingleView()` orchestrates all sub-renders. Default state pick: `dhPickDefaultDomain()` filters to monitored domains first (INBOX-83) so a one-off scan can't hijack the default.

### 5.4 Email Health (`/email-health`) — most complex
**File:** `static/email-health.html`
**Purpose:** detailed deliverability intelligence per domain, segmented by provider.
**Submenu (4 sections):**
- **Google Postmaster** — 6 internal tabs: Compliance Status, Spam, Feedback Loop, Authentication, Encryption, Delivery Errors
- **Microsoft SNDS** — IP-level reputation, complaint rate trend, sample data
- **Blacklist Monitor** — domain + IP blacklist status (HetrixTools)
- **IP Reputation** — combined SNDS + blacklist view per IP

**Load orchestrator:** `ehInit()` (added in INBOX-101) — single sequential async function that walks `init → status → (free|disconnected|continue) → domains → metrics`. All fetches use `fetchWithTimeout()` with 5s timeout. Backstop watchdog at 7s forces error state if `ehInit` silently breaks.

**Postmaster state machine:** `init / data / nodata / disconnected / free / error` — see `setGpmState()`.

**Period buttons:** 7d / 30d / 90d affect Postmaster metric fetch (`?days=N`). Currently SNDS, blacklist, IP reputation ignore the period button (filed as audit-L4).

### 5.5 Domains (`/domains`, `/domains/{domain}`)
**File:** `static/domains.html`
**Purpose:** list and manage monitored domains. Toggle monitoring on/off per domain.
**Endpoints:** `GET/POST /api/user/domains`, `DELETE /api/user/domains/{id}`, `PUT /api/user/domains/{id}/monitoring`.

### 5.6 Sending IPs (`/sending-ips`)
**File:** `static/sending-ips.html`
**Purpose:** list + add/remove user's sending IPs. Map IPs to specific domains for SNDS attribution.
**Endpoints:** `GET/POST /api/user/ips`, `PUT /api/user/ips/{ip}/domains`, `DELETE /api/user/ips/{ip}`.

### 5.7 Alerts (`/alerts`)
**File:** `static/alerts.html`
**Purpose:** show alerts triggered by monitor cycles (score drops, blacklists, deliverability degradation).
**Endpoints:** `GET /api/user/alerts`, `GET /api/user/alerts/count`, `PUT /api/alerts/{id}/read`, `PUT /api/user/alerts/read-all`, `DELETE /api/alerts/{id}`.
**Note:** alerts are written to DB but **email delivery is not configured** (INBOX-6 — no Resend/SMTP env vars in production yet).

### 5.8 Settings (`/settings`)
**File:** `static/settings.html`
**Purpose:** profile, password, preferences, connected services (Postmaster, SNDS), billing.
**Tabs:** Profile, Password, Preferences, Connected Services, Billing (placeholder).
**Endpoints:** `GET/PUT /api/user/profile`, `PUT /api/user/password`, `PUT /api/user/preferences`, `GET /api/user/export`, `DELETE /api/user/account`.
**URL params:** `?tab=connections` jumps to the Connected Services panel — used by Dashboard's Provider Status tiles (INBOX-92).

---

## 6. Scoring system

`scan_service.run_full_scan(domain, user_id)` orchestrates 15 checks in parallel, sums per-check points, and produces a `score` 0-100 plus a list of CheckResult objects.

### Current 15 checks (after INBOX-95)

| Check | Max points | Notes |
|---|---|---|
| `check_spf` | 10 | SPF record presence + syntax |
| `check_dkim` | 10 | DKIM with common selectors (default, google, k1, etc.) |
| `check_dmarc` | 10 | DMARC record + policy |
| `check_mx_records` | 5 | MX present and resolvable |
| `check_reverse_dns` | 5 | PTR matching A/AAAA |
| `check_tls` | 5 | MX hostname has valid cert (INBOX-24 rewrite) |
| `check_mta_sts` | 5 | MTA-STS policy + DNS record |
| `check_blacklists` | 10 | DNSBL lookups for sending IPs (Spamhaus, etc.) |
| `check_domain_blacklists` | 10 | DBL/SURBL/URIBL for the domain itself (INBOX-42) |
| `check_bimi` | 0 | Currently info-only, not scored — see INBOX-59 |
| `check_domain_age` | 5 | Age via RDAP (INBOX-78 + INBOX-96) |
| `check_dnssec` | 5 | Backlogged in INBOX-61 |
| `check_arc` | 5 | Backlogged in INBOX-61 |
| `check_google_safe_browsing` | 2 | INBOX-95 — real GSB v4 API |
| `check_email_authentication_alignment` | 0 | INBOX-55 — backlogged, planned to add |

**Canonical max points** are tracked in `scan_service.CANONICAL_MAX_POINTS` and asserted by tests/test_scan_service.py.

### Storage

`scans` table holds the canonical scan record: `domain`, `user_id` (nullable for anon scans), `score`, `score_band` (`Excellent`/`Good`/`Needs Work`/`At Risk`), `scan_type` (`manual` / `scheduled`), `results` (jsonb of CheckResults), `created_at`, etc.

For monitored domains, `domains.score` is updated to the latest scan score so the Dashboard can show the current state without re-running the full scan.

---

## 7. Background workers

All run inside the FastAPI process via APScheduler. No separate worker dyno.

### 7.1 `run_monitoring_cycle` — every 15 minutes
- For each monitored domain (`domains.monitoring_enabled = true`), runs `scan_service.run_full_scan` and writes a new `scans` row with `scan_type = 'scheduled'`
- Updates `domains.score`
- Triggers alerts when score drops or blacklist appears

### 7.2 `sync_all_postmaster_users` — daily at 06:00 UTC
- For each row in `postmaster_connections`, calls `fetch_metrics_for_user(user_id, connection, days=14)`
- Pulls all verified domains from Google Postmaster v2 → for each domain, queries `domainStats` for last 14 days → upserts into `postmaster_metrics`
- Logs to `postmaster_sync_log` (status: success / partial / failed)
- **Audit-M1:** the manual `/api/postmaster/sync` endpoint does NOT log here — only the scheduler does

### 7.3 `sync_all_snds_users` — daily at 07:00 UTC
- For each row in `snds_connections`, fetches the SNDS CSV from Microsoft, parses, deduplicates IPs, upserts into `snds_metrics`

### 7.4 `watchdog_tick` — every 5 minutes (INBOX-16)
- Reads from `heartbeats` table and detects stale cycles
- Logs `watchdog.stale` with affected `cycle_type`s
- Currently only logs — no auto-recovery

### 7.5 Heartbeat pattern (INBOX-16)
Every cycle wraps `heartbeat.start(cycle_type)` / `heartbeat.end(cycle_type, status)` calls. Failures are logged as `heartbeat.fetch_failed`. Used by the watchdog to detect hangs.

---

## 8. Database schema

### Core tables

| Table | Purpose | Key columns |
|---|---|---|
| `auth.users` | Supabase-managed auth | `id`, `email`, `email_confirmed_at` |
| `profiles` | App profile per user | `id` (= auth.users.id), `email`, `name`, `plan`, `created_at` |
| `domains` | Monitored domains | `id`, `user_id`, `domain`, `monitoring_enabled`, `score`, `created_at` |
| `scans` | Per-scan results | `id`, `user_id`, `domain`, `score`, `score_band`, `scan_type`, `results`, `created_at` |
| `monitoring_logs` | Per-cycle log per domain | `domain_id`, `score_change`, `triggered_alerts`, `created_at` |
| `alerts` | User-facing alerts | `id`, `user_id`, `domain`, `severity`, `message`, `read`, `created_at` |
| `user_ips` | User's sending IPs | `id`, `user_id`, `ip_address`, `created_at` |
| `user_ip_domains` | Many-to-many IP→domain | `ip_id`, `domain` |
| `postmaster_connections` | OAuth tokens for Google | `user_id`, `access_token`, `refresh_token`, `token_expiry`, `google_email` |
| `postmaster_metrics` | Daily Postmaster data | `user_id`, `domain`, `date`, spam_rate, auth_success_*, encrypted_traffic_tls, raw_data |
| `postmaster_sync_log` | Sync run history | `user_id`, `sync_started_at`, `sync_completed_at`, `domains_synced`, `status` |
| `snds_connections` | Microsoft SNDS keys | `user_id`, `snds_key`, `tracked_ips` |
| `snds_metrics` | Daily IP metrics | `user_id`, `ip_address`, `metric_date`, `data_pct`, `complaint_rate`, ... |
| `blacklist_results` | HetrixTools cached results | `user_id`, `domain`, `total_listings`, `details`, `checked_at` |
| `rate_limits` | Per-user rate-limiting | `user_id` (INBOX-30), `endpoint`, `count`, `window_start` |
| `heartbeats` | Cycle heartbeats | `cycle_type`, `started_at`, `ended_at`, `status` |

### Migrations
9 migrations to date: `001_base_schema` ... `009_rate_limits_user_id`. INBOX-32 added a `schema-drift-check` CI job that compares prod schema to migration replay and fails CI on drift.

### Known schema gaps
- `profiles` lacks `UNIQUE(email)` (INBOX-84)
- `postmaster_metrics` has no `updated_at` (audit-M2 / INBOX-108)

---

## 9. External integrations

| Service | Purpose | Auth | Module | Notes |
|---|---|---|---|---|
| Supabase | Postgres + auth | Service role key | `db.py`, `auth.py` | Project: jxqxvexoduynwpywhevr |
| Google Postmaster v2 | Email deliverability data | OAuth 2.0 per user | `postmaster.py` | Migrated v1→v2 in March 2026 |
| Microsoft SNDS | IP-level reputation | Per-user SNDS key | `snds.py` | CSV download — fragile parsing |
| Google Safe Browsing v4 | Malware/phishing check | API key (env) | `checks.py::check_google_safe_browsing` | INBOX-95 |
| HetrixTools | DNSBL aggregator | API token | `hetrix.py` | INBOX-50 backlog: improve to use real list |
| Sentry | Error tracking | DSN env var | `app.py::sentry_sdk.init` | Org: luvia-digital-ltd, project: python-fastapi |
| Render | Hosting + CI deploy gate | API key | (CI script) | Service: srv-d6hufv7kijhs73fnlf8g |
| Resend | Transactional email | env vars not set yet (INBOX-6) | n/a | Pending |
| Stripe | Pro billing | env vars not set yet (INBOX-10) | n/a | Pending |

---

## 10. Deployment

- **Auto-deploy is OFF** on the Render service. CI is the gate.
- GitHub Actions runs on every push to `main` (see `.github/workflows/`):
  1. ruff lint
  2. pytest
  3. schema-drift-check (replay migrations, diff against prod schema dump)
- On green, CI calls Render's deploy API to trigger a build with `trigger=api`. Render's deploy log marks these `trigger=api` (vs. `manual` / `webhook`).
- Health-check path: `/health` (INBOX-9). Render only marks a deploy live after `/health` returns 200.
- Secrets live in Render env vars + a few `.env.*` files (`.env.render`, `.env.sentry`, `.env.supabase`) on Vinoop's machine. NOT checked into git.

### Versioning
`/health` returns `{status, version, db, auth}`. `version` is a manual constant in `app.py` (currently `1.15.1`). Bumped only when there's a notable cut. Per-deploy uniqueness should use `RENDER_GIT_COMMIT` env var (INBOX-102 was about to land a version-check banner using this — superseded by the actual JS bug we found).

---

## 11. Observability

### Logging (INBOX-14)
- Structured JSON logs via `logging_config.py`
- Every request gets a `request_id` (UUID4) injected by `middleware.py`
- All log lines include `request_id`, `level`, `logger`, `msg`, plus context fields

### Sentry
- Initialised in `app.py` startup. DSN from `SENTRY_DSN` env var
- PII scrubbing + DSN rate-limit configured
- Release tagged with current version + git commit
- Alert rule: any new issue → email Vinoop

### Heartbeats (INBOX-16)
- Every background cycle writes to `heartbeats`
- `watchdog_tick` runs every 5 min, flags any cycle that hasn't checked in within its expected window

---

## 12. Testing

- **302 tests** as of today (2026-04-27), all green
- Pytest with FastAPI TestClient + mocked Supabase + mocked external APIs
- Test files: `tests/test_*.py` — coverage for checks, scan_service, db, postmaster (limited), idor, timezone, scheduler error reporting
- **Major gap (audit-H2):** zero behavioural tests for any `/api/postmaster/*` or `/api/snds/*` endpoint. All current /email-health tests are HTML structure assertions
- **Schema drift CI:** replays migrations against a fresh Postgres, dumps schema, diffs against `db/prod-schema-2026-04-22.sql`. Fails on drift

---

## 13. Known gotchas (the "if you don't know this, you'll burn 2 hours" list)

1. **No build step.** Edit HTML/CSS/JS directly. Hard-refresh (Cmd+Shift+R) after deploys — the `/email-health` route has no Cache-Control header (audit-L5).
2. **APScheduler runs in-process.** A long-running cycle blocks the FastAPI worker. Cycles are async, so this is mostly fine, but watch for blocking calls inside cycles.
3. **Plan resolution depends on which row gets returned.** INBOX-84 — duplicate profiles can cause the Pro/Free distinction to flip mid-session. Until migration 010 lands, use Vinoop's account as the canary.
4. **Free vs Pro UI.** `_require_pro_plan` raises 403 only on Pro endpoints. The frontend separately reads `data.is_pro` from `/api/postmaster/status` and `/api/snds/status` to decide whether to show the paywall vs the data UI.
5. **Postmaster sync depth is 14 days hardcoded** (audit-M4) regardless of UI period.
6. **Free user can scan via the marketing form, but it doesn't auto-monitor.** Monitoring requires explicit add via the Domains page.
7. **`utcnow()` is banned** in this codebase (INBOX-29 + ruff DTZ003). Use `datetime.now(timezone.utc)`.
8. **Set ordering matters** (INBOX-26). Sets are insertion-ordered in CPython but not in spec — sort before iterating if order is observable.
9. **The HTML pages have multiple DOMContentLoaded handlers.** They run in registration order and CAN race each other. Today's INBOX-101 work consolidated this for /email-health into a single `ehInit()` orchestrator. Other pages still have multi-handler code.
10. **`postmaster_metrics` only has `created_at`.** No `updated_at` — gap that drove today's INBOX-102 last_sync_at workaround. Migration 010 (audit-M2) adds it.
11. **Schedulers don't lock against manual triggers.** A user clicking "Sync now" while the daily 06:00 UTC scheduler is mid-run can cause concurrent fetches (audit-M3).

---

## 14. Open ticket overview (current backlog)

Snapshot at end of 2026-04-27. See Plane workspace `mailercloud` / project `InboxScore` for live state.

| Bucket | Tickets | Status |
|---|---|---|
| **Audit follow-ups (filed today)** | INBOX-103..109 | Todo / Backlog |
| **Postmaster page polish** | INBOX-102 (this batch shipped) | In review |
| **Foundation Audit phases** | INBOX-13 epic | Phase 0 done; phases 1-6 designed |
| **High-priority deliverability** | INBOX-69 (DKIM rotating selectors), INBOX-80 (compliance endpoint failure), INBOX-75 (transparency) | Open |
| **Plan duplicate cleanup** | INBOX-84 | Awaiting Vinoop go-ahead |
| **Pricing/Stripe** | INBOX-10 | Open |
| **Email alerts pipeline** | INBOX-6 | Open |
| **SNDS env vars** | INBOX-5 | Open |
| **Mobile responsive** | INBOX-98 | Open |
| **Design system rollout** | INBOX-65, INBOX-67 | In progress |
| **CTA + scoring features** | INBOX-46 / 47 / 48 (shipped), INBOX-55, 60, 61, 64, 76, 79 | Mixed |

---

## 15. How to update this doc

This is intended to be a **living document.** Update it when:
- A new page or major feature is added
- The schema changes substantially (new tables, new relationships)
- A new external integration is added or an old one removed
- A scheduler / background job changes cadence or scope
- An auth flow or plan-gating rule changes
- A "gotcha" worth knowing is discovered (then add to section 13)

If a section becomes stale and you don't have time to fix it, **delete the stale section** rather than leave it. Stale docs are worse than missing docs.

For an audit-style point-in-time snapshot of a single subsystem, write a separate `docs/<subsystem>-AUDIT-YYYY-MM-DD.md` file (see `EMAIL-HEALTH-AUDIT-2026-04-27.md` for the template).

---

## 16. Onboarding checklist (15 minutes to productive)

If you're new to this codebase (human or AI), do these in order:

1. **Read this file** end-to-end (you're doing it)
2. **Read `app.py:1–200`** to see the imports + scheduler setup + middleware
3. **Skim `checks.py`** — understand what a CheckResult looks like and how scoring works
4. **Skim `static/dashboard.html`** — get a feel for the vanilla-JS state of the world
5. **Run `pytest -q`** locally to confirm 302 tests pass
6. **Read the 3 most recent ticket descriptions** in Plane to see what's actively being shipped

You should now be able to make a small, scoped change without breaking things. For anything bigger, also read the relevant subsystem audit (currently only `EMAIL-HEALTH-AUDIT-2026-04-27.md` exists).
