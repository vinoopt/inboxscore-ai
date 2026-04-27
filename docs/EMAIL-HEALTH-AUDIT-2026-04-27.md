# Email Health subsystem audit — 2026-04-27

**Auditor:** Claude (paired with Vinoop)
**Scope:** `static/email-health.html`, `app.py` Postmaster + SNDS endpoints, `postmaster.py`, `postmaster_scheduler.py`, `snds.py`, `snds_scheduler.py`, related `db.py` functions, schema migrations 003 + 004, `tests/test_api.py`.
**Method:** read-only walk of the listed files, cross-reference call sites and grep for orphans, no fixes applied.
**Trigger:** today's bug cascade (INBOX-99 → 100 → 101 → 102) revealed structural gaps; this audit was commissioned to surface remaining issues so they can be filed as discrete tickets.

## TL;DR

12 verified findings. Two are worth fixing this week (HIGH). Four can wait (MEDIUM). Six are cleanup (LOW). Most worrying: **the page still renders synthetic / hardcoded data in one corner**, and **there is zero backend-endpoint test coverage** for any Postmaster or SNDS API call.

---

## HIGH severity

### H1 — `animateEmailHealthTrends` writes hardcoded synthetic data into a real chart

- **File:** `static/email-health.html:1386–1419`
- **Issue:** function bodies hardcode 30 days of fake spam rates (`[0.018,0.015,0.020,…]`) and complaint rates. The `eh-spam-trend` target was deleted in INBOX-82 Phase 2 (Overview gone), so that branch is now no-op dead code. But `eh-ms-trend` *still exists* in the SNDS section. On first paint, before SNDS metrics finish loading, the bars render with the **fake hardcoded data**. When `renderMsTrend()` (line 2216) finishes loading real data, it overwrites — so the fake data flashes briefly.
- **Why this matters:** same family as INBOX-93 / INBOX-95 — we shipped honest-data work; this is a hidden contradiction. A user who lands on the Microsoft tab quickly enough sees fabricated numbers.
- **Fix:** delete `animateEmailHealthTrends()` entirely + its DOMContentLoaded callers (lines 1432–1441). `renderMsTrend()` is the real path.

### H2 — Zero test coverage for any Postmaster or SNDS API endpoint

- **Files:** `tests/test_api.py` (12 email-health tests, all HTML structure assertions)
- **Issue:** the 7 Postmaster endpoints (`/authorize`, `/callback`, `/status`, `/disconnect`, `/metrics/{domain}`, `/compliance/{domain}`, `/sync`) and the 5 SNDS endpoints (`/connect`, `/status`, `/disconnect`, `/sync`, `/metrics`) have **no behavioural tests**. No auth path tests, no plan-gating tests, no error-path tests. Every backend bug we shipped today (last_sync_at null, status flicker, etc.) would have been caught by a 5-minute integration test.
- **Fix:** add a `TestPostmasterApi` class in `tests/test_api.py` with at least: 401 without token, 403 for free-plan user on `/metrics`, 200 happy path, schema-shape assertion on `/status` response. Mirror for `TestSndsApi`.

---

## MEDIUM severity

### M1 — Manual sync endpoint doesn't write to `postmaster_sync_log`

- **File:** `app.py:1726–1753` (`api_postmaster_sync`)
- **Issue:** the daily 6am scheduler calls `log_postmaster_sync()` (postmaster_scheduler.py:64, 89). The manual sync endpoint does not. So today's `last_sync_at` lookup in `/api/postmaster/status` (which prefers `postmaster_sync_log.sync_completed_at`) silently misses every manual sync; it falls back to `created_at` on metrics, which only updates when a NEW (user, domain, date) tuple is inserted.
- **Impact:** "Last synced X ago" can lag by up to 24 hours after a manual sync. Cosmetic but undermines the recently shipped INBOX-102 UX.
- **Fix:** wrap `fetch_metrics_for_user` in `api_postmaster_sync` with `log_postmaster_sync(user_id, status, domains_synced, sync_started_at)` calls — the same pattern the scheduler uses.

### M2 — Schema/code mismatch: `postmaster_metrics` has no `updated_at`

- **File:** `migrations/003_postmaster_tables.sql:23–39`
- **Issue:** the table has only `created_at`. There is no audit trail of when a row was last upserted. Today's INBOX-102 helper had to query `postmaster_sync_log` (with a `created_at` fallback) instead of the more natural `MAX(updated_at)`.
- **Impact:** structural — limits future analytics that need "freshness of this row".
- **Fix:** ship migration 010 adding `updated_at timestamptz DEFAULT now()` + a trigger (or rely on Supabase row-level metadata).

### M3 — Concurrent manual sync + scheduled sync can race

- **Files:** `postmaster_scheduler.py:48–96`, `app.py:1751`
- **Issue:** if Vinoop clicks "Sync now" at 06:00:30 UTC while the daily scheduler is mid-run for the same user, both processes call `fetch_metrics_for_user` and both upsert the same `(user_id, domain, date)` rows. PostgreSQL's `ON CONFLICT` makes this safe at the row level, but Google's API rate limit is per-token, so we burn quota and may briefly 429. No mutex.
- **Fix:** add a `sync_in_progress` flag on `postmaster_connections` (or a Supabase advisory lock), reject manual sync if already running. Or accept the race because it's rare and harmless.

### M4 — `/api/postmaster/sync` ignores the user's selected period

- **File:** `app.py:1752`, `static/email-health.html:gpmManualSync`
- **Issue:** the manual sync hardcodes `days=14`. UI lets users pick 7d / 30d / 90d. A user on the 90d view who clicks "Sync now" expects fresh 90 days, but only the most recent 14 days are pulled. Older dates in the chart don't refresh.
- **Fix:** thread the active period through gpmManualSync → POST body → `fetch_metrics_for_user(days=N)`. Cap at 90 server-side.

---

## LOW severity (cleanup)

### L1 — Dead code: `db.get_postmaster_domains_for_user`

- **File:** `db.py:928–944`
- **Issue:** function defined but **never imported or called** anywhere in the repo. ~17 lines of orphan code.
- **Fix:** delete, or wire into the domain dropdown so users see Postmaster-verified domains they haven't yet added to InboxScore monitoring (would also address the audit's G8).

### L2 — Dead branch in `animateEmailHealthTrends`

- **File:** `static/email-health.html:1387–1401`
- **Issue:** targets `eh-spam-trend` div which was removed in INBOX-82 Phase 2. The `if (spamTrend && …)` short-circuits silently. Will be deleted as part of fixing H1.
- **Fix:** included in H1 fix.

### L3 — Two near-duplicate sync functions: `gpmManualSync` vs `gpmSyncNow`

- **File:** `static/email-health.html:1965` (gpmManualSync) + `:1955` (gpmSyncNow)
- **Issue:** `gpmSyncNow(btn)` is only used by the nodata-state "Sync Now" button. `gpmManualSync()` is used by the data-state header button. They do almost the same thing with subtly different post-success handling. Drift risk.
- **Fix:** unify into one function; nodata state can call it with a small wrapper for the button arg.

### L4 — SNDS section keeps its own race-prone load path

- **File:** `static/email-health.html:840` (loadSndsStatus called separately from ehInit)
- **Issue:** INBOX-101 fixed the GPM section by routing through `ehInit` (single sequential orchestrator). SNDS still has its own independent `loadSndsStatus` from a separate DOMContentLoaded handler. If the SNDS API hangs, the Microsoft tab will show the same flicker class of bug we fixed for GPM.
- **Fix:** move SNDS into the same `ehInit` flow, with the same `fetchWithTimeout` wrapper.

### L5 — `/email-health` route has no Cache-Control header

- **Verified:** `curl -sI https://inboxscore.ai/email-health | grep -iE cache` returned nothing (`cf-cache-status: DYNAMIC` only)
- **Issue:** today's stuck-loading saga (a stale browser cache serving the old HTML with the const-tbody SyntaxError) would have been less likely with explicit `Cache-Control: no-cache, must-revalidate` on the HTML. INBOX-37 added Cache-Control to some static HTML routes; verify /email-health is covered.
- **Fix:** add `headers={"Cache-Control": "no-cache, must-revalidate"}` to the `/email-health` `FileResponse` in app.py.

### L6 — Inconsistent terminology: "Sync" vs "Refresh" vs "Update"

- **Files:** `static/email-health.html` (multiple)
- **Issue:** the page uses "Sync now", "Refreshing…", "Last updated", "Last synced", "Pulling latest from Google" interchangeably. From a user's perspective it's not clear which means "fetch from Google again" vs "re-render the page".
- **Fix:** standardise vocabulary. Suggest: **Sync** = fetch from Google. **Refresh** = re-render with cached data. **Updated** = the freshness of Google's data itself.

---

## Test coverage gaps (full picture)

| Area | Coverage | Gap |
|---|---|---|
| /email-health HTML structure | 12 tests | OK |
| /api/postmaster/status | 0 tests | All paths untested (free, disconnected, connected) |
| /api/postmaster/metrics/{domain} | 0 tests | Plan-gate, days clamp, null connection paths untested |
| /api/postmaster/compliance/{domain} | 0 tests | Untested |
| /api/postmaster/sync | 0 tests | Untested |
| /api/postmaster/authorize | 0 tests | OAuth init untested |
| /api/postmaster/callback | 0 tests | Token-save untested |
| /api/postmaster/disconnect | 0 tests | Untested |
| /api/snds/* (all 5) | 0 tests | All untested |
| `ensure_valid_token` (postmaster.py) | 0 tests | INBOX-29 fixed two bugs here, no regression test |
| `parse_v2_domain_stats` (postmaster.py) | 0 tests | Pure function, easy to test |
| `parse_snds_csv` (snds.py) | 0 tests | Edge cases untested |

The HTML structure tests are valuable but they don't catch any of the bugs we shipped today. **Behavioural tests on the API endpoints are the highest ROI test work available.**

---

## What this audit did NOT cover

- Dashboard page (separate audit if needed)
- Score Trend / Domain pages
- The marketing site (`index.html`)
- Background workers other than postmaster_scheduler / snds_scheduler
- Schema migrations beyond 003 + 004
- Performance / load testing

---

## Recommended next ticket grouping

| Ticket | Bundle | Effort |
|---|---|---|
| **INBOX-104** | H1 (delete fake-data fn) + L2 (dead branch) | 30 min |
| **INBOX-105** | H2 — backend tests for Postmaster + SNDS endpoints | 2-3 hrs |
| **INBOX-106** | M1 + M4 — manual sync logs + period-aware sync | 45 min |
| **INBOX-107** | L4 — SNDS into ehInit flow | 60 min |
| **INBOX-108** | L1 + L3 + L5 + L6 — cleanup/polish | 45 min |
| **INBOX-109** | M2 — schema migration 010 (postmaster_metrics.updated_at) | 30 min |
| **INBOX-110** | M3 — concurrent sync race | 45 min (or close as wontfix) |

Total ≈ 7-8 hours of follow-up work to put this subsystem on solid ground.

---

## Appendix: how to update this audit

This is a point-in-time snapshot. Re-run the audit:
- Whenever a new endpoint is added under `/api/postmaster` or `/api/snds`
- Before any major refactor of `email-health.html`
- Quarterly (cheap)

Drop the new audit at `docs/EMAIL-HEALTH-AUDIT-YYYY-MM-DD.md`. Don't update this file — keep historical audits intact.
