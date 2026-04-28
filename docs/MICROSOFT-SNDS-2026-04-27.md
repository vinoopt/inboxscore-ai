# Microsoft SNDS — Subsystem Doc

**Last updated:** 2026-04-27
**Owner:** Vinoop
**Status:** Live (since 2026-03-09 — Mailercloud connected with 48 IPs)

This document captures how Microsoft SNDS works inside InboxScore today, why we made the architectural choices we did (especially around IP-to-domain mapping), and what future paths exist when we revisit.

---

## 1. What SNDS is

**Smart Network Data Services** is Microsoft's free reputation feed for sending IPs. It returns a daily CSV of: IP address, sending volume, complaint rate, spam-trap hits, filter result (GREEN/YELLOW/RED), and HELO/MAIL FROM samples.

Critical fact: **SNDS is IP-level, not domain-level.** It's accessible only by whoever controls the IPs — almost always an ESP (Mailercloud, Mailchimp, SendGrid, Brevo). Direct senders who hand off to an ESP don't have an SNDS account of their own.

Microsoft's SNDS endpoint:

```
https://sendersupport.olc.protection.outlook.com/snds/data.aspx?key=<KEY>
```

The `<KEY>` is a per-account credential the user copies from <https://postmaster.live.com/snds>.

---

## 2. The three customer profiles

InboxScore has to support three different shapes of customer, each with a different mental model of "Microsoft SNDS data":

| Profile | Has SNDS account? | What they want from InboxScore |
|---|---|---|
| **Direct sender on dedicated infra** (e.g. a SaaS company sending its own transactional + marketing mail from owned IPs) | Yes — they own the IPs | All metrics for all their IPs in one view |
| **ESP** (Mailercloud staff) | Yes — owns the entire fleet | All 48 IPs visible, plus per-client breakdowns to investigate complaints / triage incidents |
| **End-sender on an ESP** (Red Bus, Shoppers Stop on Mailercloud) | No — the ESP owns the IPs | Per-domain view of "is my mail flowing through healthy IPs?" — but they can't connect SNDS themselves |

The end-sender case is the hard one — they're the customer most interested in IP reputation but have no native way to access it. The architectural answer in InboxScore today: the ESP connects SNDS at the org level, and per-client mapping is done by the ESP admin (manual mapping in the Domain config page).

---

## 3. Architecture in InboxScore

### Frontend
- **Route:** `GET /microsoft` (added INBOX-110, flat-route nav)
- **File:** `static/email-health.html` — the SNDS section (lines ~642–790 markup, ~2492–2870 JS)
- **States:** `free` (paywall) / `disconnected` (Connect CTA) / `data` (IP grid + trend + samples)

### Backend
- `snds.py` — fetch + parse the Microsoft CSV, classify each IP green/yellow/red
- `snds_scheduler.py` — daily cron at 07:00 UTC pulling all connected users (APScheduler in-process — note flag: same Render Free dyno-sleep risk as Postmaster, see INBOX-113)
- `db.py:1036–1175` — connection + metrics CRUD

### API
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/snds/connect` | Validate key, save, trigger initial sync |
| POST | `/api/snds/disconnect` | Cascade delete metrics + connection |
| POST | `/api/snds/sync` | Manual on-demand sync |
| GET | `/api/snds/status` | Connection state + last sync timestamp |
| GET | `/api/snds/metrics?days=N` | Per-IP daily metrics |

### Database
| Table | Key | Notes |
|---|---|---|
| `snds_connections` | `user_id` (PK) | Stores `snds_key` (plaintext today — security backlog), `last_sync_at`, `ip_count` |
| `snds_metrics` | `(user_id, ip_address, metric_date)` | Daily IP rows. `filter_results` + `sample_helos` are JSONB |

### Status thresholds (snds.py)
- Filter result GREEN/YELLOW/RED is the primary signal
- Override to red if complaint rate ≥ 0.5%, or trap hits > 5
- Complaint colours: <0.1% green, <0.5% yellow, ≥0.5% red

---

## 4. The IP-to-domain mapping problem (canonical decision)

**The hardest architectural question on this subsystem is:** when an ESP connects ONE SNDS key covering MANY IPs, and the ESP-admin user picks "Red Bus" from a domain dropdown, which subset of IPs do we show?

### What we tested

On 2026-04-27 we ran a live experiment (`scripts/spf_snds_audit.py` — keep this script, it's reusable):

**Step 1 — pull all 48 IPs from Mailercloud's connected SNDS feed:**
- 30 IPs in `103.147.104.x`
- 14 IPs in `103.147.105.x`
- 3 IPs in `162.19.145.x`

**Step 2 — recursively resolve `mc.mailercloud.com`'s SPF chain:**

```
mc.mailercloud.com
  +ip4:103.147.104.200, +ip4:51.77.93.100/110/111
  +include:_spf.google.com
  +include:mlrcloud.com   ← the comprehensive ESP fleet record
  ~all
└─ mlrcloud.com
   ip4:103.147.104.0/23     (covers .104.x AND .105.x)
   ip4:162.19.145.168/29
   …40 CIDRs total -all
```

**Step 3 — cross-reference:** **48/48 SNDS IPs matched (100%)** ✅

### What this proved AND what it didn't

| Question | Answer |
|---|---|
| Are the 48 IPs Mailercloud's? | ✅ Yes — confirmed by SPF |
| Does mailercloud.com's APEX domain have an SPF? | ❌ No — the SPF lives on subdomains (`mc.mailercloud.com`, `mta.mailercloud.com`) and the cousin TLD `mlrcloud.com` |
| Which of the 48 IPs serves Red Bus today? | ❌ SPF can't tell us. Red Bus's SPF says `include:mlrcloud.com` which authorises **all 48** the same way — it doesn't expose Mailercloud's internal pool routing |
| Can SPF auto-detect work for shared-pool ESP customers? | ❌ No — SPF authorises a pool, not a per-client subset |
| Can SPF auto-detect work for direct senders on dedicated IPs? | ✅ Yes — their SPF would list specific IPs |

### Why we picked manual mapping as canonical

**Decision (2026-04-27):** continue with **manual IP-to-domain mapping** in the Domain config page as the source of truth.

Reasons:
1. **It always works.** Every customer, every ESP, every edge case — the ESP admin knows exactly which IPs serve which client and types it in once.
2. **No automation we tested gives per-client accuracy.** SPF gives ESP-level confirmation, not client-level allocation. The data Microsoft returns in SNDS samples (HELO/MAIL FROM) is sparse and often empty/garbled (one row showed `helo: "6"`).
3. **Manual mapping is a one-time setup cost.** Once the IPs are tagged to a domain, every future SNDS sync filters automatically.

We're parking automation until one of the future paths below becomes worth building.

---

## 5. Future paths (when we revisit)

Three paths exist for reducing manual-mapping toil. None blocks current product progress.

### Path A — Mailercloud admin bridge (narrow but high accuracy)

Mailercloud's own admin DB knows IP↔client allocation exactly (the `mailercloud-admin` skill confirms client-to-pool assignment exists in the admin API). For Mailercloud customers using InboxScore specifically, expose:

```
GET /api/mailercloud-admin/client-ips?client_id=...
```

InboxScore calls this whenever a Mailercloud-customer user opens the SNDS page. Pre-populates the mapping. User can override.

**Pros:** Perfect accuracy, fast, dogfood-friendly.
**Cons:** Only solves the Mailercloud case. Doesn't generalise to Mailchimp/SendGrid customers.

### Path B — SPF auto-detect (limited but universal)

The `scripts/spf_snds_audit.py` test run proves the resolver works. Build it as a "Detect IPs via SPF" button on the Domain config page:

- Resolve the domain's SPF chain (use 8.8.8.8/1.1.1.1 — system resolver had timeouts during the test)
- Match to IPs in the connected SNDS feed
- Pre-populate the mapping with a "best-effort" caveat

**When useful:** direct senders with dedicated IPs whose SPF lists those IPs explicitly.
**When useless:** any customer whose SPF is `include:<esp-pool>.com` — that authorises the full pool, doesn't narrow.

### Path C — DMARC aggregate report (RUA) ingestion

Receivers (Gmail, Yahoo, Microsoft) send daily XML reports that include `(source_IP, sender_domain, message_count, dkim_d, spf_pass)` tuples. This is the **only universal signal** that survives shared-pool / VERP / opaque envelope-from.

Build a mailbox endpoint (`dmarc@inboxscore.ai`), parse incoming reports, auto-attribute IPs to domains based on actual delivered traffic.

**Pros:** Works for any ESP, any customer, captures real attribution.
**Cons:** Requires customers to add `rua=mailto:dmarc@inboxscore.ai` to their DMARC record. Build effort: parser + storage + reconciliation. Lag: 24h between mail send and report receipt.

### Recommended order

1. **Manual mapping (today)** — keep
2. **Path C — DMARC RUA** — universal, biggest unlock, build when we have ≥ 5 paying customers asking for less manual work
3. **Path A — Mailercloud admin bridge** — if Mailercloud customers become a meaningful segment of InboxScore users
4. **Path B — SPF auto-detect** — only worth building once we have many direct-sender (non-ESP) customers

---

## 6. Known gaps + tech debt

| Gap | Severity | Where |
|---|---|---|
| SNDS key stored plaintext in Supabase | Medium | `snds_connections.snds_key` — encrypt at rest before paid GA |
| No SWR cache layer | Medium | `loadSndsStatus`, `loadSndsMetrics` — same Postmaster cold-start issue |
| Hand-rolled SVG trend chart | Medium | `renderMsTrend()` — same hover/alignment issues as Postmaster (which we migrated to Chart.js on 2026-04-27); follow same pattern |
| No tests for SNDS | Medium | No `tests/test_snds*.py` exists |
| Empty-state colour audit pending | Low | Needs same sweep as Postmaster — 0% complaint shouldn't render red |
| Stale-sync warning | Low | Show banner if `last_sync_at > 36h` |
| Render Free dyno sleep | High | APScheduler in-process — risk of missed daily sync. Tracked as **INBOX-113** |
| Plaintext PTR check failing | Investigative | All 48 Mailercloud IPs have NoAnswer on PTR lookups — that's a deliverability red flag worth flagging back to the Mailercloud infra team |
| `tracked_ips` column unused | Low | Migration 004 added it; API doesn't filter by it |

---

## 7. Code map

```
static/email-health.html
  642–790    SNDS section markup (ms-state-* divs, IP grid, trend, samples)
  2492       loadSndsStatus()    — GET /api/snds/status, set state
  2522       loadSndsMetrics()   — GET /api/snds/metrics, render
  2557       renderSndsData()    — group by IP, populate grid
  2632       renderMsTrend()     — hand-rolled SVG bar chart (migrate to Chart.js)
  2685       renderMsSamples()   — last 5 IP/HELO/date rows
  2721/2734  openMsSndsModal / closeMsSndsModal
  2763       msSndsConnect()     — 3-step connect flow
  2834       msSyncNow()         — POST /api/snds/sync

snds.py
  fetch_snds_data(key)            — GET Microsoft CSV
  parse_snds_csv(text)            — 12-column CSV → list of dicts
  determine_ip_status(...)        — filter_result + complaint + traps → green/yellow/red
  validate_snds_key(key)          — pre-flight check on connect

snds_scheduler.py
  sync_all_snds_users()           — daily 07:00 UTC, processes all connections

db.py:1036–1175
  save_snds_connection            — upsert
  get_snds_connection             — fetch
  delete_snds_connection          — cascade delete metrics
  get_all_snds_connections        — used by scheduler
  update_snds_sync_status         — touch last_sync_at + ip_count
  upsert_snds_metrics             — daily IP rows
  get_snds_metrics                — fetch user's recent metrics
  get_snds_metrics_for_ip         — drill-down

migrations/
  002_missing_tables.sql          — snds_connections + snds_metrics
  004_snds_tracked_ips.sql        — adds tracked_ips JSONB (unused in API today)

app.py
  /api/snds/connect, /disconnect, /sync, /status, /metrics  (lines 1764–2000)
  GET /microsoft → email-health.html (line 2113)

scripts/spf_snds_audit.py
  Reusable SPF→SNDS cross-reference validator (run for any domain to test the auto-detect hypothesis).
```

---

## 8. Decision log

| Date | Decision | Reason |
|---|---|---|
| 2026-03-09 | Connected Mailercloud's SNDS feed (48 IPs) | First production SNDS account |
| 2026-04-27 | Tested SPF auto-detect — 100% match for ESP-level identification, but cannot resolve per-client subset | SPF authorises pools, not per-client allocations |
| 2026-04-27 | Stay on manual IP↔domain mapping as canonical | Always-correct, low-tech, unblocks current customers |
| 2026-04-27 | Park automation paths (admin bridge, DMARC RUA, SPF auto-detect) for revisit when customer mix justifies the build | Manual is fine for current customer count |
