# InboxScore — Lessons Specific to Deliverability Products

Wisdom that applies to InboxScore and other email-deliverability products. For product-agnostic lessons, see `Master-Playbook/08-Product-Lessons.md`.

---

## Domain & IP architecture

### D1. SNDS is IP-level, ESPs own the keys

**The truth:** Microsoft SNDS is accessible only to whoever controls the IPs — almost always an ESP (Mailercloud, Mailchimp, SendGrid). End-senders (Red Bus, Shoppers Stop) using an ESP can't connect SNDS themselves; their ESP can.

**Implication:** Two completely different customer profiles need different UIs. End-senders want "my IPs only" filtered to their domain. ESPs want fleet-wide visibility across all 48+ shared IPs. Design for both from day one or you'll re-design the page 3 months in.

**See:** `docs/MICROSOFT-SNDS-2026-04-27.md` for the full architectural decision.

---

### D2. Per-client IP attribution can't come from public DNS for shared pools

**What we tested:** 2026-04-27. Resolved Mailercloud's SPF chain (`mc.mailercloud.com → mlrcloud.com`). 100% match for ESP-level identification (all 48 IPs authorised). But: AdBuzz's SPF (`include:mlrcloud.com`) authorises the same 48 IPs the same way. SPF alone cannot tell us which IP serves AdBuzz today vs. Red Bus today.

**The lesson:** For shared-pool ESP customers, public DNS records (SPF, DKIM `d=`, PTR) cannot narrow which IP serves which sub-client. Three real signals can:
1. ESP's own admin DB (e.g., Mailercloud knows their pool→client mapping)
2. DMARC RUA aggregate reports (receivers tell us per-IP which domains they signed for)
3. Manual mapping (always works, requires human input)

**How to apply:** Default to manual mapping as canonical. Auto-detection only for **direct senders with dedicated IPs** (their SPF lists IPs explicitly). DMARC RUA ingestion is the universal long-term answer if you build the parser.

**See:** INBOX-119 (DMARC RUA), INBOX-120 (Mailercloud admin bridge), INBOX-121 (SPF auto-detect for direct senders).

---

### D3. SPF records often live on subdomains, not the apex

**What we found:** `mailercloud.com` itself has NO SPF record. The SPF lives on `mc.mailercloud.com`, `mta.mailercloud.com`, plus the cousin TLD `mlrcloud.com` for the shared pool.

**The lesson:** When auto-resolving customer SPF, don't just probe the apex. Common subdomains: `mc.<domain>`, `mta.<domain>`, `bounce(s).<domain>`, `email.<domain>`, `e.<domain>`, `_spf.<domain>`. Plus the customer might use a separate bounce-domain (different TLD).

**How to apply:** SPF resolver tool needs a list of common subdomain patterns to probe. Surface results explicitly: "Found SPF on: mc.example.com, with IPs [...]." Let the user confirm which sending identity they want to attribute.

---

### D4. PTR records missing → deliverability red flag

**What we found:** All 48 Mailercloud SNDS IPs returned `NoAnswer` on reverse-DNS lookup.

**The lesson:** PTR records are a deliverability baseline. Microsoft's Outlook Sender Guidelines and Gmail's recommendations both expect IPs to have PTR. Mail from PTR-less IPs is more likely to be filtered or rate-limited. Filter result tier YELLOW vs. GREEN can be partly explained by this.

**How to apply:** Build a PTR check into IP Reputation / Sending IPs page. Flag any IP with no PTR as a deliverability gap with a "Fix this with your ESP" link.

**See:** INBOX-122 (advisory ticket sent back to Mailercloud's infra team).

---

## Provider-specific gotchas

### P1. Google Postmaster v2 API exposes only 8 metrics

**The reality:** v2 (March 2025) retired domain reputation, IP reputation tier, FBL by identifier, and per-error-type delivery breakdowns. What's left:
- User-reported spam rate
- Authentication (DKIM, SPF alignment, DMARC)
- TLS encryption rate (inbound + outbound)
- Delivery error rate (aggregated, no per-type)

**Implication:** Don't surface UI for metrics that don't exist in v2. The Dashboard's "Domain reputation" stat became a permanent `—` after v2 launched. Replaced with Delivery error rate.

**How to apply:** When integrating any provider, inventory their actual API output before designing the UI. If v1→v2 retired 50% of metrics, your UI's threshold colour rules and tab structure need to match what's actually available, not what was historically there.

**See:** `docs/EMAIL-HEALTH-AUDIT-2026-04-27.md` H1 finding.

---

### P2. SNDS CSV columns are positional and historical fields move

**The trap:** Microsoft's SNDS CSV format has 13 columns. Position 11 is `TrapHitCount`; position 12 is `SampleHELO`. Our parser was off-by-one — putting trap count `6` into `sample_helos.helo` field. Real bug discovered while doing the SPF cross-reference test.

**The lesson:** When parsing positional CSV from a third-party API, write a unit test against a real captured payload. Don't assume column positions.

**How to apply:** `tests/test_snds_parser.py` should cover the full 13-column row including edge cases (empty trap period, IPv6 addresses if Microsoft ever surfaces them).

**See:** INBOX-115 (parser bugs ticket).

---

### P2.1. SNDS returns multiple rows per IP per day when activity spans day boundaries

**The trap:** 2026-04-28. While running the 30-day backfill, the Postgres upsert failed with `ON CONFLICT DO UPDATE command cannot affect row a second time`. Cause: the `&date=MMDDYY` parameter on the SNDS API doesn't return *exactly one row per IP*. If sending activity straddled midnight (e.g., active period 2026-04-26 5:30 AM → 2026-04-27 4:30 AM), an IP gets one row with activity_start=4/26 AND another with activity_start=4/27 in the same daily fetch. After parsing both, you get two rows with the same `(ip, metric_date)` — Postgres rejects the batch upsert.

**The lesson:** When backfilling time-windowed data from external APIs, dedup *before* the database hit. Use `(ip, date)` as the dedup key, prefer the row with the higher message_count (the longer activity window).

**How to apply:** Backfill paths must include a `dedup_by_key()` step. Pattern: `by_key = {}; for r in rows: k = (r["ip"], r["date"]); if k not in by_key or r["count"] > by_key[k]["count"]: by_key[k] = r;`

**See:** INBOX-127 backfill code (snds.py + the upsert script).

---

### P3. ESP envelope-from rewriting breaks attribution by MAIL FROM

**The trap:** ESPs use VERP (Variable Envelope Return Path). When Red Bus sends through Mailercloud, the SMTP envelope `MAIL FROM` becomes something like `bounce-12345@bounces.mailercloud.com`, NOT `noreply@redbus.com`. SNDS sample MAIL FROM data tells us nothing about the actual sender.

**The lesson:** Don't rely on envelope-from for per-client attribution. Receivers see VERP'd ESP bounce addresses, not the customer's domain.

**How to apply:** Customer attribution requires DKIM `d=` (which IS the customer's domain) or out-of-band data (admin DB, DMARC RUA). Plan around this from day one.

---

### P4. Postmaster vs. SNDS data shapes differ enough to need different UIs

**Postmaster (Gmail):**
- Daily aggregate per-domain
- 8 metrics × 30 days
- Compliance verdicts (8 binary checks)
- **One mental model**: "is my domain reputation good with Gmail?"

**SNDS (Microsoft):**
- Daily aggregate per-IP
- ~6 fields × 30 days × N IPs
- Filter result tier per IP per day
- **Two mental models**: per-domain (end-sender) and fleet-view (ESP)

**The lesson:** Don't force one tab structure across all providers. Postmaster's 6 tabs (Compliance / Spam / Unsubscribe / Auth / Encryption / Delivery Errors) don't map cleanly to SNDS. SNDS's 5 tabs (IP Health / Complaints / Trap Hits / Filter Result / Volume) don't map cleanly to Yahoo CFL. Each provider's UI should match its data shape.

---

## ESP / Direct-sender mental models

### E1. End-sender users (Red Bus) cannot connect SNDS themselves

**Implication:** A direct customer using Mailercloud has no Microsoft data path. Either the ESP shares aggregated stats, or the customer doesn't see SNDS data at all. Empty state must say so plainly: "Microsoft SNDS access is owned by your ESP. Ask Mailercloud to share their dashboard with you, or connect a different ESP that has SNDS sharing."

**How to apply:** Don't show a "Connect SNDS" button to a customer profile that can't actually connect. The Pro upgrade gate is the wrong message — the limitation is structural, not pricing.

---

### E2. ESP customers want fleet view; end-senders want domain view

**The architectural decision:** 2026-04-28. Filed as INBOX-114 (5-tab redesign for end-senders) + parking-lot for fleet view (table-first layout, separate ticket when GTM justifies).

**The lesson:** Don't try to satisfy both with one layout. End-sender = vertical, scoped, story-driven (5 tabs). ESP = horizontal, dense, sortable (table with drill-down). These are different page-shapes, not display modes of one page.

---

### E3. The customer's SPF probably routes through their ESP

**The trap:** When verifying a customer's setup, you can't just check `customer.com` SPF. They probably have `v=spf1 include:_spf.<esp>.com -all`. The actual sending IPs are inside the ESP's record, not the customer's.

**How to apply:** SPF expansion must follow `include:` chains recursively. Document the recursion limit (10 includes max per RFC 7208). Surface the *expanded* IP list, not the raw customer SPF.

---

## Operational gotchas

### O1. Daily cron syncs need external triggers on free-tier hosts

**The trap:** Render Free / Vercel Hobby / Railway's free tier all sleep on inactivity. APScheduler / cron in-process dies during sleep. Missed cron windows are lost, data goes stale, customers see 2-day-old numbers.

**How to apply:** Either (a) pay for an always-on dyno, (b) use a dedicated cron service (Render Cron, GitHub Actions schedule, cron-job.org) that wakes the host by hitting an internal `/api/cron/*` endpoint, (c) move scheduling out of the web process entirely.

**See:** INBOX-113 (filed as P1 for InboxScore).

---

### O2. Empty data + flashy UI = looks broken

**The trap:** Free / new / unconnected users see empty charts, zero stats, and "—" placeholders. Without explicit empty-state copy, the UI looks broken even when it's correctly empty.

**How to apply:** Every metric tile, chart, and table needs an explicit empty-state: muted-coloured value + one-line "why" + (where applicable) action link to fix. Test the page with zero data as a first-class scenario, not an afterthought.

---

## How to use this doc

Read on:
- Onboarding to InboxScore
- Adding a new provider integration (Yahoo CFL, AOL, etc.)
- Designing a new dashboard for a deliverability product
- When you're about to assume per-client mapping is solvable from public DNS

Add to it:
- When a deliverability-specific incident teaches you something
- When an ESP / DNS / SMTP edge case bites you
- When you make an architectural decision worth memorialising
