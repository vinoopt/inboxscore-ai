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

### O3. Three-clock confusion in "Last synced X ago" labels

**The trap:** 2026-04-29. Vinoop reported "Last synced just now" never changing on `/microsoft` and `/postmaster`. v1.15.9 fixed two literal `'just now'` hardcodes — but the next page reload still showed the bug. v1.15.10 found 5 MORE sites all using `cacheAgeLabel(_gpmCacheKey)` which returns local cache age, not provider sync age.

The deeper bug: there are **three different "X ago" times** in the product, and the codebase mixed them up:

| Concept | Source | Means |
|---|---|---|
| **Provider sync age** | `connection.last_sync_at` | "When did we last call Google's API?" |
| **DB write age** | `row.created_at` | "When did our DB row get written?" |
| **Local cache age** | `cacheSet()` timestamp | "When did localStorage refresh?" |

The label `id="gpm-last-sync"` promises the first one. Code was using the third one (which is "just now" right after any fetch).

**How to apply:**

1. **A label is a contract.** "Last synced X ago" MUST source from `connection.last_sync_at`. No exceptions.
2. **Cache the real timestamp** alongside the data. When persisting metrics, also store `last_sync_at` so SWR hydration paints from the right source.
3. **Hardcoded `'just now'` is OK in exactly one place**: immediately after a successful manual-sync handler.
4. **When fixing one site, sweep ALL callers of the affected helper.** Don't grep for the symptom string — grep for `getElementById('gpm-last-sync')` / every `ehUpdateRefreshStamp(` call. Trust nothing until you've read each line.
5. **Tier-3 verification must include first-paint inspection.** Refresh the page, observe the label is correct on first frame AND stays correct after revalidation (no flicker). My v1.15.9 Tier-3 only checked the literal strings were gone — that wasn't enough.

**See:** INBOX-140 (initial fix, v1.15.9), INBOX-140-followup (deeper sweep, v1.15.10), INBOX-141 (sitewide audit ticket).

---

### O4. Symptom-fixing leaves the underlying conceptual bug

**The trap:** Same incident as O3. After I shipped v1.15.9 fixing 2 hardcoded `'just now'` literals, Vinoop reloaded the page within minutes and the bug was still there. The literals were a symptom of a deeper conceptual confusion (three freshness clocks); fixing the symptoms left the cause intact in 5 other sites.

**How to apply:**

1. **Before declaring "fixed," ask: am I patching the symptom or the cause?** If the cause is a confused mental model (three freshness clocks → one label), the symptoms WILL recur in places I haven't grepped for.
2. **Grep every caller of the affected helper before claiming Tier-3.** Not every literal string — every consumer of the contract. `ehUpdateRefreshStamp(` had 5 callers, not 2.
3. **A working contract has invariants.** Write them down: "any code path that writes element X must source data from Y." Then audit every site that writes X.
4. **The verification pyramid (Tier-1 trace → Tier-2 test → Tier-3 prod) must include "first-paint visual inspection" for any UI fix.** Not just "the broken string is gone from the rendered HTML."

---

---

## Frontend chrome migrations

### F1. After renaming markup classes, grep every page's inline `<style>` for selectors that match the new class

**The trap:** when you rename HTML classes (e.g. `pm-sidebar` → `sidebar`, or `dom-sidebar` → `sidebar`), don't only update the canonical CSS file — grep every affected page's inline `<style>` block for selectors that match the **new** class. Dead rules from a previous rename can re-activate and silently override the canonical styling, because the inline `<style>` block has higher source-order precedence than the external stylesheet at equal specificity.

**What bit us (INBOX-220):** `postmaster.html` had ~10 lines of `.sidebar-nav li a { ... border-left: 3px solid transparent; }` and `.sidebar-nav li a.active { color: var(--accent); border-left-color: var(--accent); ... }` from BEFORE INBOX-184 (when the page used `.sidebar` markup). The page had since switched to `.pm-sidebar` (rules became dead, no element matched). When INBOX-219 renamed back to `.sidebar`, the dead selectors matched the new markup and re-activated. `app-chrome.css`'s canonical grey active state couldn't win — the inline `<style>` block came later in source order. Vinoop saw a purple-active sidebar on Postmaster while Dashboard's was grey. Same exact bug repeated on Domains in INBOX-221.

**How to apply:** when you do a markup rename, the cleanup checklist is:

1. Update the canonical CSS file (`app-chrome.css`, `design-system-v2.css`, etc.).
2. For every page that ships the renamed markup, grep its inline `<style>` block for the **new** class name's selectors:
   ```bash
   grep -nE "^\.<new-class>|<new-class> li|<new-class>-foo" static/<page>.html
   ```
3. Delete any rules that target the new class name. They are EITHER:
   - Dead rules from before a previous rename — pure dead code, delete with confidence
   - Page-specific overrides someone added — verify intent before deletion, but usually delete in favour of the canonical
4. Run a paint diff (manual screenshot or `inboxscore-frontend-qa` skill) after deploy to catch any styling drift.
5. Leave a one-line comment where you deleted the rules so the next migrator doesn't add them back.

**Don't trust** "this rule used to apply to a different element so it's safe to leave alone." If the selector matches the new markup, it WILL apply. CSS doesn't know about your migration intent.

**Pair this with:** when you replace markup, also clean up the OLD CSS that targets the same selectors — otherwise specificity wars and you ship a half-fix. (Lesson originally codified in INBOX-178 retro.)

---

### F2. When you delete chrome (markup or class), audit the page for orphan duplicate IDs

**The trap (INBOX-221, Domains):** the page had two elements with `id="plan-badge"` AND two with `id="plan-name"` — leftover from when INBOX-180 introduced `<div class="app-plan-card" id="plan-badge">` but didn't delete the previous `<div class="plan-badge" id="plan-badge">📋 ... plan</div>`. Both rendered. The legacy element appeared as a tiny pill below the new card. JS hydrators that called `getElementById('plan-badge')` got the **first** match (the canonical card) and worked fine — which is exactly why the bug went undetected for weeks: it was visually broken but functionally silent.

**How to spot:** during any chrome migration, run:
```bash
grep -oE 'id="[^"]+"' static/<page>.html | sort | uniq -d
```
Any output means duplicate IDs in the same page. Triage each:
- Real duplicate (both render at runtime) → delete one
- False positive (inside a comment, inside mutually-exclusive JS branches, or inside a JS template literal) → leave it but note WHY in a comment

**Going forward:** worth adding a CI grep check that fails the build on duplicate IDs in any HTML file. ~10-line script, catches this class of bug at PR time.

---

### F3. Chrome that should be consistent across pages lives in ONE external CSS file

**Pattern that drifted (INBOX-178 → INBOX-219):** every page started life with a copy of "canonical" CSS in its inline `<style>` block. Over time each page's copy diverged independently, producing 3 different sidebar implementations (`.sidebar`, `.pm-sidebar`, `.dom-sidebar`) with 8 visually distinct results across pages. Class collisions between files don't surface until you grep across the codebase or migrate markup — and by then the inconsistency is already shipped.

**Rule:** chrome that should be consistent across pages lives in **one** external CSS file (`app-chrome.css`). Anything in a page's inline `<style>` should be **page-specific** — and use a page-prefix class (`.pm-tab`, `.bl-domain-pill`) to make scope obvious. If the inline rule needs the canonical class name (`.sidebar`, `.brand`, `.sidebar-footer`), you've made the wrong call — promote the rule to the shared file instead.

**Going forward:** for shared chrome (sidebar, plan card, page header, domain dropdown), prefer one canonical CSS file + one shared JS helper (e.g., `static/js/app-domain-select.js`) over 8 page-prefixed copies. Smaller surface area, drift is impossible.

---

## How to use this doc

Read on:
- Onboarding to InboxScore
- Adding a new provider integration (Yahoo CFL, AOL, etc.)
- Designing a new dashboard for a deliverability product
- When you're about to assume per-client mapping is solvable from public DNS
- **Before any UI migration that renames a CSS class** (sections F1-F3)

Add to it:
- When a deliverability-specific incident teaches you something
- When an ESP / DNS / SMTP edge case bites you
- When you make an architectural decision worth memorialising
- **When a chrome / migration / front-end pattern bites you** — duplicate of the auto-memory note is intentional; this file is the project's own learning log that survives if auto-memory is wiped or another collaborator joins.
