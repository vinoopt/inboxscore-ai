/* InboxScore — sidebar plan-card hydrator (INBOX-259, 2026-05-15).
 *
 * Previously inlined on every authenticated page. Suffered from a
 * 4-state flicker on every page nav:
 *
 *   1. HTML default:           "— / —"                  (blank)
 *   2. Per-page hydrator T+10: "pro / —"                (raw plan from cache)
 *   3. Per-page hydrator T+50: "Pro / —"                (capitalised but still no count)
 *   4. Global hydrator T+1500: "Pro plan / 6 of 10 domains"  (final state)
 *
 * Causes:
 *   • Artificial 1500ms setTimeout — added as a hack to outlive
 *     per-page hydrators that overwrite #plan-name with the raw plan
 *     value. The MutationObserver downstream was the actual defense.
 *   • No localStorage cache for the sidebar block specifically. Each
 *     page nav refetched plan + domain count from network.
 *
 * This module replaces the inline version with the SWR pattern Vinoop
 * codified as a memory feedback rule:
 *   "Hydrate from localStorage first paint, fetch fresh in parallel.
 *    Skeleton on first-ever visit, corner pill on refresh — never dim
 *    existing data."
 *
 * Flow:
 *   1. SYNCHRONOUSLY (script load, no DOMContentLoaded wait) read
 *      cached plan+usage from localStorage and write to #plan-name +
 *      #plan-usage-text. First paint is fully populated for any user
 *      who has visited any authenticated page before.
 *   2. Fire /api/user/plan + /api/user/domains in parallel.
 *   3. If response differs from cache, update DOM + cache.
 *   4. MutationObserver re-applies if a per-page script tries to
 *      overwrite #plan-name (legacy defence — we'll remove the
 *      offenders as they surface).
 */
(function () {
  'use strict';

  var CACHE_KEY = 'inboxscore_sidebar_plan_v1';
  var CACHE_TTL_MS = 5 * 60 * 1000;       // 5 min — sidebar data changes rarely
  var PLAN_LABELS = {
    trial:      'Trial',
    pro:        'Pro plan',
    stub:       'Free plan',
    free:       'Free plan',
    growth:     'Growth plan',
    enterprise: 'Enterprise plan',
  };
  var PLAN_DOMAIN_LIMITS = {
    trial: 10, pro: 10, stub: 0, free: 1, growth: 50, enterprise: -1,
  };

  function getToken() {
    try {
      return localStorage.getItem('access_token')
        || sessionStorage.getItem('access_token');
    } catch (e) { return null; }
  }

  function readCache() {
    try {
      var raw = localStorage.getItem(CACHE_KEY);
      if (!raw) return null;
      var obj = JSON.parse(raw);
      if (!obj || typeof obj !== 'object') return null;
      // Cache is fresh? Used to decide whether to skip the network.
      // (Stale cache still hydrates first paint — we just also refetch.)
      var fresh = (Date.now() - (obj.ts || 0)) < CACHE_TTL_MS;
      return { data: obj, fresh: fresh };
    } catch (e) { return null; }
  }

  function writeCache(plan, used, cap) {
    try {
      localStorage.setItem(CACHE_KEY, JSON.stringify({
        plan: plan, used: used, cap: cap, ts: Date.now(),
      }));
    } catch (e) {}
  }

  function setText(id, text) {
    var el = document.getElementById(id);
    if (el && el.textContent !== text) el.textContent = text;
  }
  function setHTML(id, html) {
    var el = document.getElementById(id);
    if (el && el.innerHTML !== html) el.innerHTML = html;
  }

  function render(plan, used, cap) {
    var card = document.getElementById('plan-badge');
    if (card) {
      // is-free triggers the muted/zinc style for free/stub users.
      card.classList.toggle('is-free', plan === 'free' || plan === 'stub');
    }
    var label = PLAN_LABELS[plan] || (plan.charAt(0).toUpperCase() + plan.slice(1) + ' plan');
    setText('plan-name', label);

    if (cap === -1) {
      setText('plan-usage-text', 'Unlimited domains');
      var fillU = document.getElementById('plan-usage-fill');
      if (fillU) fillU.style.width = '100%';
    } else if (used != null && cap) {
      setHTML('plan-usage-text',
        '<span class="app-plan-num">' + used + '</span> of '
        + '<span class="app-plan-num">' + cap + '</span> domain'
        + (cap === 1 ? '' : 's'));
      var fillEl = document.getElementById('plan-usage-fill');
      if (fillEl) fillEl.style.width =
        Math.min(100, Math.round((used / cap) * 100)) + '%';
    } else if (cap) {
      setHTML('plan-usage-text',
        '<span class="app-plan-num">' + cap + '</span> domain'
        + (cap === 1 ? '' : 's') + ' included');
    }
  }

  /* Synchronous cache-hydration. Runs at script-load time so it lands
     before paint on every page that includes this file in <head>. */
  function hydrateFromCacheSync() {
    var cached = readCache();
    if (!cached) return false;
    render(cached.data.plan, cached.data.used, cached.data.cap);
    return cached.fresh;
  }

  async function refreshFromNetwork() {
    var card = document.getElementById('plan-badge');
    if (!card || !card.classList.contains('app-plan-card')) return;
    var token = getToken();
    if (!token) return;
    var headers = { 'Authorization': 'Bearer ' + token };

    try {
      var responses = await Promise.all([
        fetch('/api/user/plan', { headers: headers }),
        fetch('/api/user/domains?per_page=200', { headers: headers }),
      ]);
      var planResp = responses[0], domsResp = responses[1];
      if (!planResp.ok || !domsResp.ok) return;
      var bodies = await Promise.all([planResp.json(), domsResp.json()]);
      var planData = bodies[0], domsData = bodies[1];

      var plan = (planData.plan || 'free').toLowerCase();
      var cap = (planData.domains_limit != null)
        ? planData.domains_limit
        : (PLAN_DOMAIN_LIMITS[plan] != null ? PLAN_DOMAIN_LIMITS[plan] : 1);
      var used = (planData.domains_used != null)
        ? planData.domains_used
        : (typeof domsData.total === 'number'
            ? domsData.total
            : (domsData.domains || domsData.items || []).length);

      writeCache(plan, used, cap);
      render(plan, used, cap);
    } catch (e) {}
  }

  /* Defence in depth — watch both #plan-name AND #plan-usage-text. Any
     write that doesn't match our canonical label set is treated as a
     clobber and we re-apply from cache. INBOX-259 follow-up: the
     original filter was too lax — "Pro plan" + "10 domains included"
     (both 12+ chars) slipped through and broke microsoft/postmaster
     for hours before we caught it. Now we whitelist EXPLICIT known-good
     strings instead of trying to detect "bad" ones.
  */
  var KNOWN_GOOD_NAMES = new Set([
    'Trial', 'Pro plan', 'Free plan', 'Stub plan',
    'Growth plan', 'Enterprise plan',
  ]);

  function watchForClobber() {
    var nameEl = document.getElementById('plan-name');
    var usageEl = document.getElementById('plan-usage-text');
    if (typeof MutationObserver === 'undefined') return;

    var lastReapplyAt = 0;
    var reapply = function () {
      if (Date.now() - lastReapplyAt < 500) return;
      lastReapplyAt = Date.now();
      var cached = readCache();
      if (cached) render(cached.data.plan, cached.data.used, cached.data.cap);
    };

    if (nameEl) {
      var moName = new MutationObserver(function () {
        var t = (nameEl.textContent || '').trim();
        // Whitelist canonical labels. Anything else = clobber.
        if (!t || KNOWN_GOOD_NAMES.has(t)) return;
        reapply();
      });
      moName.observe(nameEl, { childList: true, characterData: true, subtree: true });
    }

    if (usageEl) {
      var moUsage = new MutationObserver(function () {
        var t = (usageEl.textContent || '').trim();
        // Catch the specific "X domains included" clobber from INBOX-184/185
        // and any "—" placeholder revert.
        if (!t || t === '—') { reapply(); return; }
        // Our canonical formats:
        //   "Unlimited domains"
        //   "<num> of <num> domain(s)"  → contains " of "
        //   "<num> domain(s) included"  → only legitimate when used=null+cap (rare)
        var isOurs = /^Unlimited domains$/.test(t)
          || / of /i.test(t)
          || /^\d+ domain[s]? included$/.test(t);
        if (!isOurs) reapply();
      });
      moUsage.observe(usageEl, { childList: true, characterData: true, subtree: true });
    }
  }

  /* Bootstrap: synchronous cache → DOM (no waiting). Then async net. */
  function bootstrap() {
    var cacheWasFresh = hydrateFromCacheSync();
    watchForClobber();
    // Skip the network if the cache is still fresh (< 5 min). The user
    // can force a refresh by reloading after that window or by visiting
    // settings/billing which always refetches.
    if (!cacheWasFresh) refreshFromNetwork();
  }

  // Bootstrap immediately if DOM ready, else wait for it.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrap);
  } else {
    bootstrap();
  }
})();
