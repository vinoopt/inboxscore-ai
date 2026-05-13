/*
 * InboxScore — Trial countdown banner (INBOX-215)
 *
 * Single shared script that auto-mounts a banner on every authenticated
 * page. Renders based on /api/user/plan response shape (returned by
 * INBOX-208 refactor):
 *
 *   {
 *     plan: 'trial' | 'pro' | 'stub' | 'free' | 'growth' | 'enterprise',
 *     trial_end: ISO timestamp | null,
 *     subscription_status: 'trialing' | 'active' | ...
 *     ...
 *   }
 *
 * Display matrix (PAYMENT-PLAN.md sec 5):
 *
 *   plan='trial', days_left > 7    → silent (no banner) — early trial
 *   plan='trial', 4 <= days_left ≤ 7 → blue banner, low urgency
 *   plan='trial', 1 <= days_left ≤ 3 → orange banner, high urgency
 *   plan='trial', days_left ≤ 0    → orange "trial ended today" banner
 *   plan='stub'                    → yellow persistent banner
 *   plan='pro' or anything paid    → silent
 *   plan='free'                    → silent (legacy grandfathered; UI
 *                                    nudges them via /settings/billing)
 *
 * Banner can be dismissed for the current session (sessionStorage). It
 * comes back on next page load or next browser session, by design — we
 * don't want users to bury an urgent countdown forever.
 *
 * Mount point: inserts as the FIRST child of <body> so it pushes
 * existing page content down. Uses position:sticky + top:0 to ride
 * with the user as they scroll, but doesn't overlay (so the existing
 * topnav still works).
 */
(function () {
  'use strict';

  var DISMISS_KEY_PREFIX = 'inboxscore.trialBanner.dismissed.';
  var BANNER_ID = 'trial-banner-host';

  function getToken() {
    try {
      return localStorage.getItem('access_token') || sessionStorage.getItem('access_token');
    } catch (e) { return null; }
  }

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  function daysUntil(iso) {
    if (!iso) return null;
    var d = new Date(iso).getTime();
    if (isNaN(d)) return null;
    return Math.ceil((d - Date.now()) / (24 * 3600 * 1000));
  }

  function injectStyles() {
    if (document.getElementById('trial-banner-styles')) return;
    var css = ''
      + '.trial-banner-host{position:sticky;top:0;z-index:100;font-family:inherit;}'
      + '.trial-banner{display:flex;align-items:center;justify-content:center;gap:12px;'
      + 'padding:10px 20px;font-size:13px;line-height:1.5;flex-wrap:wrap;}'
      + '.trial-banner-low   {background:rgba(37,99,235,0.10);color:#1e3a8a;'
      + 'border-bottom:1px solid rgba(37,99,235,0.25);}'
      + '.trial-banner-high  {background:rgba(234,88,12,0.12);color:#7c2d12;'
      + 'border-bottom:1px solid rgba(234,88,12,0.30);}'
      + '.trial-banner-stub  {background:rgba(202,138,4,0.12);color:#713f12;'
      + 'border-bottom:1px solid rgba(202,138,4,0.30);}'
      + '@media (prefers-color-scheme:dark){'
      + '  .trial-banner-low   {color:#bfdbfe;}'
      + '  .trial-banner-high  {color:#fed7aa;}'
      + '  .trial-banner-stub  {color:#fde68a;}'
      + '}'
      + 'html[data-theme="dark"] .trial-banner-low   {color:#bfdbfe;}'
      + 'html[data-theme="dark"] .trial-banner-high  {color:#fed7aa;}'
      + 'html[data-theme="dark"] .trial-banner-stub  {color:#fde68a;}'
      + '.trial-banner-msg{font-weight:500;}'
      + '.trial-banner-cta{padding:5px 14px;border-radius:6px;border:1px solid currentColor;'
      + 'background:transparent;color:inherit;font-size:12px;font-weight:600;cursor:pointer;'
      + 'font-family:inherit;text-decoration:none;display:inline-flex;align-items:center;gap:4px;}'
      + '.trial-banner-cta:hover{background:rgba(0,0,0,0.05);}'
      + '.trial-banner-cta-primary{background:currentColor;color:#fff;border-color:currentColor;}'
      + '.trial-banner-cta-primary span{color:#fff;}'
      + '.trial-banner-close{background:transparent;border:none;color:inherit;opacity:0.6;'
      + 'cursor:pointer;font-size:18px;line-height:1;padding:0 4px;margin-left:4px;}'
      + '.trial-banner-close:hover{opacity:1;}';
    var s = document.createElement('style');
    s.id = 'trial-banner-styles';
    s.textContent = css;
    document.head.appendChild(s);
  }

  function buildBanner(kind, msg, ctaLabel, ctaHref) {
    var host = document.createElement('div');
    host.id = BANNER_ID;
    host.className = 'trial-banner-host';

    var bar = document.createElement('div');
    bar.className = 'trial-banner trial-banner-' + kind;

    var msgEl = document.createElement('span');
    msgEl.className = 'trial-banner-msg';
    msgEl.innerHTML = msg;
    bar.appendChild(msgEl);

    if (ctaLabel && ctaHref) {
      var cta = document.createElement('a');
      cta.className = 'trial-banner-cta';
      cta.href = ctaHref;
      cta.innerHTML = escapeHtml(ctaLabel) + ' <span aria-hidden="true">→</span>';
      bar.appendChild(cta);
    }

    var close = document.createElement('button');
    close.className = 'trial-banner-close';
    close.setAttribute('aria-label', 'Dismiss for this session');
    close.textContent = '×';
    close.addEventListener('click', function () {
      var key = DISMISS_KEY_PREFIX + kind;
      try { sessionStorage.setItem(key, '1'); } catch (e) {}
      host.remove();
    });
    bar.appendChild(close);

    host.appendChild(bar);
    return host;
  }

  function isDismissed(kind) {
    try {
      return sessionStorage.getItem(DISMISS_KEY_PREFIX + kind) === '1';
    } catch (e) { return false; }
  }

  function pickRender(data) {
    var plan = (data && data.plan) || null;
    if (!plan) return null;

    if (plan === 'trial') {
      var daysLeft = daysUntil(data.trial_end);
      if (daysLeft == null || daysLeft > 7) return null;  // early trial: silent

      if (daysLeft <= 3) {
        // High urgency — orange
        var hMsg = daysLeft <= 0
          ? '<strong>Trial ends today.</strong> Add a card to keep Pro features.'
          : '<strong>Trial ends in ' + daysLeft + ' day' + (daysLeft === 1 ? '' : 's') + '.</strong> Add a card to keep Pro.';
        return {
          kind: 'high',
          msg: hMsg,
          ctaLabel: 'Add card',
          ctaHref: '/settings#billing',
        };
      }
      // Low urgency — blue (days 4-7 left)
      return {
        kind: 'low',
        msg: 'Trial: <strong>' + daysLeft + ' days left.</strong> Enjoying Pro? Add a card any time to keep it.',
        ctaLabel: 'Manage plan',
        ctaHref: '/settings#billing',
      };
    }

    if (plan === 'stub') {
      return {
        kind: 'stub',
        msg: '<strong>Your trial has ended.</strong> Stub Free is limited to 1 scan per 7 days. Reactivate Pro for full access.',
        ctaLabel: 'Reactivate Pro',
        ctaHref: '/settings#billing',
      };
    }

    // Pro, free, growth, enterprise → silent
    return null;
  }

  function mount(render) {
    if (!render) return;
    if (isDismissed(render.kind)) return;

    injectStyles();
    var existing = document.getElementById(BANNER_ID);
    if (existing) existing.remove();

    var node = buildBanner(render.kind, render.msg, render.ctaLabel, render.ctaHref);
    if (document.body.firstChild) {
      document.body.insertBefore(node, document.body.firstChild);
    } else {
      document.body.appendChild(node);
    }
  }

  function init() {
    var token = getToken();
    if (!token) return;  // not authenticated

    fetch('/api/user/plan', { headers: { 'Authorization': 'Bearer ' + token } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data) return;
        mount(pickRender(data));
      })
      .catch(function () { /* silent — banner is best-effort */ });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
