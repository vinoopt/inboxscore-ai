/* InboxScore SWR cache helper — see docs/DESIGN-SYSTEM.md §11.5
 * ----------------------------------------------------------------
 * Purpose: provide a tiny, dependency-free localStorage layer so
 * every data-driven page can hydrate from a previous payload on
 * cold start, then revalidate in the background. This eliminates
 * the "Loading…" spinner on every page navigation.
 *
 * Public API (all globals — no module system in this app):
 *   cacheGet(key, maxAgeMs)      → value or null
 *   cacheSet(key, value)         → void
 *   cacheClear()                 → void (call on logout)
 *   cacheAgeMs(key)              → number or null
 *   cacheAgeLabel(key)           → human string ("5 min ago") or null
 *   cacheUserNamespace()         → returns the namespace currently in use
 *
 * Keys are auto-namespaced by a hash of the bearer token so two
 * users on the same browser don't see each other's data. If the
 * token isn't available we fall back to a public namespace; this
 * is fine because the only pages that call us are auth-gated and
 * will always have a token before fetching data.
 */
(function () {
  'use strict';

  var ROOT = 'is.cache.v1.';   // root prefix; bump when shape changes

  /** Cheap, deterministic hash of a string. */
  function _hash(str) {
    var h = 5381;
    for (var i = 0; i < str.length; i++) {
      h = ((h << 5) + h) + str.charCodeAt(i);
      h |= 0;
    }
    return ('00000000' + (h >>> 0).toString(16)).slice(-8);
  }

  /** Read the bearer token, the same way the app's other code does. */
  function _readToken() {
    try {
      return localStorage.getItem('access_token') || localStorage.getItem('token') || '';
    } catch (e) { return ''; }
  }

  /** Returns "u_<hash>." for an authed user, or "anon." otherwise. */
  function cacheUserNamespace() {
    var t = _readToken();
    return t ? 'u_' + _hash(t) + '.' : 'anon.';
  }

  function _key(rawKey) {
    return ROOT + cacheUserNamespace() + rawKey;
  }

  /** Returns parsed value or null if missing / expired / corrupt. */
  function cacheGet(rawKey, maxAgeMs) {
    try {
      var raw = localStorage.getItem(_key(rawKey));
      if (!raw) return null;
      var entry = JSON.parse(raw);
      if (!entry || typeof entry.ts !== 'number') return null;
      if (typeof maxAgeMs === 'number' && Date.now() - entry.ts > maxAgeMs) return null;
      return entry.v;
    } catch (e) {
      return null;
    }
  }

  /** Stores value with a timestamp. Silently no-ops on quota errors. */
  function cacheSet(rawKey, value) {
    try {
      var entry = { ts: Date.now(), v: value };
      localStorage.setItem(_key(rawKey), JSON.stringify(entry));
    } catch (e) {
      // QuotaExceeded or private mode — ignore. SWR is best-effort.
    }
  }

  /** Returns age in ms or null if no entry. */
  function cacheAgeMs(rawKey) {
    try {
      var raw = localStorage.getItem(_key(rawKey));
      if (!raw) return null;
      var entry = JSON.parse(raw);
      if (!entry || typeof entry.ts !== 'number') return null;
      return Date.now() - entry.ts;
    } catch (e) { return null; }
  }

  /** Human-readable freshness stamp. */
  function cacheAgeLabel(rawKey) {
    var ms = cacheAgeMs(rawKey);
    if (ms == null) return null;
    if (ms < 60 * 1000) return 'just now';
    if (ms < 60 * 60 * 1000) {
      var m = Math.round(ms / 60000);
      return m + ' min ago';
    }
    if (ms < 24 * 60 * 60 * 1000) {
      var h = Math.round(ms / 3600000);
      return h + ' hour' + (h === 1 ? '' : 's') + ' ago';
    }
    var d = Math.round(ms / 86400000);
    return d + ' day' + (d === 1 ? '' : 's') + ' ago';
  }

  /** Wipes every cache entry for the current user. Call on logout. */
  function cacheClear() {
    try {
      var prefix = ROOT + cacheUserNamespace();
      var toDelete = [];
      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        if (k && k.indexOf(prefix) === 0) toDelete.push(k);
      }
      toDelete.forEach(function (k) { localStorage.removeItem(k); });
    } catch (e) {}
  }

  // Expose globals.
  window.cacheGet = cacheGet;
  window.cacheSet = cacheSet;
  window.cacheClear = cacheClear;
  window.cacheAgeMs = cacheAgeMs;
  window.cacheAgeLabel = cacheAgeLabel;
  window.cacheUserNamespace = cacheUserNamespace;
})();
