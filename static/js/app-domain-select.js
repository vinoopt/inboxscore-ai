/* INBOX-218 — Shared domain-select component.
 *
 * One canonical pill-with-chevron domain picker used across:
 *   • Dashboard      (the original "good one" Vinoop pointed at)
 *   • Postmaster     (was native <select>)
 *   • Microsoft SNDS (was native <select>)
 *   • Blacklist      (had its own bl-* implementation)
 *   • Alerts         (had its own al-* implementation)
 *
 * CSS lives in static/css/app-chrome.css under the canonical
 * .domain-select / .domain-dropdown / .domain-dropdown-item classes.
 *
 * Usage per page:
 *
 *   1. Render the markup (with page-prefixed IDs):
 *
 *      <div class="domain-select" id="pm-domain-select"
 *           onclick="AppDomainSelect.toggle('pm-domain-dropdown', event)">
 *        <span class="domain-select-dot"></span>
 *        <div style="flex:1;min-width:0;">
 *          <div id="pm-selected-domain" style="font-weight:500;...">
 *            <!-- shown domain name goes here, hydrated by setSelected() -->
 *          </div>
 *        </div>
 *        <span class="domain-select-arrow">
 *          <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
 *               stroke="currentColor" stroke-width="1.5" stroke-linecap="round"
 *               stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
 *        </span>
 *        <div class="domain-dropdown" id="pm-domain-dropdown"></div>
 *      </div>
 *
 *   2. Mount the controller once during page init:
 *
 *      const ctl = AppDomainSelect.create({
 *        dropdownId:  'pm-domain-dropdown',
 *        nameElId:    'pm-selected-domain',
 *        onSelect:    function(domain) { onEhDomainChange(domain); },
 *      });
 *
 *   3. Whenever the page learns the domain list / selection, call:
 *
 *      ctl.setDomains([{domain:'example.com'}, ...]);
 *      ctl.setSelected('example.com');
 *
 * Each page keeps its own state — this helper only owns the dropdown
 * markup + open/close + click → callback. It does not touch URL params,
 * localStorage, or any page-specific data flow.
 */
(function (window, document) {
  'use strict';

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Each mounted controller is registered by its dropdownId so
  // _handleItemClick (called from inline onclick attributes) can route
  // back to the right onSelect callback.
  const _registry = Object.create(null);

  /**
   * Mount a domain-select controller. See file-level docblock for usage.
   *
   * @param {Object} config
   * @param {string} config.dropdownId  - id of the .domain-dropdown <div>
   * @param {string} config.nameElId    - id of the element that displays the current domain
   * @param {(domain:string)=>void} config.onSelect - called when user picks a domain
   * @returns {{setDomains:(arr:Array)=>void, setSelected:(d:string)=>void}}
   */
  function create(config) {
    if (!config || !config.dropdownId) {
      console.warn('[AppDomainSelect] create() requires config.dropdownId');
      return null;
    }
    const dd = document.getElementById(config.dropdownId);
    if (!dd) {
      console.warn('[AppDomainSelect] dropdown element not found:', config.dropdownId);
      return null;
    }

    let _domains = [];
    let _selected = null;

    function _normalize(d) {
      if (!d) return '';
      if (typeof d === 'string') return d;
      return d.domain || d.name || '';
    }

    function render() {
      if (_domains.length === 0) { dd.innerHTML = ''; return; }
      const parts = [];
      for (let i = 0; i < _domains.length; i++) {
        const name = _normalize(_domains[i]);
        if (!name) continue;
        const sel = (name === _selected) ? ' selected' : '';
        // Pass dropdownId + domain to the click handler. We use a data
        // attribute (instead of inline string concat into onclick) to
        // avoid quote-escaping bugs on domains with unusual characters.
        parts.push(
          '<div class="domain-dropdown-item' + sel + '" ' +
          'data-domain="' + escapeHtml(name) + '" ' +
          'data-dropdown-id="' + escapeHtml(config.dropdownId) + '">' +
          escapeHtml(name) +
          '</div>'
        );
      }
      dd.innerHTML = parts.join('');
    }

    function setDomains(arr) {
      _domains = Array.isArray(arr) ? arr : [];
      render();
    }

    function setSelected(domain) {
      _selected = domain || null;
      const nameEl = config.nameElId ? document.getElementById(config.nameElId) : null;
      if (nameEl) nameEl.textContent = _selected || '';
      render();
    }

    _registry[config.dropdownId] = {
      onSelect: typeof config.onSelect === 'function' ? config.onSelect : null,
      setSelected: setSelected,
    };

    // Delegated click handler on the dropdown — survives setDomains
    // re-renders without rebinding per item.
    dd.addEventListener('click', function (e) {
      const item = e.target.closest('.domain-dropdown-item');
      if (!item || !dd.contains(item)) return;
      e.stopPropagation();
      const domain = item.getAttribute('data-domain');
      const reg = _registry[config.dropdownId];
      if (!reg) return;
      dd.classList.remove('open');
      reg.setSelected(domain);
      if (reg.onSelect) reg.onSelect(domain);
    });

    return { setDomains: setDomains, setSelected: setSelected };
  }

  /**
   * Toggle a dropdown open/close. Closes other open dropdowns first so
   * only one is ever visible at a time across the page.
   * Wired via inline onclick on the .domain-select container.
   */
  function toggle(dropdownId, e) {
    if (e) e.stopPropagation();
    const dd = document.getElementById(dropdownId);
    if (!dd) return;
    Object.keys(_registry).forEach(function (id) {
      if (id !== dropdownId) {
        const otherDd = document.getElementById(id);
        if (otherDd) otherDd.classList.remove('open');
      }
    });
    dd.classList.toggle('open');
  }

  // Outside-click closes any open dropdown.
  document.addEventListener('click', function () {
    Object.keys(_registry).forEach(function (id) {
      const dd = document.getElementById(id);
      if (dd) dd.classList.remove('open');
    });
  });

  // Escape key closes any open dropdown.
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    Object.keys(_registry).forEach(function (id) {
      const dd = document.getElementById(id);
      if (dd) dd.classList.remove('open');
    });
  });

  window.AppDomainSelect = {
    create: create,
    toggle: toggle,
  };
})(window, document);
