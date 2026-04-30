"""
INBOX-82 — Dashboard v2 view contract tests.

Asserts the trimmed-card decision approved 2026-04-26:
  • Top row: SPF, DKIM, DMARC, MX
  • Second row: Reverse DNS, TLS, MTA-STS
  • DROPPED from Dashboard: BIMI, Domain Age
    (still rendered in the Scan Detail page below, just not as Dashboard tiles)

Also asserts that critical view IDs and helper functions are still wired
up so the rebuild doesn't silently drift from the mockup.

These are file-content assertions, not browser-renders — fast, deterministic,
and no Selenium dependency. They guard against future regressions where a
developer accidentally re-introduces BIMI/Domain Age tiles on the Dashboard.
"""

from pathlib import Path

import pytest

DASHBOARD_HTML = (
    Path(__file__).parent.parent / "static" / "dashboard.html"
).read_text()


def _view_dashboard_block() -> str:
    """Return only the markup between #view-dashboard open and close.

    The full file also contains #view-scan-results which DOES include
    BIMI/Domain Age cards (that's the Scan Detail page we deliberately
    leave alone). Scoping assertions to the Dashboard block prevents
    false negatives from the unrelated Scan Detail markup.
    """
    start = DASHBOARD_HTML.find('id="view-dashboard"')
    end = DASHBOARD_HTML.find("<!-- /view-dashboard -->")
    assert start != -1, "Could not find #view-dashboard opening"
    assert end != -1, "Could not find #view-dashboard closing comment"
    return DASHBOARD_HTML[start:end]


class TestDashboardDiagCards:
    """Top-row + second-row DNS/Auth diagnostic cards (the 7 we kept)."""

    def test_diag_grid_present(self):
        assert 'id="dh-diag-grid"' in _view_dashboard_block()

    def test_dh_diag_cards_constant_lists_seven_checks(self):
        # The JS module declares which checks render as Dashboard tiles in
        # the DH_DIAG_CARDS array. Lock the count + identities.
        block = DASHBOARD_HTML
        assert "DH_DIAG_CARDS = [" in block
        # Pull the array literal
        start = block.index("DH_DIAG_CARDS = [")
        end = block.index("];", start)
        arr = block[start:end]
        # The 7 expected keys
        for key in ["spf", "dkim", "dmarc", "mx_records", "reverse_dns", "tls", "mta_sts"]:
            assert f"key: '{key}'" in arr or f'key: "{key}"' in arr, (
                f"DH_DIAG_CARDS is missing '{key}' card key"
            )

    def test_bimi_not_in_dh_diag_cards(self):
        block = DASHBOARD_HTML
        start = block.index("DH_DIAG_CARDS = [")
        end = block.index("];", start)
        arr = block[start:end]
        assert "bimi" not in arr.lower(), (
            "BIMI must NOT appear as a Dashboard tile (INBOX-82). "
            "It still renders in the Scan Detail page."
        )

    def test_domain_age_not_in_dh_diag_cards(self):
        block = DASHBOARD_HTML
        start = block.index("DH_DIAG_CARDS = [")
        end = block.index("];", start)
        arr = block[start:end]
        assert "domain_age" not in arr.lower(), (
            "Domain Age must NOT appear as a Dashboard tile (INBOX-82). "
            "It still renders in the Scan Detail page."
        )


class TestDashboardScoreHero:
    def test_score_hero_present(self):
        assert 'id="dh-score-hero"' in _view_dashboard_block()

    def test_score_circle_present(self):
        assert 'id="dh-score-circle"' in _view_dashboard_block()

    def test_score_band_present(self):
        # Excellent / Good / Needs Work / At Risk
        assert 'id="dh-score-band"' in _view_dashboard_block()


class TestDashboardSections:
    def test_provider_grid_present(self):
        assert 'id="dh-provider-grid"' in _view_dashboard_block()

    def test_safety_grid_present(self):
        assert 'id="dh-safety-grid"' in _view_dashboard_block()

    def test_recent_scans_list_present(self):
        assert 'id="dh-history-list"' in _view_dashboard_block()

    def test_needs_attention_block_present(self):
        # INBOX-156 (v1.16.6): renamed "Active Alerts" container to the
        # Needs Attention block. The block is hidden by default and
        # only renders when alerts exist (the score hero is the
        # all-clear signal — no separate "no alerts" empty state).
        block = _view_dashboard_block()
        assert 'id="dh-needs-attention"' in block
        assert 'id="dh-na-list"' in block
        assert 'id="dh-na-icon"' in block

    def test_trend_card_present(self):
        assert 'id="dh-trend-card"' in _view_dashboard_block()


class TestDashboardToggles:
    def test_domain_selector_present(self):
        assert 'id="dh-domain-select"' in _view_dashboard_block()
        assert 'id="dh-domain-dropdown"' in _view_dashboard_block()

    def test_view_toggle_buttons_present(self):
        assert 'id="dh-toggle-single"' in _view_dashboard_block()
        assert 'id="dh-toggle-portfolio"' in _view_dashboard_block()

    def test_portfolio_view_present(self):
        assert 'id="dh-portfolio-view"' in _view_dashboard_block()


class TestDashboardJavaScriptHooks:
    """Make sure the render functions and orchestrator are still wired up."""

    @pytest.mark.parametrize(
        "fn",
        [
            "dhPickDefaultDomain",
            "dhRenderScoreHero",
            "dhRenderDiagGrid",
            "dhRenderProviderGrid",
            "dhRenderSafety",
            "dhRenderHistory",
            "dhRenderTrend",
            "dhRenderSingleView",
            "dhRenderPortfolio",
            "dhShowSingleView",
            "dhShowPortfolioView",
            "dhSelectDomain",
            # INBOX-97: dhToggleTrend removed (chart is always visible now)
        ],
    )
    def test_render_function_defined(self, fn: str):
        assert f"function {fn}" in DASHBOARD_HTML, (
            f"Expected JS function {fn}() to be defined in dashboard.html"
        )


class TestRenderShapeAdapter:
    """INBOX-83 — guard against the regression where dhRenderDiagGrid read
    `results[card.key]` instead of iterating `results.checks[]`. The new
    code uses a `dhCheckByName(scan)` adapter; lock its presence + that
    every render path that needs check rows uses it."""

    def test_dhCheckByName_helper_defined(self):
        assert "function dhCheckByName(scan)" in DASHBOARD_HTML, (
            "Missing dhCheckByName adapter — without it, the diagnostic "
            "cards fall through to 'Info' on every domain (INBOX-83)."
        )

    def test_diag_grid_uses_check_adapter(self):
        # Locate the dhRenderDiagGrid function and assert it pulls checks
        # via dhCheckByName, not by indexing results[card.key].
        idx = DASHBOARD_HTML.index("function dhRenderDiagGrid(domain)")
        # Find the closing brace of this function (rough heuristic — first
        # occurrence of "\n}" after a balanced body would require parsing,
        # so just look for the adapter call anywhere in the next 4kb).
        body = DASHBOARD_HTML[idx : idx + 4000]
        assert "dhCheckByName(scan)" in body, (
            "dhRenderDiagGrid must call dhCheckByName(scan) — otherwise "
            "every card renders 'Info' (INBOX-83 regression)."
        )
        assert "results[card.key]" not in body, (
            "dhRenderDiagGrid still reads results[card.key] — that path "
            "doesn't exist on real scans (INBOX-83)."
        )

    def test_safety_uses_check_adapter(self):
        idx = DASHBOARD_HTML.index("function dhRenderSafety(domain)")
        body = DASHBOARD_HTML[idx : idx + 3000]
        assert "dhCheckByName(scan)" in body, (
            "dhRenderSafety must use dhCheckByName(scan) for blacklist "
            "lookup (INBOX-83)."
        )
        # The old broken path read results.blacklists at the top level
        assert "scan.results.blacklists" not in body, (
            "dhRenderSafety still reads scan.results.blacklists at top "
            "level — that path doesn't exist on real scans (INBOX-83)."
        )

    def test_score_hero_iterates_checks_array(self):
        idx = DASHBOARD_HTML.index("function dhRenderScoreHero(domain)")
        body = DASHBOARD_HTML[idx : idx + 3500]
        assert "scan.results.checks" in body, (
            "Score Hero pass/warn/fail counts must iterate "
            "scan.results.checks (INBOX-83)."
        )
        assert "Object.values(scan.results)" not in body, (
            "Score Hero still iterates Object.values(scan.results) — "
            "that includes domain/score/scanned_at and produces wrong "
            "counts (INBOX-83)."
        )


class TestDefaultDomainPick:
    """INBOX-83 — `dhPickDefaultDomain` must prefer the user's monitored
    domains. A one-off scan (e.g. mailercloud.com from the marketing site)
    must NOT hijack the default selected domain over a real monitored
    domain like euverify.com."""

    def test_picks_monitored_first(self):
        idx = DASHBOARD_HTML.index("function dhPickDefaultDomain()")
        body = DASHBOARD_HTML[idx : idx + 1500]
        # The fix: build a Set of monitored domains and only consider
        # scans for those domains in the first pass.
        assert "monitored.has(scan.domain)" in body, (
            "dhPickDefaultDomain must filter scans to monitored domains "
            "before picking (INBOX-83 ghost-domain hijack regression)."
        )


class TestRefreshButton:
    """INBOX-83 ergonomics — Score Hero gets a Refresh button so users
    can re-scan the selected domain in one click."""

    def test_refresh_button_present(self):
        assert 'id="dh-refresh-btn"' in _view_dashboard_block()

    def test_refresh_handler_defined(self):
        assert "function dhRefreshSelectedDomain()" in DASHBOARD_HTML


class TestDashboardRefreshOnNavBack:
    """INBOX-85 — after dashStartScan completes, the in-memory _dh state must
    be updated so navigating back to the Dashboard surfaces the new scan
    (without a hard page reload). Previously dashShowView only toggled
    view classes and the user saw 'No scan yet' for a domain they had
    just scanned."""

    def test_dash_show_view_rerenders_dashboard(self):
        idx = DASHBOARD_HTML.index("function dashShowView(view)")
        body = DASHBOARD_HTML[idx : idx + 1000]
        assert "dhRenderSingleView()" in body, (
            "dashShowView must call dhRenderSingleView() when switching to "
            "'dashboard' so just-completed scans appear (INBOX-85)."
        )

    def test_dash_start_scan_updates_dh_state(self):
        idx = DASHBOARD_HTML.index("async function dashStartScan()")
        body = DASHBOARD_HTML[idx : idx + 8000]
        assert "window._dh.scansByDomain[domain] = fresh" in body, (
            "dashStartScan must push the new scan into "
            "window._dh.scansByDomain so the Dashboard renders it on "
            "return (INBOX-85)."
        )
        assert "window._dh.scansListByDomain[domain].unshift(fresh)" in body, (
            "dashStartScan must prepend the new scan to history so Recent "
            "Scans on the Dashboard reflects it (INBOX-85)."
        )
        assert "window._dh.selectedDomain = domain" in body, (
            "dashStartScan must flip the selected domain to the just-"
            "scanned one so the user lands on the right card (INBOX-85)."
        )


class TestScanDetailViewIntact:
    """Sanity: the Scan Detail view (which DOES show BIMI + Domain Age) must
    remain intact. INBOX-82 only changes the Dashboard surface."""

    def test_scan_results_view_present(self):
        assert 'id="view-scan-results"' in DASHBOARD_HTML

    def test_dash_render_results_function_present(self):
        # The full per-check rendering used by the Scan Detail page
        assert "dashRenderResults" in DASHBOARD_HTML

    def test_scanning_view_present(self):
        # Loading-spinner view used during /api/scan
        assert 'id="view-scanning"' in DASHBOARD_HTML
