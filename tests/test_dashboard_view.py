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

    def test_active_alerts_container_present(self):
        assert 'id="dh-alerts-container"' in _view_dashboard_block()

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
            "dhToggleTrend",
        ],
    )
    def test_render_function_defined(self, fn: str):
        assert f"function {fn}" in DASHBOARD_HTML, (
            f"Expected JS function {fn}() to be defined in dashboard.html"
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
