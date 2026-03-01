"""
InboxScore.ai — PDF Report Generator
Generates branded deliverability reports from scan results.
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT


# ─── BRAND COLORS ───────────────────────────────────────────────
BRAND_BG = HexColor("#0a0f1c")
BRAND_PRIMARY = HexColor("#6366f1")  # Indigo
BRAND_GREEN = HexColor("#22c55e")
BRAND_YELLOW = HexColor("#eab308")
BRAND_RED = HexColor("#ef4444")
BRAND_GRAY = HexColor("#64748b")
BRAND_LIGHT = HexColor("#e2e8f0")
BRAND_DARK = HexColor("#1e293b")

STATUS_COLORS = {
    "pass": BRAND_GREEN,
    "warn": BRAND_YELLOW,
    "fail": BRAND_RED,
    "info": BRAND_GRAY,
}

STATUS_LABELS = {
    "pass": "PASS",
    "warn": "WARNING",
    "fail": "FAIL",
    "info": "INFO",
}

CHECK_ICONS = {
    "mx_records": "MX Records",
    "spf": "SPF Record",
    "dkim": "DKIM Signing",
    "dmarc": "DMARC Policy",
    "blacklists": "Blacklist Check",
    "tls": "TLS/SSL Encryption",
    "reverse_dns": "Reverse DNS (PTR)",
    "bimi": "BIMI Record",
    "mta_sts": "MTA-STS Policy",
    "tls_rpt": "TLS Reporting",
    "sender_detection": "Sender Detection",
    "domain_age": "Domain Age",
    "ip_reputation": "IP Reputation",
}


def _score_color(score: int):
    """Return color based on score value."""
    if score >= 85:
        return BRAND_GREEN
    elif score >= 65:
        return BRAND_YELLOW
    else:
        return BRAND_RED


def _score_verdict(score: int) -> str:
    if score >= 85:
        return "Excellent"
    elif score >= 65:
        return "Good"
    elif score >= 40:
        return "Needs Work"
    else:
        return "Critical"


def generate_pdf_report(scan_data: dict) -> bytes:
    """
    Generate a branded PDF report from scan results.

    Args:
        scan_data: Dict with keys: domain, score, summary, checks, scan_time, scanned_at

    Returns:
        PDF file content as bytes
    """
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        topMargin=0.5 * inch,
        bottomMargin=0.6 * inch,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
    )

    # ─── Styles ───
    styles = getSampleStyleSheet()

    style_title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=BRAND_PRIMARY,
        spaceAfter=4,
        alignment=TA_LEFT,
    )

    style_subtitle = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=11,
        textColor=BRAND_GRAY,
        spaceAfter=12,
    )

    style_h2 = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=BRAND_DARK,
        spaceBefore=16,
        spaceAfter=8,
    )

    style_body = ParagraphStyle(
        "BodyText",
        parent=styles["Normal"],
        fontSize=10,
        textColor=black,
        leading=14,
    )

    style_small = ParagraphStyle(
        "SmallText",
        parent=styles["Normal"],
        fontSize=8,
        textColor=BRAND_GRAY,
        leading=11,
    )

    style_check_title = ParagraphStyle(
        "CheckTitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=BRAND_DARK,
        leading=13,
    )

    style_check_detail = ParagraphStyle(
        "CheckDetail",
        parent=styles["Normal"],
        fontSize=9,
        textColor=BRAND_GRAY,
        leading=12,
    )

    style_fix = ParagraphStyle(
        "FixStep",
        parent=styles["Normal"],
        fontSize=9,
        textColor=HexColor("#334155"),
        leading=12,
        leftIndent=12,
    )

    style_footer = ParagraphStyle(
        "Footer",
        parent=styles["Normal"],
        fontSize=8,
        textColor=BRAND_GRAY,
        alignment=TA_CENTER,
    )

    # ─── Build document content ───
    story = []

    domain = scan_data.get("domain", "unknown")
    score = scan_data.get("score", 0)
    checks = scan_data.get("checks", [])
    scan_time = scan_data.get("scan_time", 0)
    scanned_at = scan_data.get("scanned_at", datetime.utcnow().isoformat())
    summary = scan_data.get("summary", {})

    # Parse date
    try:
        scan_date = datetime.fromisoformat(scanned_at.replace("Z", "+00:00"))
        date_str = scan_date.strftime("%B %d, %Y at %H:%M UTC")
    except Exception:
        date_str = scanned_at

    # ─── HEADER ───
    story.append(Paragraph("InboxScore.ai", style_title))
    story.append(Paragraph("Email Deliverability Report", style_subtitle))
    story.append(HRFlowable(
        width="100%", thickness=1, color=BRAND_PRIMARY,
        spaceAfter=12, spaceBefore=0
    ))

    # ─── DOMAIN + SCORE BANNER ───
    verdict = _score_verdict(score)
    score_color = _score_color(score)

    banner_data = [[
        Paragraph(f'<b>{domain}</b>', ParagraphStyle(
            "BannerDomain", parent=styles["Normal"],
            fontSize=16, textColor=white, leading=20
        )),
        Paragraph(f'<b>{score}/100</b>', ParagraphStyle(
            "BannerScore", parent=styles["Normal"],
            fontSize=20, textColor=white, alignment=TA_RIGHT, leading=24
        )),
    ], [
        Paragraph(f'Scanned: {date_str}', ParagraphStyle(
            "BannerDate", parent=styles["Normal"],
            fontSize=9, textColor=HexColor("#94a3b8"), leading=12
        )),
        Paragraph(f'<b>{verdict}</b>', ParagraphStyle(
            "BannerVerdict", parent=styles["Normal"],
            fontSize=11, textColor=score_color, alignment=TA_RIGHT, leading=14
        )),
    ]]

    banner_table = Table(banner_data, colWidths=[doc.width * 0.65, doc.width * 0.35])
    banner_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BRAND_DARK),
        ("TOPPADDING", (0, 0), (-1, 0), 12),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 12),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROUNDEDCORNERS", [6, 6, 6, 6]),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 12))

    # ─── SUMMARY ───
    summary_text = summary.get("text", "")
    if summary_text:
        story.append(Paragraph(summary_text, style_body))
        story.append(Spacer(1, 6))

    # Quick stats
    passed = len([c for c in checks if c.get("status") == "pass"])
    warned = len([c for c in checks if c.get("status") == "warn"])
    failed = len([c for c in checks if c.get("status") == "fail"])
    info_count = len([c for c in checks if c.get("status") == "info"])

    stats_text = f"<b>{passed}</b> passed, <b>{warned}</b> warnings, <b>{failed}</b> failed"
    if info_count:
        stats_text += f", <b>{info_count}</b> informational"
    stats_text += f" &mdash; scan completed in {scan_time}s"
    story.append(Paragraph(stats_text, style_small))
    story.append(Spacer(1, 8))

    # ─── CHECKS TABLE ───
    story.append(Paragraph("Check Results", style_h2))
    story.append(HRFlowable(
        width="100%", thickness=0.5, color=BRAND_LIGHT,
        spaceAfter=8, spaceBefore=0
    ))

    # Build check rows — group by category
    categories = {}
    for check in checks:
        cat = check.get("category", "other")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(check)

    cat_labels = {
        "authentication": "Authentication",
        "reputation": "Reputation",
        "infrastructure": "Infrastructure",
    }

    for cat_key in ["authentication", "infrastructure", "reputation"]:
        cat_checks = categories.get(cat_key, [])
        if not cat_checks:
            continue

        cat_label = cat_labels.get(cat_key, cat_key.title())
        story.append(Spacer(1, 6))
        story.append(Paragraph(f'<b>{cat_label}</b>', ParagraphStyle(
            "CatLabel", parent=styles["Normal"],
            fontSize=11, textColor=BRAND_PRIMARY, spaceBefore=4, spaceAfter=4,
        )))

        for check in cat_checks:
            status = check.get("status", "info")
            name = check.get("name", "")
            title = check.get("title", name)
            detail = check.get("detail", "")
            points = check.get("points", 0)
            max_pts = check.get("max_points", 0)
            fix_steps = check.get("fix_steps", [])

            # Friendly name
            friendly_name = CHECK_ICONS.get(name, title)

            # Status badge color
            s_color = STATUS_COLORS.get(status, BRAND_GRAY)
            s_label = STATUS_LABELS.get(status, status.upper())

            # Points display
            pts_text = ""
            if max_pts > 0:
                pts_text = f"  ({points}/{max_pts} pts)"

            # Build a mini-table for each check row
            row_data = [[
                Paragraph(
                    f'<font color="{s_color.hexval()}">[{s_label}]</font>  '
                    f'<b>{friendly_name}</b>'
                    f'<font color="#94a3b8">{pts_text}</font>',
                    style_check_title
                ),
            ]]

            # Add detail line
            if detail:
                # Truncate very long details
                display_detail = detail if len(detail) <= 300 else detail[:297] + "..."
                # Escape XML special chars
                display_detail = (display_detail
                                  .replace("&", "&amp;")
                                  .replace("<", "&lt;")
                                  .replace(">", "&gt;"))
                row_data.append([
                    Paragraph(display_detail, style_check_detail)
                ])

            # Add fix steps for warn/fail
            if fix_steps and status in ("warn", "fail"):
                fix_items = []
                for i, step in enumerate(fix_steps[:3], 1):  # Max 3 fix steps
                    step_text = str(step).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    if len(step_text) > 200:
                        step_text = step_text[:197] + "..."
                    fix_items.append(Paragraph(f'{i}. {step_text}', style_fix))

                if fix_items:
                    row_data.append([Paragraph(
                        '<font color="#6366f1"><b>How to fix:</b></font>',
                        ParagraphStyle("FixLabel", parent=styles["Normal"],
                                       fontSize=9, textColor=BRAND_PRIMARY, leading=12, leftIndent=12)
                    )])
                    for fix_p in fix_items:
                        row_data.append([fix_p])

            check_table = Table(row_data, colWidths=[doc.width])
            check_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), HexColor("#f8fafc")),
                ("TOPPADDING", (0, 0), (-1, 0), 8),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 1), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
                ("LINEBELOW", (0, -1), (-1, -1), 0.5, HexColor("#e2e8f0")),
            ]))

            story.append(KeepTogether([check_table, Spacer(1, 4)]))

    # Handle any uncategorized checks
    other_checks = []
    for cat_key, cat_checks in categories.items():
        if cat_key not in ("authentication", "infrastructure", "reputation"):
            other_checks.extend(cat_checks)

    if other_checks:
        story.append(Spacer(1, 6))
        story.append(Paragraph('<b>Other</b>', ParagraphStyle(
            "CatLabelOther", parent=styles["Normal"],
            fontSize=11, textColor=BRAND_PRIMARY, spaceBefore=4, spaceAfter=4,
        )))
        for check in other_checks:
            status = check.get("status", "info")
            name = check.get("name", "")
            title = check.get("title", name)
            s_color = STATUS_COLORS.get(status, BRAND_GRAY)
            s_label = STATUS_LABELS.get(status, status.upper())
            story.append(Paragraph(
                f'<font color="{s_color.hexval()}">[{s_label}]</font>  <b>{title}</b>',
                style_check_title
            ))

    # ─── SCORE BREAKDOWN ───
    story.append(Spacer(1, 14))
    story.append(Paragraph("Score Breakdown", style_h2))
    story.append(HRFlowable(
        width="100%", thickness=0.5, color=BRAND_LIGHT,
        spaceAfter=8, spaceBefore=0
    ))

    # Table with check name, status, points
    style_table_header = ParagraphStyle(
        "TableHeader", parent=styles["Normal"],
        fontSize=10, textColor=white, leading=13,
    )
    breakdown_header = [
        Paragraph('<b>Check</b>', style_table_header),
        Paragraph('<b>Status</b>', style_table_header),
        Paragraph('<b>Points</b>', style_table_header),
    ]
    breakdown_rows = [breakdown_header]

    for check in checks:
        name = check.get("name", "")
        status = check.get("status", "info")
        points = check.get("points", 0)
        max_pts = check.get("max_points", 0)
        friendly = CHECK_ICONS.get(name, check.get("title", name))
        s_color = STATUS_COLORS.get(status, BRAND_GRAY)
        s_label = STATUS_LABELS.get(status, status.upper())

        pts_display = f"{points}/{max_pts}" if max_pts > 0 else "N/A"

        breakdown_rows.append([
            Paragraph(friendly, style_body),
            Paragraph(f'<font color="{s_color.hexval()}">{s_label}</font>', style_body),
            Paragraph(pts_display, style_body),
        ])

    # Total row
    total_pts = sum(c.get("points", 0) for c in checks)
    total_max = sum(c.get("max_points", 0) for c in checks if c.get("max_points", 0) > 0)
    breakdown_rows.append([
        Paragraph('<b>TOTAL</b>', style_body),
        Paragraph(f'<b>Score: {score}/100</b>', style_body),
        Paragraph(f'<b>{total_pts}/{total_max}</b>', style_body),
    ])

    breakdown_table = Table(
        breakdown_rows,
        colWidths=[doc.width * 0.50, doc.width * 0.25, doc.width * 0.25]
    )
    breakdown_table.setStyle(TableStyle([
        # Header row
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), white),
        # Alternating row colors
        *[("BACKGROUND", (0, i), (-1, i), HexColor("#f8fafc") if i % 2 == 0 else white)
          for i in range(1, len(breakdown_rows) - 1)],
        # Total row
        ("BACKGROUND", (0, -1), (-1, -1), HexColor("#f1f5f9")),
        ("LINEABOVE", (0, -1), (-1, -1), 1, BRAND_DARK),
        # Borders
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(breakdown_table)

    # ─── FOOTER ───
    story.append(Spacer(1, 24))
    story.append(HRFlowable(
        width="100%", thickness=0.5, color=BRAND_LIGHT,
        spaceAfter=8, spaceBefore=0
    ))
    story.append(Paragraph(
        f'Generated by InboxScore.ai &mdash; {date_str}',
        style_footer
    ))
    story.append(Paragraph(
        'https://inboxscore.ai &mdash; Free email deliverability diagnostics',
        style_footer
    ))

    # ─── Build PDF ───
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
