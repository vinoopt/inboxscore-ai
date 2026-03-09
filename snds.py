"""
InboxScore - Microsoft SNDS (Smart Network Data Services) Integration
Fetches IP-level reputation data from Microsoft's SNDS automated data access.
No OAuth required — uses a simple URL key that the user gets from SNDS portal.

SNDS Data URL: https://sendersupport.olc.protection.outlook.com/snds/data.aspx?key={KEY}
Returns CSV with columns:
  IP Address, Activity Start, Activity End, RCPT commands,
  DATA commands, Message recipients, Filter result, Complaint rate,
  Trap message period, Trap hits, Sample HELO, Sample MAIL FROM
"""

import httpx
import csv
import io
from datetime import datetime


# ─── SNDS API CONFIG ───────────────────────────────────────────

SNDS_DATA_URL = "https://sendersupport.olc.protection.outlook.com/snds/data.aspx"


# ─── KEY VALIDATION ───────────────────────────────────────────

async def validate_snds_key(key: str) -> dict:
    """
    Validate an SNDS automated access key by attempting to fetch data.
    Returns {"valid": True/False, "ip_count": N, "error": str|None}
    """
    if not key or len(key) < 10:
        return {"valid": False, "ip_count": 0, "error": "Invalid key format"}

    try:
        url = f"{SNDS_DATA_URL}?key={key}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)

        if response.status_code != 200:
            return {
                "valid": False,
                "ip_count": 0,
                "error": f"SNDS returned status {response.status_code}",
            }

        content = response.text.strip()

        # Check for error pages (SNDS returns HTML on invalid keys)
        if "<html" in content.lower() or "<!doctype" in content.lower():
            return {
                "valid": False,
                "ip_count": 0,
                "error": "Invalid SNDS key — received error page instead of CSV data",
            }

        # Empty response means valid key but no data yet
        if not content:
            return {"valid": True, "ip_count": 0, "error": None}

        # Try parsing as CSV to confirm it's valid data
        rows = parse_snds_csv(content)
        return {"valid": True, "ip_count": len(rows), "error": None}

    except httpx.TimeoutException:
        return {"valid": False, "ip_count": 0, "error": "Connection to SNDS timed out"}
    except Exception as e:
        return {"valid": False, "ip_count": 0, "error": f"Connection error: {str(e)}"}


# ─── DATA FETCHING ────────────────────────────────────────────

async def fetch_snds_data(key: str) -> dict:
    """
    Fetch SNDS CSV data for a given key.
    Returns {"success": True/False, "data": [list of parsed dicts], "error": str|None}
    """
    try:
        url = f"{SNDS_DATA_URL}?key={key}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)

        if response.status_code != 200:
            return {
                "success": False,
                "data": [],
                "error": f"SNDS returned status {response.status_code}",
            }

        content = response.text.strip()

        # Check for HTML error page
        if "<html" in content.lower() or "<!doctype" in content.lower():
            return {
                "success": False,
                "data": [],
                "error": "SNDS key may have expired — received error page",
            }

        if not content:
            return {"success": True, "data": [], "error": None}

        rows = parse_snds_csv(content)
        return {"success": True, "data": rows, "error": None}

    except httpx.TimeoutException:
        return {"success": False, "data": [], "error": "Connection to SNDS timed out"}
    except Exception as e:
        return {"success": False, "data": [], "error": f"Fetch error: {str(e)}"}


# ─── CSV PARSING ──────────────────────────────────────────────

def parse_snds_csv(csv_text: str) -> list:
    """
    Parse SNDS CSV export into structured dicts.

    SNDS CSV format (comma-delimited, no header row):
    IP, ActivityStart, ActivityEnd, RCPTCommands, DATACommands,
    MessageRecipients, FilterResult, ComplaintRate, TrapMsgPeriod,
    TrapHits, SampleHELO, SampleMAILFROM

    FilterResult values: GREEN, YELLOW, RED (or empty)
    ComplaintRate: percentage like "< 0.1%" or "0.5%" or empty
    """
    rows = []

    reader = csv.reader(io.StringIO(csv_text))
    for line in reader:
        # Skip empty lines or lines that look like headers
        if not line or len(line) < 7:
            continue

        # Skip if first field doesn't look like an IP
        ip = line[0].strip()
        if not ip or not _looks_like_ip(ip):
            continue

        try:
            activity_start = line[1].strip() if len(line) > 1 else ""
            activity_end = line[2].strip() if len(line) > 2 else ""
            rcpt_commands = _safe_int(line[3]) if len(line) > 3 else 0
            data_commands = _safe_int(line[4]) if len(line) > 4 else 0
            message_recipients = _safe_int(line[5]) if len(line) > 5 else 0
            filter_result = line[6].strip().upper() if len(line) > 6 else ""
            complaint_rate_str = line[7].strip() if len(line) > 7 else ""
            trap_msg_period = line[8].strip() if len(line) > 8 else ""
            trap_hits = _safe_int(line[9]) if len(line) > 9 else 0
            sample_helo = line[10].strip() if len(line) > 10 else ""
            sample_mail_from = line[11].strip() if len(line) > 11 else ""

            # Parse complaint rate from string like "< 0.1%" or "0.5%"
            complaint_rate = _parse_complaint_rate(complaint_rate_str)

            # Determine IP status from filter result
            ip_status = determine_ip_status(filter_result, complaint_rate, trap_hits)

            # Parse activity date (use start date)
            metric_date = _parse_snds_date(activity_start)

            rows.append({
                "ip_address": ip,
                "metric_date": metric_date,
                "ip_status": ip_status,
                "complaint_rate": complaint_rate,
                "trap_hits": trap_hits,
                "message_count": message_recipients,
                "filter_results": {
                    "filter_result": filter_result,
                    "rcpt_commands": rcpt_commands,
                    "data_commands": data_commands,
                    "message_recipients": message_recipients,
                },
                "sample_helos": {
                    "helo": sample_helo,
                    "mail_from": sample_mail_from,
                    "trap_period": trap_msg_period,
                },
                "raw_data": ",".join(line),
            })

        except Exception as e:
            print(f"[SNDS] Error parsing CSV row: {e}, line: {line}")
            continue

    return rows


# ─── HELPERS ─────────────────────────────────────────────────

def determine_ip_status(filter_result: str, complaint_rate: float, trap_hits: int) -> str:
    """
    Determine overall IP health status.
    Uses SNDS filter result as primary signal, with complaint/trap as secondary.
    Returns: 'green', 'yellow', or 'red'
    """
    # Use SNDS filter result as primary indicator
    if filter_result in ("GREEN", "GRN"):
        return "green"
    elif filter_result in ("YELLOW", "YLW"):
        return "yellow"
    elif filter_result in ("RED",):
        return "red"

    # Fallback: derive from complaint rate and trap hits
    if complaint_rate is not None:
        if complaint_rate >= 0.5:
            return "red"
        elif complaint_rate >= 0.1:
            return "yellow"

    if trap_hits and trap_hits > 5:
        return "red"
    elif trap_hits and trap_hits > 0:
        return "yellow"

    return "green"


def _parse_complaint_rate(rate_str: str) -> float:
    """Parse SNDS complaint rate string like '< 0.1%' or '0.5%' into float 0.0-1.0"""
    if not rate_str:
        return None
    try:
        # Remove < > signs and % and whitespace
        cleaned = rate_str.replace("<", "").replace(">", "").replace("%", "").strip()
        if not cleaned:
            return None
        val = float(cleaned)
        # SNDS reports as percentage, convert to ratio (0.1% → 0.001)
        return val / 100.0
    except (ValueError, TypeError):
        return None


def _parse_snds_date(date_str: str) -> str:
    """Parse SNDS date string into YYYY-MM-DD format"""
    if not date_str:
        return datetime.utcnow().strftime("%Y-%m-%d")
    try:
        # SNDS uses formats like "3/8/2026 12:00 AM" or ISO-ish formats
        for fmt in ("%m/%d/%Y %I:%M %p", "%m/%d/%Y %H:%M", "%Y-%m-%dT%H:%M:%S",
                     "%m/%d/%Y", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(date_str.strip(), fmt)
                return dt.strftime("%Y-%m-%d")
            except ValueError:
                continue
        # If no format matches, try to extract just the date part
        return date_str.split(" ")[0].strip() if " " in date_str else date_str.strip()
    except Exception:
        return datetime.utcnow().strftime("%Y-%m-%d")


def _looks_like_ip(s: str) -> bool:
    """Quick check if string looks like an IPv4 address"""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _safe_int(val) -> int:
    """Safely convert to int, return 0 on failure"""
    try:
        return int(str(val).strip().replace(",", ""))
    except (ValueError, TypeError):
        return 0
