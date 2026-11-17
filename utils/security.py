from datetime import datetime, time
import ipaddress
import re

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_input(value: str, max_length: int = 8000) -> str:
    """Strip control characters and bound untrusted log/alert strings before LLM prompts."""
    if not isinstance(value, str):
        value = str(value)
    cleaned = CONTROL_CHARS.sub("", value).strip()
    return cleaned[:max_length]


def validate_ip_address(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def validate_cve_format(cve_id: str) -> bool:
    return bool(cve_id and CVE_REGEX.match(cve_id.strip()))


def is_time_in_window(check_time: time, start_hhmm: str, end_hhmm: str) -> bool:
    """
    Evaluate whether check_time falls inside [start_hhmm, end_hhmm], accurately
    handling windows that cross midnight (e.g. 23:00 -> 01:00).
    """
    start = datetime.strptime(start_hhmm, "%H:%M").time()
    end = datetime.strptime(end_hhmm, "%H:%M").time()
    if start <= end:
        return start <= check_time <= end
    return check_time >= start or check_time <= end
