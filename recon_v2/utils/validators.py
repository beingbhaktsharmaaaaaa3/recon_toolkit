import ipaddress
import re
import socket
from urllib.parse import urlparse


def validate_target(target: str) -> str:
    """Strip scheme/path from URL and return clean hostname or IP."""
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or target
    else:
        host = target.split("/")[0]
    return host.rstrip(".").lower()


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_valid_hostname(s: str) -> bool:
    if len(s) > 253:
        return False
    pattern = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    return bool(pattern.match(s))


def validate_target_strict(target: str) -> tuple[bool, str]:
    """Returns (is_valid, error_message)."""
    if not target:
        return False, "Target cannot be empty"
    if is_ip(target):
        return True, ""
    if is_valid_hostname(target):
        return True, ""
    return False, f"'{target}' is not a valid hostname or IP address"


def parse_ports(port_str: str) -> tuple[list[int], str]:
    """
    Parse '80,443' or '1-1024' into a sorted list of ints.
    Returns (ports, error_message). error_message is '' on success.
    """
    ports = []
    try:
        for part in port_str.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                bounds = part.split("-", 1)
                if len(bounds) != 2:
                    return [], f"Invalid range: '{part}'"
                start, end = int(bounds[0]), int(bounds[1])
                if start < 1 or end > 65535 or start > end:
                    return [], f"Port range out of bounds: '{part}' (must be 1-65535)"
                ports.extend(range(start, end + 1))
            else:
                p = int(part)
                if p < 1 or p > 65535:
                    return [], f"Port {p} out of range (1-65535)"
                ports.append(p)
    except ValueError as e:
        return [], f"Invalid port value: {e}"
    return sorted(set(ports)), ""


def validate_threads(value: int) -> tuple[bool, str]:
    if value < 1:
        return False, "Thread count must be at least 1"
    if value > 1000:
        return False, "Thread count above 1000 may cause resource exhaustion — max is 1000"
    return True, ""


def validate_timeout(value: float) -> tuple[bool, str]:
    if value <= 0:
        return False, "Timeout must be greater than 0"
    if value > 60:
        return False, "Timeout above 60s is impractical"
    return True, ""


def resolve_target(target: str) -> tuple[str, str]:
    """Returns (ip, error). Resolves hostname to IP."""
    if is_ip(target):
        return target, ""
    try:
        ip = socket.gethostbyname(target)
        return ip, ""
    except socket.gaierror as e:
        return "", f"Could not resolve '{target}': {e}"
