"""Utility helpers."""
import ipaddress
import re
import socket
from urllib.parse import urlparse

URL_RE = re.compile(
    r"^https?://"                                  # scheme
    r"(\[[0-9a-fA-F:]+\]|"                          # IPv6 literal
    r"[a-zA-Z0-9._-]+"                              # hostname
    r")(:\d{1,5})?(/.*)?$"
)


def is_valid_url(value: str) -> bool:
    if not value or not URL_RE.match(value.strip()):
        return False
    try:
        parsed = urlparse(value.strip())
        return bool(parsed.netloc)
    except ValueError:
        return False


def normalize_url(value: str) -> str:
    return value.strip().rstrip("/")


def hostname_of(value: str) -> str:
    try:
        return (urlparse(value).hostname or "").lower()
    except ValueError:
        return ""


PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
)


def is_local_target(url: str) -> bool:
    host = hostname_of(url)
    if not host:
        return False
    if host in ("localhost",) or host.endswith(".local") or host.endswith(".test"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except Exception:
            return False
    return any(ip in net for net in PRIVATE_NETS)


def fmt_dt(value):
    return value.isoformat() if value else None
