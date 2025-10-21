import ipaddress
import re
from typing import Literal

from .defang import refang

HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    if is_ip(value):
        return False
    return bool(HOST_RE.match(value))


def normalize_host_input(raw: str) -> tuple[Literal["ip", "domain"], str]:
    s = refang(raw.strip().lower())
    # strip common scheme prefixes
    s = re.sub(r"^[a-z]+://", "", s)
    # strip path/query
    s = s.split("/")[0].split("?")[0]
    # strip brackets around IPv6
    s = s.strip("[]")
    if is_ip(s):
        return ("ip", s)
    if is_domain(s):
        return ("domain", s.rstrip("."))
    raise ValueError(f"Input does not look like an IP or domain: {raw}")
