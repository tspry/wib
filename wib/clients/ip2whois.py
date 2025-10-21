from __future__ import annotations

from datetime import datetime
from http import HTTPStatus
from typing import Any

from ..http.request import RequestManager
from ..models.common import DomainWhois


class Ip2WhoisClient:
    """WHOIS via IP2WHOIS API (optional, requires API key).

    Docs: https://www.ip2whois.com/documentation
    """

    BASE = "https://api.ip2whois.com/v2"

    def __init__(self, rm: RequestManager, api_key: str) -> None:
        self.rm = rm
        self.api_key = api_key

    @staticmethod
    def _parse_dt(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None

    async def fetch(self, domain: str) -> DomainWhois | None:
        resp = await self.rm.get(self.BASE, params={"key": self.api_key, "domain": domain})
        if resp.status_code != HTTPStatus.OK:
            return None
        data: dict[str, Any] = resp.json()
        # API reports errors in an "error" object
        if isinstance(data.get("error"), dict):
            return None

        registrar = data.get("registrar") or None
        raw_ns = data.get("name_servers")
        if isinstance(raw_ns, list):
            nameservers = sorted({str(ns).lower() for ns in raw_ns if isinstance(ns, str)})
        elif isinstance(raw_ns, str):
            parts = [p.strip().lower() for p in raw_ns.split(",") if p.strip()]
            nameservers = sorted(set(parts))
        else:
            nameservers = None

        dnssec_raw = data.get("dnssec")
        dnssec = None
        if isinstance(dnssec_raw, str):
            v = dnssec_raw.strip().lower()
            dnssec = v in {"signed", "yes", "true", "enabled", "enable"}

        return DomainWhois(
            domain=domain,
            registrar=registrar,
            nameservers=nameservers or None,
            dnssec=dnssec,
            created=self._parse_dt(data.get("create_date")),
            updated=self._parse_dt(data.get("update_date")),
            expires=self._parse_dt(data.get("expire_date")),
        )
