from __future__ import annotations

from datetime import datetime
from http import HTTPStatus
from typing import Any

from ..http.request import RequestManager
from ..models.common import DomainWhois


class RdapClient:
    """Free RDAP client via public rdap.org service.

    Using https://rdap.org/domain/<domain>
    """

    BASE = "https://rdap.org/domain/"

    def __init__(self, rm: RequestManager) -> None:
        self.rm = rm

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None

    def _parse_events(
        self, data: dict[str, Any]
    ) -> tuple[datetime | None, datetime | None, datetime | None]:
        created = updated = expires = None
        for ev in data.get("events", []) or []:
            action = ev.get("eventAction")
            ts = self._parse_datetime(ev.get("eventDate"))
            if action == "registration":
                created = ts
            elif action == "last changed":
                updated = ts
            elif action == "expiration":
                expires = ts
        return created, updated, expires

    def _parse_registrar(self, data: dict[str, Any]) -> str | None:
        vcard_tuple_len = 2
        for ent in data.get("entities", []) or []:
            roles = ent.get("roles", []) or []
            if "registrar" in roles:
                vcard = ent.get("vcardArray")
                if isinstance(vcard, list) and len(vcard) == vcard_tuple_len:
                    for attr in vcard[1]:
                        if attr and attr[0] == "fn":
                            value = attr[-1]
                            if isinstance(value, str):
                                return value
                            if isinstance(value, list) and value:
                                last = value[-1]
                                if isinstance(last, str):
                                    return last
        return None

    def _parse_nameservers(self, data: dict[str, Any]) -> list[str]:
        nameservers: list[str] = []
        for ns in data.get("nameservers", []) or []:
            if isinstance(ns, dict) and ns.get("ldhName"):
                nameservers.append(ns["ldhName"].lower())
        return sorted(set(nameservers))

    def _parse_dnssec(self, data: dict[str, Any]) -> bool | None:
        sec = data.get("secureDNS")
        if isinstance(sec, dict) and "zoneSigned" in sec:
            return bool(sec.get("zoneSigned"))
        return None

    async def fetch(self, domain: str) -> DomainWhois | None:
        resp = await self.rm.get(f"{self.BASE}{domain}")
        if resp.status_code != HTTPStatus.OK:
            return None
        data: dict[str, Any] = resp.json()
        created, updated, expires = self._parse_events(data)
        registrar = self._parse_registrar(data)
        nameservers = self._parse_nameservers(data)
        dnssec = self._parse_dnssec(data)
        return DomainWhois(
            domain=domain,
            registrar=registrar,
            nameservers=nameservers or None,
            dnssec=dnssec,
            created=created,
            updated=updated,
            expires=expires,
        )
