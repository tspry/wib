from __future__ import annotations

from http import HTTPStatus
from typing import Any

from ..http.request import RequestManager
from ..models.common import DnsRecordMx, DomainDns


class DnsClient:
    """DNS over HTTPS client using Google Public DNS.

    Docs: https://developers.google.com/speed/public-dns/docs/doh
    Endpoint: https://dns.google/resolve?name=<domain>&type=<RRType>
    """

    BASE = "https://dns.google/resolve"

    def __init__(self, rm: RequestManager) -> None:
        self.rm = rm

    async def _resolve(self, name: str, rrtype: str) -> list[dict[str, Any]]:
        resp = await self.rm.get(self.BASE, params={"name": name, "type": rrtype})
        if resp.status_code != HTTPStatus.OK:
            return []
        data: dict[str, Any] = resp.json()
        if int(data.get("Status", 0)) != 0:
            return []
        answers = data.get("Answer") or []
        return [a for a in answers if isinstance(a, dict)]

    async def fetch(self, domain: str) -> DomainDns | None:
        a = await self._resolve(domain, "A")
        aaaa = await self._resolve(domain, "AAAA")
        cname = await self._resolve(domain, "CNAME")
        ns = await self._resolve(domain, "NS")
        mx = await self._resolve(domain, "MX")
        txt = await self._resolve(domain, "TXT")

        def extract_values(items: list[dict[str, Any]], *, field: str) -> list[str]:
            vals: list[str] = []
            for it in items:
                v = it.get("data")
                if isinstance(v, str):
                    vals.append(v.strip().rstrip("."))
            return list(dict.fromkeys(vals))  # de-dup, preserve order

        def extract_mx(items: list[dict[str, Any]]) -> list[DnsRecordMx]:
            out: list[DnsRecordMx] = []
            mx_min_parts = 2
            for it in items:
                v = it.get("data")
                if isinstance(v, str):
                    # e.g., "10 mail.example.com."
                    parts = v.split()
                    if len(parts) >= mx_min_parts and parts[0].isdigit():
                        out.append(
                            DnsRecordMx(preference=int(parts[0]), exchange=parts[1].rstrip("."))
                        )
            # stable sort by preference then name
            out.sort(key=lambda x: (x.preference, x.exchange))
            return out

        result = DomainDns(
            a=extract_values(a, field="data") or None,
            aaaa=extract_values(aaaa, field="data") or None,
            cname=extract_values(cname, field="data") or None,
            ns=extract_values(ns, field="data") or None,
            mx=extract_mx(mx) or None,
            txt=extract_values(txt, field="data") or None,
        )
        # If nothing resolved, return None
        if not any([result.a, result.aaaa, result.cname, result.ns, result.mx, result.txt]):
            return None
        return result
