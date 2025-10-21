from __future__ import annotations

from ..clients.dns import DnsClient
from ..clients.ip2whois import Ip2WhoisClient
from ..clients.rdap import RdapClient
from ..clients.whois import Port43WhoisClient
from ..http.request import RequestManager, RequestSettings
from ..models.common import DomainData


class DomainHandler:
    def __init__(self, *, timeout: float = 10.0, ip2whois_key: str | None = None) -> None:
        self.rm = RequestManager(RequestSettings(timeout=timeout))
        self.rdap = RdapClient(self.rm)
        # Port 43 WHOIS does not use HTTP, so it doesn't need RequestManager
        self.port43 = Port43WhoisClient(timeout=timeout)
        self.dns = DnsClient(self.rm)
        self.ip2whois = Ip2WhoisClient(self.rm, ip2whois_key) if ip2whois_key else None

    async def fetch(self, domain: str, *, include_dns: bool = False) -> DomainData:
        whois = await self.rdap.fetch(domain)
        if whois is None:
            # Best-effort fallback to traditional WHOIS over port 43
            whois = await self.port43.fetch(domain)
        if whois is None and self.ip2whois is not None:
            # Optional paid API fallback if configured via env
            whois = await self.ip2whois.fetch(domain)
        dns = await self.dns.fetch(domain) if include_dns else None
        return DomainData(domain=domain, whois=whois, dns=dns)

    async def aclose(self) -> None:
        await self.rm.aclose()
