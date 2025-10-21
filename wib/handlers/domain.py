from __future__ import annotations

from ..clients.rdap import RdapClient
from ..http.request import RequestManager, RequestSettings
from ..models.common import DomainData


class DomainHandler:
    def __init__(self, *, timeout: float = 10.0) -> None:
        self.rm = RequestManager(RequestSettings(timeout=timeout))
        self.rdap = RdapClient(self.rm)

    async def fetch(self, domain: str) -> DomainData:
        whois = await self.rdap.fetch(domain)
        return DomainData(domain=domain, whois=whois)

    async def aclose(self) -> None:
        await self.rm.aclose()
