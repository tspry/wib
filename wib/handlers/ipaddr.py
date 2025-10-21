from __future__ import annotations

from ..clients.ipwhois import IpWhoisClient
from ..http.request import RequestManager, RequestSettings
from ..models.common import IpData


class IpAddressHandler:
    def __init__(self, *, timeout: float = 10.0) -> None:
        self.rm = RequestManager(RequestSettings(timeout=timeout))
        self.ipwhois = IpWhoisClient(self.rm)

    async def fetch(self, ip: str) -> IpData:
        geo = await self.ipwhois.fetch(ip)
        return IpData(ip=ip, geo=geo)

    async def aclose(self) -> None:
        await self.rm.aclose()
