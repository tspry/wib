from __future__ import annotations

from http import HTTPStatus
from typing import Any

from ..http.request import RequestManager
from ..models.common import IpGeo


class IpWhoisClient:
    """Free IP geolocation/ASN via ipwho.is API.

    Docs: https://ipwho.is/
    """

    BASE = "https://ipwho.is/"

    def __init__(self, rm: RequestManager) -> None:
        self.rm = rm

    async def fetch(self, ip: str) -> IpGeo | None:
        resp = await self.rm.get(f"{self.BASE}{ip}")
        if resp.status_code != HTTPStatus.OK:
            return None
        data: dict[str, Any] = resp.json()
        if not data.get("success", True):
            return None
        asn = None
        if isinstance(data.get("connection"), dict):
            asn = data["connection"].get("asn")
            isp = data["connection"].get("isp")
        else:
            isp = (
                data.get("connection", {}).get("isp")
                if isinstance(data.get("connection"), dict)
                else None
            )
        domain = data.get("domain") or None
        return IpGeo(
            ip=ip,
            asn=str(asn) if asn else None,
            org=data.get("org") or None,
            isp=isp or None,
            country=data.get("country") or None,
            region=data.get("region") or None,
            city=data.get("city") or None,
            lat=data.get("latitude"),
            lon=data.get("longitude"),
            domain=domain,
        )
