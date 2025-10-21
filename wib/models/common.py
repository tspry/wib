from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class IpGeo(BaseModel):
    ip: str
    asn: str | None = None
    org: str | None = None
    isp: str | None = None
    country: str | None = None
    region: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    domain: str | None = None


class IpData(BaseModel):
    ip: str
    geo: IpGeo | None = None
    # Optional provider-normalized blobs
    vt: dict[str, Any] | None = None
    shodan: dict[str, Any] | None = None
    greynoise: dict[str, Any] | None = None
    abuseipdb: dict[str, Any] | None = None
    urlhaus: dict[str, Any] | None = None


class DomainWhois(BaseModel):
    domain: str
    registrar: str | None = None
    nameservers: list[str] | None = None
    dnssec: bool | None = None
    created: datetime | None = None
    updated: datetime | None = None
    expires: datetime | None = None


class DnsRecordMx(BaseModel):
    preference: int
    exchange: str


class DomainDns(BaseModel):
    a: list[str] | None = None
    aaaa: list[str] | None = None
    cname: list[str] | None = None
    ns: list[str] | None = None
    mx: list[DnsRecordMx] | None = None
    txt: list[str] | None = None


class VtDomainSummary(BaseModel):
    categories: dict[str, str] | None = None
    reputation: int | None = None
    popularity_ranks: dict[str, int] | None = None
    resolutions: list[dict[str, Any]] | None = None


class DomainData(BaseModel):
    domain: str
    whois: DomainWhois | None = None
    dns: DomainDns | None = None
    vt: VtDomainSummary | None = None
    urlhaus: dict[str, Any] | None = None
