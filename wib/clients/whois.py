from __future__ import annotations

import asyncio
import contextlib
import re
from collections.abc import Iterable
from datetime import datetime

from ..models.common import DomainWhois


class Port43WhoisClient:
    """Minimal WHOIS client over port 43.

    Strategy:
    - Resolve registry WHOIS server via whois.iana.org using the TLD.
    - Query the resolved server with the full domain name.
    - Parse a small set of common fields into DomainWhois.

    Notes:
    - This is best-effort; formats vary widely across registries.
    - Timeouts are enforced per socket operation via asyncio.wait_for.
    """

    def __init__(self, *, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def _query(self, server: str, query: str) -> str:
        reader: asyncio.StreamReader
        writer: asyncio.StreamWriter
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, 43), timeout=self.timeout
        )
        try:
            # WHOIS protocol expects CRLF and ASCII; many servers tolerate LF. Use CRLF and latin-1.
            writer.write((query + "\r\n").encode("latin-1", errors="ignore"))
            await asyncio.wait_for(writer.drain(), timeout=self.timeout)
            chunks: list[bytes] = []
            # Cap to ~1MB to avoid runaway reads
            max_bytes = 1024 * 1024
            total = 0
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=self.timeout)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_bytes:
                    break
            return b"".join(chunks).decode("latin-1", errors="replace")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    @staticmethod
    def _tld(domain: str) -> str:
        parts = domain.lower().strip().strip(".").split(".")
        return parts[-1] if parts else domain

    async def _resolve_server_for_domain(self, domain: str) -> str | None:
        # First ask IANA for TLD -> whois server mapping
        tld = self._tld(domain)
        try:
            resp = await self._query("whois.iana.org", tld)
        except Exception:
            return None
        # Look for a line like: "whois:        whois.verisign-grs.com"
        for line in resp.splitlines():
            if line.lower().startswith("whois:"):
                server = line.split(":", 1)[1].strip()
                if server:
                    return server
        # Some IANA responses include refer:
        for line in resp.splitlines():
            if line.lower().startswith("refer:"):
                server = line.split(":", 1)[1].strip()
                if server:
                    return server
        return None

    @staticmethod
    def _parse_dt(value: str | None) -> datetime | None:
        if not value:
            return None
        # Try a few common formats
        formats: Iterable[str] = (
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%d-%b-%Y",
            "%Y-%m-%d",
        )
        for fmt in formats:
            try:
                return datetime.strptime(value, fmt)
            except Exception:
                continue
        # Fallback: try to parse ISO-ish by replacing Z
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None

    @staticmethod
    def _find_first(patterns: list[re.Pattern[str]], text: str) -> str | None:
        for pat in patterns:
            m = pat.search(text)
            if m:
                return m.group(1).strip()
        return None

    @staticmethod
    def _find_all(patterns: list[re.Pattern[str]], text: str) -> list[str]:
        values: list[str] = []
        for pat in patterns:
            for m in pat.finditer(text):
                v = m.group(1).strip().lower()
                if v:
                    values.append(v)
        # De-dup while preserving order
        seen: set[str] = set()
        out: list[str] = []
        for v in values:
            if v not in seen:
                seen.add(v)
                out.append(v)
        return out

    def _parse_whois_text(self, domain: str, text: str) -> DomainWhois:
        # Common fields across registries
        registrar = self._find_first(
            [
                re.compile(r"^Registrar:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
                re.compile(r"^Sponsoring Registrar:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
                re.compile(r"^Registrar Name:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
            ],
            text,
        )

        nameservers = self._find_all(
            [
                re.compile(r"^Name Server:\s*([^\s#;]+)", re.IGNORECASE | re.MULTILINE),
                re.compile(r"^nserver:\s*([^\s#;]+)", re.IGNORECASE | re.MULTILINE),
            ],
            text,
        )

        created_raw = self._find_first(
            [
                re.compile(r"^Creation Date:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
                re.compile(r"^Registered on:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
                re.compile(r"^Created:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
            ],
            text,
        )
        updated_raw = self._find_first(
            [
                re.compile(r"^Updated Date:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
                re.compile(r"^Last Updated on:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
                re.compile(r"^Last Modified:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
            ],
            text,
        )
        expires_raw = self._find_first(
            [
                re.compile(r"^Registry Expiry Date:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
                re.compile(r"^Expiry Date:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
                re.compile(r"^Expires:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
                re.compile(r"^paid-till:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
            ],
            text,
        )

        dnssec_raw = self._find_first(
            [
                re.compile(r"^DNSSEC:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
            ],
            text,
        )
        dnssec: bool | None
        if dnssec_raw is None:
            dnssec = None
        else:
            v = dnssec_raw.strip().lower()
            dnssec = v.startswith("signed") or v in {"yes", "true", "ds present"}

        return DomainWhois(
            domain=domain,
            registrar=registrar or None,
            nameservers=nameservers or None,
            dnssec=dnssec,
            created=self._parse_dt(created_raw),
            updated=self._parse_dt(updated_raw),
            expires=self._parse_dt(expires_raw),
        )

    async def fetch(self, domain: str) -> DomainWhois | None:
        try:
            server = await self._resolve_server_for_domain(domain)
            if not server:
                return None
            text = await self._query(server, domain)
            if not text.strip():
                return None
            return self._parse_whois_text(domain, text)
        except Exception:
            return None
