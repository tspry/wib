from __future__ import annotations

import asyncio
import random
import time
from collections import defaultdict
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any

import httpx


def _compute_backoff(attempt: int, base: float = 0.2, cap: float = 5.0) -> float:
    exp: float = min(cap, base * (2**attempt))
    # jitter 50-100% (non-cryptographic)
    jitter: float = 0.5 + float(random.random()) * 0.5  # nosec B311
    return float(exp * jitter)


@dataclass
class RequestSettings:
    timeout: float = 10.0
    max_retries: int = 2
    user_agent: str = "wib/0.1.0"
    per_host_limit: int = 5


class RequestManager:
    def __init__(self, settings: RequestSettings | None = None) -> None:
        self.settings = settings or RequestSettings()
        self._client = httpx.AsyncClient(
            follow_redirects=True,
            headers={"User-Agent": self.settings.user_agent},
        )
        self._locks: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(self.settings.per_host_limit)
        )
        self._cache: dict[tuple[str, str], tuple[float, httpx.Response]] = {}

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cache: bool = True,
    ) -> httpx.Response:
        key = (url, str(params) if params else "")
        if cache and key in self._cache:
            return self._cache[key][1]

        host = httpx.URL(url).host or ""
        async with self._locks[host]:
            last_exc: Exception | None = None
            for attempt in range(self.settings.max_retries + 1):
                try:
                    resp = await self._client.get(
                        url, params=params, headers=headers, timeout=self.settings.timeout
                    )
                    if cache and resp.status_code == HTTPStatus.OK:
                        self._cache[key] = (time.time(), resp)
                    return resp
                except (httpx.TimeoutException, httpx.TransportError) as exc:
                    last_exc = exc
                    if attempt >= self.settings.max_retries:
                        raise
                    await asyncio.sleep(_compute_backoff(attempt))

        if last_exc is not None:
            raise last_exc
        # Defensive: we should have either returned or raised by now.
        raise RuntimeError("Request failed after retries")
