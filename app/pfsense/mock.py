"""Mock en memoire du client pfSense — developpement et tests."""
from __future__ import annotations

import asyncio

from .base import PfSenseClient


class MockPfSenseClient(PfSenseClient):
    def __init__(self, arp: dict[str, str] | None = None, latency: float = 0.0):
        self.alias: set[str] = set()
        self.arp: dict[str, str] = dict(arp or {})
        self.applied = 0
        self._latency = latency

    async def _wait(self):
        if self._latency:
            await asyncio.sleep(self._latency)

    async def get_alias_ips(self) -> list[str]:
        await self._wait()
        return sorted(self.alias)

    async def add_ip(self, ip: str) -> None:
        await self._wait()
        self.alias.add(ip)

    async def remove_ip(self, ip: str) -> None:
        await self._wait()
        self.alias.discard(ip)

    async def apply(self) -> None:
        await self._wait()
        self.applied += 1

    async def get_arp_table(self) -> dict[str, str]:
        await self._wait()
        return dict(self.arp)

    async def ping(self) -> bool:
        return True
