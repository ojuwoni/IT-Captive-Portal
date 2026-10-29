"""Sessions d'autorisation (Redis, JSON) + verrous + cache ARP + rate limit.

Cle par IP : une autorisation = une IP (DAT v2.1 par. 6.1).
Stockage JSON (corrige le split(':') casse de la v1).
"""
from __future__ import annotations

import json
import time
import uuid

AUTH_PREFIX = "auth:"          # auth:<campus>:<ip> -> json
LOCK_PREFIX = "lock:campus:"   # verrou d'ecriture d'alias
ARP_PREFIX = "arp:"            # arp:<campus> -> json {ip: mac}
RATE_PREFIX = "rl:"


class SessionStore:
    def __init__(self, redis, ttl: int):
        self._r = redis
        self._ttl = ttl

    @staticmethod
    def _key(campus_id: str, ip: str) -> str:
        return f"{AUTH_PREFIX}{campus_id}:{ip}"

    async def save(self, campus_id: str, ip: str, data: dict) -> None:
        payload = dict(data, ip=ip, campus=campus_id,
                       expires_at=time.time() + self._ttl)
        await self._r.set(self._key(campus_id, ip), json.dumps(payload),
                          ex=self._ttl)

    async def get(self, campus_id: str, ip: str) -> dict | None:
        raw = await self._r.get(self._key(campus_id, ip))
        return json.loads(raw) if raw else None

    async def delete(self, campus_id: str, ip: str) -> None:
        await self._r.delete(self._key(campus_id, ip))

    async def all_for_campus(self, campus_id: str) -> dict[str, dict]:
        """{ip: session} — utilise par le reconciler."""
        out: dict[str, dict] = {}
        cursor = 0
        pattern = f"{AUTH_PREFIX}{campus_id}:*"
        while True:
            cursor, keys = await self._r.scan(cursor=cursor, match=pattern, count=200)
            for key in keys:
                raw = await self._r.get(key)
                if raw:
                    data = json.loads(raw)
                    out[data["ip"]] = data
            if cursor == 0:
                return out


class CampusLock:
    """Verrou Redis par campus pour serialiser les ecritures d'alias (M1)."""

    def __init__(self, redis, campus_id: str, ttl_ms: int):
        self._r = redis
        self._key = f"{LOCK_PREFIX}{campus_id}"
        self._ttl_ms = ttl_ms
        self._token = uuid.uuid4().hex

    async def __aenter__(self):
        deadline = time.monotonic() + (self._ttl_ms / 1000) * 3
        while True:
            if await self._r.set(self._key, self._token, nx=True, px=self._ttl_ms):
                return self
            if time.monotonic() > deadline:
                raise TimeoutError(f"verrou campus indisponible : {self._key}")
            import asyncio
            await asyncio.sleep(0.05)

    async def __aexit__(self, *exc):
        # liberation uniquement si on detient encore le verrou
        if await self._r.get(self._key) == self._token:
            await self._r.delete(self._key)


class ArpCache:
    """Cache des tables ARP par campus (M3 : proteger l'API pfSense)."""

    def __init__(self, redis, ttl: int):
        self._r = redis
        self._ttl = ttl

    async def get(self, campus_id: str) -> dict[str, str] | None:
        raw = await self._r.get(f"{ARP_PREFIX}{campus_id}")
        return json.loads(raw) if raw else None

    async def put(self, campus_id: str, table: dict[str, str]) -> None:
        await self._r.set(f"{ARP_PREFIX}{campus_id}", json.dumps(table),
                          ex=self._ttl)


class RateLimiter:
    """Compteur par IP et par minute, pour /login et /callback."""

    def __init__(self, redis, per_minute: int):
        self._r = redis
        self._limit = per_minute

    async def allow(self, ip: str) -> bool:
        key = f"{RATE_PREFIX}{ip}:{int(time.time() // 60)}"
        count = await self._r.incr(key)
        if count == 1:
            await self._r.expire(key, 90)
        return count <= self._limit
