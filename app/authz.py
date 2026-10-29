"""Service d'autorisation : le coeur du cycle de vie (DAT v2.1 par. 6).

autorise(ip)  : verrou campus -> ajout alias -> apply -> session Redis
revoque(ip)   : verrou campus -> retrait alias -> apply -> suppression session
mac_for(ip)   : MAC via table ARP du pfSense, cachee (45 s par defaut)
"""
from __future__ import annotations

import json
import logging
import sys
import time

from .config import CampusConfig, Settings
from .pfsense.base import PfSenseClient
from .sessions import ArpCache, CampusLock, SessionStore

log = logging.getLogger("portal.authz")


def jlog(event: str, **fields) -> None:
    """Journal structure JSON (obligation de tracabilite, DAT par. 12)."""
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "event": event, **fields}
    print(json.dumps(record, ensure_ascii=False), file=sys.stdout, flush=True)


class AuthorizationService:
    def __init__(self, redis, settings: Settings,
                 client_factory):
        """client_factory(campus: CampusConfig) -> PfSenseClient"""
        self._redis = redis
        self._settings = settings
        self._factory = client_factory
        self.store = SessionStore(redis, settings.session_ttl)
        self._arp = ArpCache(redis, settings.arp_cache_ttl)

    def client_for(self, campus: CampusConfig) -> PfSenseClient:
        return self._factory(campus)

    async def mac_for(self, campus: CampusConfig, ip: str,
                      refresh: bool = False) -> str | None:
        table = None if refresh else await self._arp.get(campus.id)
        if table is None:
            table = await self.client_for(campus).get_arp_table()
            await self._arp.put(campus.id, table)
        mac = table.get(ip)
        if mac is None and not refresh:
            # l'entree peut etre plus recente que le cache : un seul refresh
            return await self.mac_for(campus, ip, refresh=True)
        return mac

    async def authorize(self, campus: CampusConfig, ip: str,
                        username: str, email: str = "") -> dict:
        mac = await self.mac_for(campus, ip)
        client = self.client_for(campus)
        async with CampusLock(self._redis, campus.id,
                              self._settings.campus_lock_ttl_ms):
            await client.add_ip(ip)
            await client.apply()
        session = {"user": username, "email": email, "mac": mac,
                   "login_time": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                               time.gmtime())}
        await self.store.save(campus.id, ip, session)
        jlog("authorize", campus=campus.id, ip=ip, mac=mac, user=username)
        return session

    async def revoke(self, campus: CampusConfig, ip: str,
                     reason: str = "logout") -> None:
        client = self.client_for(campus)
        async with CampusLock(self._redis, campus.id,
                              self._settings.campus_lock_ttl_ms):
            await client.remove_ip(ip)
            await client.apply()
        session = await self.store.get(campus.id, ip)
        await self.store.delete(campus.id, ip)
        jlog("revoke", campus=campus.id, ip=ip, reason=reason,
             user=(session or {}).get("user"))
