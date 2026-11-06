"""Reconciliateur alias-first (DAT v2.1 par. 6.4 — corrige le bloquant B3).

La source de verite controlee est L'ALIAS de chaque pfSense :
  pour chaque IP presente dans l'alias :
    - pas de session Redis            -> IP orpheline : retrait immediat
    - session Redis mais plus de
      session Keycloak active         -> retrait + cloture de la session
    - la MAC de l'IP (table ARP) a
      change depuis l'authentification -> IP reattribuee a un autre
      appareil (bail DHCP recycle)    -> retrait + cloture  [mac_check]
    - IP absente de la table ARP
      depuis idle_grace_cycles cycles -> appareil parti     [inactivite]
Ce sens de parcours garantit qu'aucune IP ne reste autorisee sans session
valide ni presence reelle (TTL expire, crash, revocation Keycloak,
reattribution DHCP, depart du client).

Usage :
  python -m app.reconciler --once
  python -m app.reconciler --daemon --interval 300
En production : CronJob Kubernetes toutes les 5 minutes (--once).
"""
from __future__ import annotations

import argparse
import asyncio

import redis.asyncio as aioredis

from .authz import AuthorizationService, jlog
from .config import CampusConfig, CampusRouting, settings
from .keycloak_admin import KeycloakAdmin
from .main import make_client  # meme fabrique que le portail (mock incluse)
from .sessions import CampusLock


async def reconcile_campus(authz: AuthorizationService, redis,
                           campus: CampusConfig,
                           kc_active: set[str] | None) -> dict:
    client = authz.client_for(campus)
    alias_ips = await client.get_alias_ips()
    sessions = await authz.store.all_for_campus(campus.id)
    arp = await client.get_arp_table() if (
        settings.mac_check_enabled or settings.idle_grace_cycles > 0) else {}
    removed = {"orphan": [], "kc_expired": [], "ip_reassigned": [], "idle": []}

    async def _absence(ip: str) -> int:
        key = f"idle:{campus.id}:{ip}"
        count = await redis.incr(key)
        await redis.expire(key, 3600)
        return count

    changed = False
    async with CampusLock(redis, campus.id, settings.campus_lock_ttl_ms,
                          settings.campus_lock_retry_ms):
        for ip in alias_ips:
            session = sessions.get(ip)
            reason = None
            if session is None:
                reason = "orphan"
            elif kc_active is not None and session.get("user") not in kc_active:
                reason = "kc_expired"
            elif settings.mac_check_enabled and session.get("mac")                     and arp.get(ip) and arp[ip] != session["mac"]:
                # bail DHCP recycle : l'IP appartient a un autre appareil
                reason = "ip_reassigned"
            elif settings.idle_grace_cycles > 0 and ip not in arp:
                if await _absence(ip) >= settings.idle_grace_cycles:
                    reason = "idle"
            else:
                await redis.delete(f"idle:{campus.id}:{ip}")

            if reason:
                await client.remove_ip(ip)
                if session is not None:
                    await authz.store.delete(campus.id, ip)
                removed[reason].append(ip)
                changed = True
    if changed:
        await client.apply()

    result = {"campus": campus.id, "alias_count": len(alias_ips),
              "orphans_removed": len(removed["orphan"]),
              "kc_expired_removed": len(removed["kc_expired"]),
              "ip_reassigned_removed": len(removed["ip_reassigned"]),
              "idle_removed": len(removed["idle"])}
    jlog("reconcile", **result)
    return result


async def run_once() -> None:
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    routing = CampusRouting(settings.routing_path)
    authz = AuthorizationService(redis, settings, make_client)

    kc_active: set[str] | None = None
    admin_secret = settings.keycloak_admin_secret()
    if admin_secret:
        try:
            admin = KeycloakAdmin(settings.keycloak_url, settings.keycloak_realm,
                                  settings.keycloak_admin_client_id, admin_secret,
                                  page_size=settings.keycloak_admin_page_size)
            kc_active = await admin.active_usernames(settings.keycloak_client_id)
        except Exception as exc:
            # Keycloak injoignable : on ne revoque PAS en masse (prudence),
            # on ne purge que les orphelines.
            jlog("reconcile_kc_unreachable", error=str(exc)[:200])
            kc_active = None

    for campus in routing.all():
        try:
            await reconcile_campus(authz, redis, campus, kc_active)
        except Exception as exc:
            jlog("reconcile_error", campus=campus.id, error=str(exc)[:200])
    await redis.aclose()


async def run_daemon(interval: int) -> None:
    while True:
        await run_once()
        await asyncio.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconciliateur alias-first")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--interval", type=int, default=300)
    args = parser.parse_args()
    if args.daemon:
        asyncio.run(run_daemon(args.interval))
    else:
        asyncio.run(run_once())


if __name__ == "__main__":
    main()
