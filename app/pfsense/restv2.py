"""Client REST API v2 (package pfrest — pfSense Plus).

Auth : header X-API-Key. Base URL AVEC le port de l'interface web
(ex. https://10.24.112.34:10443) — relevé A1 du 28/10.

Chemins VERIFIES contre l'OpenAPI officielle du package (pfrest.org,
api-docs/openapi.json, 29/10/2026) :
  - GET  /api/v2/status/system          (sante — PAS /system/status)
  - GET  /api/v2/firewall/aliases       (liste, champ address = tableau)
  - PATCH /api/v2/firewall/alias        (par id NUMERIQUE — le nom est
    refuse (404, releve T4) et l'id peut changer : toujours re-resolu par
    nom via /firewall/aliases avant ecriture, jamais code en dur)
  - POST /api/v2/firewall/apply   (DIFFERE : repond applied:false ;
    on sonde GET /firewall/apply jusqu'a applied:true — releve T4 : ~1,6 s)
  - GET  /api/v2/diagnostics/arp_table  (cles ip_address / mac_address)
Reste a confirmer sur le pfSense reel (T4) : codes de reponse et latences.
"""
from __future__ import annotations

import httpx

import asyncio

from .base import PfSenseClient, PfSenseError


class RestV2Client(PfSenseClient):
    def __init__(
        self,
        base_url: str,
        api_key: str,
        alias_name: str = "authorized_clients",
        verify: bool | str = True,
        timeout: float = 10.0,
    ):
        self._base = base_url.rstrip("/")
        self._alias_name = alias_name
        self._alias_id: int | None = None
        self._headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
        self._verify = verify
        self._timeout = timeout

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base, headers=self._headers,
            verify=self._verify, timeout=self._timeout,
        )

    @staticmethod
    def _data(resp: httpx.Response):
        if resp.status_code != 200:
            raise PfSenseError(f"HTTP {resp.status_code} sur {resp.request.url}: "
                               f"{resp.text[:200]}")
        body = resp.json()
        return body.get("data", body)

    async def _resolve_alias(self, client: httpx.AsyncClient) -> dict:
        data = self._data(await client.get("/api/v2/firewall/aliases"))
        for alias in data if isinstance(data, list) else []:
            if alias.get("name") == self._alias_name:
                self._alias_id = alias.get("id")
                return alias
        raise PfSenseError(f"alias {self._alias_name!r} introuvable sur {self._base}")

    async def get_alias_ips(self) -> list[str]:
        async with self._client() as client:
            alias = await self._resolve_alias(client)
            addresses = alias.get("address") or []
            if isinstance(addresses, str):  # tolerance ancien format
                addresses = addresses.split()
            return [a.strip() for a in addresses if a.strip()]

    async def _write_addresses(self, addresses: list[str]) -> None:
        async with self._client() as client:
            # l'id d'alias est numerique et peut changer (alias recree) :
            # re-resolution par nom a chaque ecriture (releve T4)
            await self._resolve_alias(client)
            resp = await client.patch(
                "/api/v2/firewall/alias",
                json={"id": self._alias_id,
                      "address": sorted(addresses),
                      "detail": ["portail captif SSO"] * len(addresses)},
            )
            self._data(resp)

    async def add_ip(self, ip: str) -> None:
        current = set(await self.get_alias_ips())
        if ip in current:
            return
        current.add(ip)
        await self._write_addresses(sorted(current))

    async def remove_ip(self, ip: str) -> None:
        current = set(await self.get_alias_ips())
        if ip not in current:
            return
        current.discard(ip)
        await self._write_addresses(sorted(current))

    APPLY_POLL_INTERVAL = 0.4   # releve T4 : effectif en ~1,6 s
    APPLY_POLL_TIMEOUT = 15.0

    async def apply(self) -> None:
        """Declenche l'application puis attend applied:true (apply differe)."""
        async with self._client() as client:
            data = self._data(await client.post("/api/v2/firewall/apply", json={}))
            if isinstance(data, dict) and data.get("applied") is True:
                return
            deadline = asyncio.get_event_loop().time() + self.APPLY_POLL_TIMEOUT
            while asyncio.get_event_loop().time() < deadline:
                await asyncio.sleep(self.APPLY_POLL_INTERVAL)
                data = self._data(await client.get("/api/v2/firewall/apply"))
                if isinstance(data, dict) and data.get("applied") is True:
                    return
            raise PfSenseError(
                f"apply non confirme apres {self.APPLY_POLL_TIMEOUT}s sur {self._base}")

    async def get_arp_table(self) -> dict[str, str]:
        async with self._client() as client:
            data = self._data(await client.get("/api/v2/diagnostics/arp_table"))
            table: dict[str, str] = {}
            for entry in data if isinstance(data, list) else []:
                ip = entry.get("ip_address") or entry.get("ip")
                mac = entry.get("mac_address") or entry.get("mac")
                if ip and mac:
                    table[ip] = mac.upper()
            return table

    async def ping(self) -> bool:
        try:
            async with self._client() as client:
                self._data(await client.get("/api/v2/status/system"))
            return True
        except Exception:
            return False
