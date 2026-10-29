"""Client REST API v2 (package pfrest — pfSense Plus).

Auth : header X-API-Key. Base URL AVEC le port de l'interface web
(ex. https://10.24.112.34:10443) — relevé A1 du 28/10.

Chemins VERIFIES contre l'OpenAPI officielle du package (pfrest.org,
api-docs/openapi.json, 29/10/2026) :
  - GET  /api/v2/status/system          (sante — PAS /system/status)
  - GET  /api/v2/firewall/aliases       (liste, champ address = tableau)
  - PATCH /api/v2/firewall/alias        (par id — pas d'endpoint unitaire
    d'adresse : lecture + PATCH sous verrou campus, assume)
  - POST /api/v2/firewall/apply
  - GET  /api/v2/diagnostics/arp_table  (cles ip_address / mac_address)
Reste a confirmer sur le pfSense reel (T4) : codes de reponse et latences.
"""
from __future__ import annotations

import httpx

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
            if self._alias_id is None:
                await self._resolve_alias(client)
            resp = await client.patch(
                "/api/v2/firewall/alias",
                json={"id": self._alias_id, "address": sorted(addresses)},
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

    async def apply(self) -> None:
        async with self._client() as client:
            self._data(await client.post("/api/v2/firewall/apply", json={}))

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
