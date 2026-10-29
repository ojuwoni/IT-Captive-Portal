"""Client admin Keycloak du reconciler — lecture seule, paginee.

Corrige deux defauts de la v1 :
- M4 : pagination (sans elle, les utilisateurs au-dela de la premiere page
  etaient revoques a tort) ;
- M5 : cache du token admin (expires_in etait calcule puis jamais applique).
"""
from __future__ import annotations

import time

import httpx


class KeycloakAdmin:
    def __init__(self, base_url: str, realm: str, client_id: str,
                 client_secret: str, timeout: float = 15.0,
                 page_size: int = 100):
        self.PAGE = page_size
        self._base = base_url.rstrip("/")
        self._realm = realm
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = timeout
        self._token: str | None = None
        self._token_exp: float = 0.0
        self._portal_client_uuid: str | None = None

    async def _get_token(self, client: httpx.AsyncClient) -> str:
        if self._token and time.time() < self._token_exp:
            return self._token
        resp = await client.post(
            f"{self._base}/realms/{self._realm}/protocol/openid-connect/token",
            data={"grant_type": "client_credentials",
                  "client_id": self._client_id,
                  "client_secret": self._client_secret},
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self._token_exp = time.time() + data.get("expires_in", 300) - 30
        return self._token

    async def _get(self, client: httpx.AsyncClient, path: str, **params):
        token = await self._get_token(client)
        resp = await client.get(
            f"{self._base}/admin/realms/{self._realm}{path}",
            headers={"Authorization": f"Bearer {token}"}, params=params,
        )
        resp.raise_for_status()
        return resp.json()

    async def active_usernames(self, portal_client_id: str) -> set[str]:
        """Utilisateurs ayant une session active sur le client du portail."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            if self._portal_client_uuid is None:
                found = await self._get(client, "/clients",
                                        clientId=portal_client_id)
                if not found:
                    return set()
                self._portal_client_uuid = found[0]["id"]
            users: set[str] = set()
            first = 0
            while True:
                page = await self._get(
                    client,
                    f"/clients/{self._portal_client_uuid}/user-sessions",
                    first=first, max=self.PAGE,
                )
                for session in page:
                    name = session.get("username")
                    if name:
                        users.add(name)
                if len(page) < self.PAGE:
                    return users
                first += self.PAGE
