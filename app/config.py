"""Configuration du portail captif v2.

Deux sources :
- variables d'environnement / fichiers montes (Settings)
- table de routing multi-campus (routing.json, ConfigMap en production)
"""
from __future__ import annotations

import ipaddress
import json
import threading
from dataclasses import dataclass
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Portail Captif SSO RBER"
    public_base_url: str = "https://portal.rber.bj"
    secret_key: str = ""  # OBLIGATOIRE en production (cookie de session)
    debug: bool = False

    # Keycloak (RBERConnect)
    keycloak_url: str = "https://auth.rber.bj"
    keycloak_realm: str = "rber"
    keycloak_client_id: str = "captive-portal"
    keycloak_client_secret: str = ""
    keycloak_client_secret_file: str = ""  # prioritaire si present (Secret K8s)
    # Compte de service du reconciler (lecture seule)
    keycloak_admin_client_id: str = "portal-reconciler"
    keycloak_admin_client_secret: str = ""
    keycloak_admin_client_secret_file: str = ""

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Sessions / autorisations
    session_ttl: int = 28800          # duree d'autorisation (s) — 8 h
    campus_lock_ttl_ms: int = 5000    # verrou d'ecriture d'alias par campus
    campus_lock_retry_ms: int = 50    # attente entre deux essais de verrou
    arp_cache_ttl: int = 45           # cache des lectures ARP (secondes)
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 20   # /login et /callback, par IP
    keycloak_admin_page_size: int = 100  # pagination des sessions (reconciler)

    # Fichiers / repertoires
    routing_path: str = "config/routing.json"
    secrets_dir: str = "secrets"      # cles API pfSense (1 fichier par campus)
    themes_dir: str = "themes"
    templates_dir: str = "templates"
    static_dir: str = "static"

    # pfSense : "restv2" (production) ou "mock" (developpement sans firewall)
    pfsense_mode: str = "restv2"

    # Reseau
    trusted_proxies: str = "127.0.0.1/32,10.42.0.0/16"  # ingress RKE2 par defaut
    pfsense_verify_tls: bool = True
    pfsense_ca_bundle: str = ""       # CA interne RBER (chemin), sinon store systeme
    pfsense_timeout: float = 10.0

    def keycloak_secret(self) -> str:
        if self.keycloak_client_secret_file:
            return Path(self.keycloak_client_secret_file).read_text().strip()
        return self.keycloak_client_secret

    def keycloak_admin_secret(self) -> str:
        if self.keycloak_admin_client_secret_file:
            return Path(self.keycloak_admin_client_secret_file).read_text().strip()
        return self.keycloak_admin_client_secret

    @property
    def keycloak_issuer(self) -> str:
        return f"{self.keycloak_url}/realms/{self.keycloak_realm}"

    @property
    def keycloak_metadata_url(self) -> str:
        return f"{self.keycloak_issuer}/.well-known/openid-configuration"

    @property
    def public_host(self) -> str:
        return self.public_base_url.split("://", 1)[-1].split("/", 1)[0].lower()

    def trusted_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        nets = []
        for part in self.trusted_proxies.split(","):
            part = part.strip()
            if part:
                nets.append(ipaddress.ip_network(part, strict=False))
        return nets


@dataclass(frozen=True)
class CampusConfig:
    id: str
    site: str
    universite: str
    subnet: str
    pfsense_url: str
    pfsense_alias: str
    api_key_secret: str
    theme: str

    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.subnet, strict=False)

    def contains(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in self.network()
        except ValueError:
            return False


class CampusRouting:
    """Table de routing des campus, rechargee si le fichier change (ConfigMap)."""

    def __init__(self, path: str):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._mtime: float = -1.0
        self._campuses: dict[str, CampusConfig] = {}
        self.reload()

    def reload(self) -> None:
        mtime = self._path.stat().st_mtime
        with self._lock:
            if mtime == self._mtime:
                return
            raw = json.loads(self._path.read_text())
            self._campuses = {
                cid.lower(): CampusConfig(id=cid.lower(), **cfg)
                for cid, cfg in raw.items()
            }
            self._mtime = mtime

    def _fresh(self) -> dict[str, CampusConfig]:
        try:
            self.reload()
        except OSError:
            pass  # fichier momentanement absent : on garde la table courante
        return self._campuses

    def get(self, campus_id: str | None) -> CampusConfig | None:
        if not campus_id:
            return None
        return self._fresh().get(campus_id.strip().lower())

    def all(self) -> list[CampusConfig]:
        return list(self._fresh().values())

    def find_by_ip(self, ip: str) -> CampusConfig | None:
        for campus in self._fresh().values():
            if campus.contains(ip):
                return campus
        return None


settings = Settings()
