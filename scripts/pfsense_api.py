#!/usr/bin/env python3
"""
scripts/pfsense_api.py
Client pour l'API pfSense (pfSense-pkg-API ou fauxapi)

Fonctionnalites:
- Recuperer la MAC d'un client depuis les DHCP Leases
- Ajouter/supprimer des MACs dans un Alias pfSense
- Appliquer les changements de firewall

Usage:
  python pfsense_api.py get-mac --ip 10.0.0.50
  python pfsense_api.py add-mac --mac AA:BB:CC:DD:EE:FF
  python pfsense_api.py remove-mac --mac AA:BB:CC:DD:EE:FF
  python pfsense_api.py list-macs
  python pfsense_api.py test
"""

import argparse
import logging
import sys
from typing import Optional, List
from datetime import datetime

import httpx

# Ajouter le repertoire parent au path
sys.path.insert(0, '/opt/captive-portal')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PfSenseAPIError(Exception):
    """Exception pour les erreurs API pfSense."""
    pass


class PfSenseClient:
    """
    Client pour l'API pfSense.

    Supporte deux modes:
    - pfSense-pkg-API (package officiel)
    - FauxAPI (alternative populaire)

    La detection est automatique basee sur la reponse.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        verify_ssl: bool = False,
        alias_name: str = "authorized_macs"
    ):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.api_secret = api_secret
        self.verify_ssl = verify_ssl
        self.alias_name = alias_name
        self.api_mode: Optional[str] = None  # 'pkg-api' ou 'fauxapi'

    def _get_headers(self) -> dict:
        """Retourne les headers d'authentification selon le mode API."""
        if self.api_mode == 'fauxapi':
            # FauxAPI utilise un format different
            import hashlib
            import time
            timestamp = str(int(time.time()))
            nonce = hashlib.sha256(f"{timestamp}{self.api_secret}".encode()).hexdigest()[:8]
            auth_hash = hashlib.sha256(
                f"{self.api_secret}{timestamp}{nonce}".encode()
            ).hexdigest()
            return {
                "fauxapi-auth": f"{self.api_key}:{timestamp}:{nonce}:{auth_hash}"
            }
        else:
            # pfSense-pkg-API
            return {
                "Authorization": f"{self.api_key} {self.api_secret}",
                "Content-Type": "application/json"
            }

    async def _detect_api_mode(self, client: httpx.AsyncClient) -> str:
        """Detecte le type d'API pfSense installe."""
        # Essayer pfSense-pkg-API d'abord
        try:
            response = await client.get(
                f"{self.base_url}/api/v1/system/version",
                headers={"Authorization": f"{self.api_key} {self.api_secret}"}
            )
            if response.status_code == 200:
                self.api_mode = 'pkg-api'
                logger.info("Mode API detecte: pfSense-pkg-API")
                return 'pkg-api'
        except Exception:
            pass

        # Essayer FauxAPI
        try:
            response = await client.get(
                f"{self.base_url}/fauxapi/v1/?action=system_info",
                headers=self._get_headers()
            )
            if response.status_code == 200:
                self.api_mode = 'fauxapi'
                logger.info("Mode API detecte: FauxAPI")
                return 'fauxapi'
        except Exception:
            pass

        raise PfSenseAPIError(
            "Impossible de detecter le type d'API pfSense. "
            "Verifier que pfSense-pkg-API ou FauxAPI est installe."
        )

    async def test_connection(self) -> bool:
        """Teste la connexion a l'API pfSense."""
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=10) as client:
            try:
                await self._detect_api_mode(client)
                logger.info(f"Connexion pfSense OK ({self.api_mode})")
                return True
            except Exception as e:
                logger.error(f"Connexion pfSense echouee: {e}")
                return False

    async def get_dhcp_leases(self) -> List[dict]:
        """Recupere tous les baux DHCP."""
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30) as client:
            if not self.api_mode:
                await self._detect_api_mode(client)

            if self.api_mode == 'pkg-api':
                response = await client.get(
                    f"{self.base_url}/api/v1/services/dhcpd/lease",
                    headers=self._get_headers()
                )
            else:  # fauxapi
                response = await client.get(
                    f"{self.base_url}/fauxapi/v1/?action=system_stats",
                    headers=self._get_headers()
                )

            if response.status_code != 200:
                raise PfSenseAPIError(f"Erreur DHCP leases: {response.status_code}")

            data = response.json()

            if self.api_mode == 'pkg-api':
                return data.get('data', [])
            else:
                # FauxAPI structure differente
                return data.get('data', {}).get('dhcp_leases', [])

    async def get_mac_from_ip(self, ip: str) -> Optional[str]:
        """
        Recupere l'adresse MAC associee a une IP depuis les baux DHCP.

        Args:
            ip: Adresse IP du client

        Returns:
            Adresse MAC en majuscules (AA:BB:CC:DD:EE:FF) ou None
        """
        try:
            leases = await self.get_dhcp_leases()

            for lease in leases:
                lease_ip = lease.get('ip') or lease.get('address')
                if lease_ip == ip:
                    mac = lease.get('mac') or lease.get('hwaddr')
                    if mac:
                        # Normaliser le format MAC
                        return mac.upper().replace('-', ':')

            logger.warning(f"Aucun bail DHCP trouve pour IP {ip}")
            return None

        except Exception as e:
            logger.error(f"Erreur recuperation MAC pour {ip}: {e}")
            return None

    async def get_alias(self) -> dict:
        """Recupere l'Alias des MACs autorisees."""
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30) as client:
            if not self.api_mode:
                await self._detect_api_mode(client)

            if self.api_mode == 'pkg-api':
                response = await client.get(
                    f"{self.base_url}/api/v1/firewall/alias",
                    headers=self._get_headers(),
                    params={"name": self.alias_name}
                )
            else:  # fauxapi
                response = await client.get(
                    f"{self.base_url}/fauxapi/v1/?action=config_get&config_path=aliases",
                    headers=self._get_headers()
                )

            if response.status_code != 200:
                raise PfSenseAPIError(f"Erreur get alias: {response.status_code}")

            data = response.json()

            if self.api_mode == 'pkg-api':
                aliases = data.get('data', [])
                for alias in aliases:
                    if alias.get('name') == self.alias_name:
                        return alias
            else:
                aliases = data.get('data', {}).get('config', {}).get('aliases', {}).get('alias', [])
                if isinstance(aliases, dict):
                    aliases = [aliases]
                for alias in aliases:
                    if alias.get('name') == self.alias_name:
                        return alias

            return {}

    async def get_authorized_macs(self) -> List[str]:
        """Recupere la liste des MACs autorisees."""
        alias = await self.get_alias()

        if not alias:
            return []

        # Le champ peut etre 'address' (string avec espaces) ou 'detail'
        addresses = alias.get('address', '') or alias.get('detail', '')

        if isinstance(addresses, str):
            return [mac.strip().upper() for mac in addresses.split() if mac.strip()]
        elif isinstance(addresses, list):
            return [mac.upper() for mac in addresses]

        return []

    async def add_mac_to_alias(self, mac: str, description: str = "") -> bool:
        """
        Ajoute une MAC a l'Alias des autorisees.

        Args:
            mac: Adresse MAC (format AA:BB:CC:DD:EE:FF)
            description: Description optionnelle (username)

        Returns:
            True si succes
        """
        mac = mac.upper().replace('-', ':')

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30) as client:
            if not self.api_mode:
                await self._detect_api_mode(client)

            # Recuperer l'alias actuel
            current_macs = await self.get_authorized_macs()

            if mac in current_macs:
                logger.info(f"MAC {mac} deja dans l'alias")
                return True

            # Ajouter la nouvelle MAC
            current_macs.append(mac)

            if self.api_mode == 'pkg-api':
                # Mettre a jour via PUT
                response = await client.put(
                    f"{self.base_url}/api/v1/firewall/alias",
                    headers=self._get_headers(),
                    json={
                        "name": self.alias_name,
                        "type": "host",
                        "address": current_macs,
                        "descr": f"MACs autorisees par portail captif",
                        "detail": [description or f"Added {datetime.now().isoformat()}"] * len(current_macs),
                        "apply": True
                    }
                )
            else:  # fauxapi
                # FauxAPI necessite de modifier la config complete
                response = await client.post(
                    f"{self.base_url}/fauxapi/v1/?action=config_patch",
                    headers=self._get_headers(),
                    json={
                        "aliases": {
                            "alias": {
                                "name": self.alias_name,
                                "type": "host",
                                "address": " ".join(current_macs),
                                "descr": "MACs autorisees par portail captif"
                            }
                        }
                    }
                )

            if response.status_code not in [200, 201]:
                logger.error(f"Erreur ajout MAC: {response.status_code} - {response.text}")
                return False

            # Appliquer les changements firewall
            await self._apply_changes(client)

            logger.info(f"MAC {mac} ajoutee a l'alias {self.alias_name}")
            return True

    async def remove_mac_from_alias(self, mac: str) -> bool:
        """
        Supprime une MAC de l'Alias.

        Args:
            mac: Adresse MAC a supprimer

        Returns:
            True si succes
        """
        mac = mac.upper().replace('-', ':')

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30) as client:
            if not self.api_mode:
                await self._detect_api_mode(client)

            # Recuperer l'alias actuel
            current_macs = await self.get_authorized_macs()

            if mac not in current_macs:
                logger.info(f"MAC {mac} pas dans l'alias")
                return True

            # Retirer la MAC
            current_macs.remove(mac)

            if self.api_mode == 'pkg-api':
                response = await client.put(
                    f"{self.base_url}/api/v1/firewall/alias",
                    headers=self._get_headers(),
                    json={
                        "name": self.alias_name,
                        "type": "host",
                        "address": current_macs,
                        "descr": "MACs autorisees par portail captif",
                        "apply": True
                    }
                )
            else:  # fauxapi
                response = await client.post(
                    f"{self.base_url}/fauxapi/v1/?action=config_patch",
                    headers=self._get_headers(),
                    json={
                        "aliases": {
                            "alias": {
                                "name": self.alias_name,
                                "type": "host",
                                "address": " ".join(current_macs),
                                "descr": "MACs autorisees par portail captif"
                            }
                        }
                    }
                )

            if response.status_code not in [200, 201]:
                logger.error(f"Erreur suppression MAC: {response.status_code}")
                return False

            # Appliquer les changements
            await self._apply_changes(client)

            logger.info(f"MAC {mac} supprimee de l'alias {self.alias_name}")
            return True

    async def _apply_changes(self, client: httpx.AsyncClient) -> bool:
        """Applique les changements de configuration (reload firewall)."""
        try:
            if self.api_mode == 'pkg-api':
                response = await client.post(
                    f"{self.base_url}/api/v1/firewall/apply",
                    headers=self._get_headers()
                )
            else:  # fauxapi
                response = await client.post(
                    f"{self.base_url}/fauxapi/v1/?action=send_event&event=filter reload",
                    headers=self._get_headers()
                )

            if response.status_code in [200, 201]:
                logger.info("Changements firewall appliques")
                return True
            else:
                logger.warning(f"Erreur apply firewall: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Erreur apply changes: {e}")
            return False


# Fonctions helper pour utilisation depuis main.py
async def get_pfsense_client():
    """Cree un client pfSense avec les settings."""
    from config.settings import settings

    return PfSenseClient(
        base_url=settings.pfsense_url,
        api_key=settings.pfsense_api_key,
        api_secret=settings.pfsense_api_secret,
        verify_ssl=settings.pfsense_verify_ssl,
        alias_name=settings.pfsense_alias_name
    )


async def authorize_mac_pfsense(mac: str, username: str) -> bool:
    """Autorise une MAC via l'API pfSense."""
    client = await get_pfsense_client()
    return await client.add_mac_to_alias(mac, description=username)


async def revoke_mac_pfsense(mac: str) -> bool:
    """Revoque une MAC via l'API pfSense."""
    client = await get_pfsense_client()
    return await client.remove_mac_from_alias(mac)


async def get_mac_from_pfsense(ip: str) -> Optional[str]:
    """Recupere la MAC d'une IP via les DHCP Leases pfSense."""
    client = await get_pfsense_client()
    return await client.get_mac_from_ip(ip)


# CLI
def main():
    parser = argparse.ArgumentParser(description="pfSense API Client")
    parser.add_argument("action", choices=["test", "get-mac", "add-mac", "remove-mac", "list-macs"])
    parser.add_argument("--ip", help="IP du client")
    parser.add_argument("--mac", help="Adresse MAC")
    parser.add_argument("--url", default="https://192.168.1.1", help="URL pfSense")
    parser.add_argument("--key", required=True, help="API key")
    parser.add_argument("--secret", required=True, help="API secret")
    parser.add_argument("--alias", default="authorized_macs", help="Nom de l'alias")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Desactiver verification SSL")

    args = parser.parse_args()

    import asyncio

    client = PfSenseClient(
        base_url=args.url,
        api_key=args.key,
        api_secret=args.secret,
        verify_ssl=not args.no_verify_ssl,
        alias_name=args.alias
    )

    async def run():
        if args.action == "test":
            success = await client.test_connection()
            print(f"Connexion: {'OK' if success else 'ECHEC'}")
            return 0 if success else 1

        elif args.action == "get-mac":
            if not args.ip:
                parser.error("--ip requis pour get-mac")
            mac = await client.get_mac_from_ip(args.ip)
            if mac:
                print(f"MAC pour {args.ip}: {mac}")
                return 0
            else:
                print(f"MAC non trouvee pour {args.ip}")
                return 1

        elif args.action == "add-mac":
            if not args.mac:
                parser.error("--mac requis pour add-mac")
            success = await client.add_mac_to_alias(args.mac)
            print(f"Ajout: {'OK' if success else 'ECHEC'}")
            return 0 if success else 1

        elif args.action == "remove-mac":
            if not args.mac:
                parser.error("--mac requis pour remove-mac")
            success = await client.remove_mac_from_alias(args.mac)
            print(f"Suppression: {'OK' if success else 'ECHEC'}")
            return 0 if success else 1

        elif args.action == "list-macs":
            macs = await client.get_authorized_macs()
            print(f"MACs autorisees ({len(macs)}):")
            for mac in macs:
                print(f"  - {mac}")
            return 0

    exit_code = asyncio.run(run())
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
