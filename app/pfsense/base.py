"""Interface du client pfSense.

Le portail ne depend que de cette interface : l'implementation REST v2
(restv2.py) se branche sur les endpoints confirmes par le test A1, et le
mock (mock.py) permet de developper et tester sans firewall.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class PfSenseError(Exception):
    """Echec d'un appel a l'API pfSense (reseau, auth, reponse inattendue)."""


class PfSenseClient(ABC):
    @abstractmethod
    async def get_alias_ips(self) -> list[str]:
        """Contenu courant de l'alias authorized_clients."""

    @abstractmethod
    async def add_ip(self, ip: str) -> None:
        """Ajoute une IP a l'alias (sans apply)."""

    @abstractmethod
    async def remove_ip(self, ip: str) -> None:
        """Retire une IP de l'alias (sans apply)."""

    @abstractmethod
    async def apply(self) -> None:
        """Applique les changements firewall en attente."""

    @abstractmethod
    async def get_arp_table(self) -> dict[str, str]:
        """Table ARP du firewall : {ip: mac}."""

    @abstractmethod
    async def ping(self) -> bool:
        """L'API repond-elle ? (healthcheck / monitoring)"""
