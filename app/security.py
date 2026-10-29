"""IP reelle du client et validation campus <-> subnet (DAT v2.1 par. 6.2)."""
from __future__ import annotations

import ipaddress

from .config import CampusConfig, CampusRouting, Settings


class CampusValidationError(Exception):
    """La requete est incoherente : campus inconnu ou IP hors subnet."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def client_ip(peer_ip: str, xff_header: str | None, settings: Settings) -> str:
    """IP reelle du client.

    X-Forwarded-For n'est cru que si la connexion vient d'un proxy de
    confiance (l'ingress, qui recoit l'IP d'origine via PROXY protocol).
    Un XFF envoye directement par un client est ignore (defaut M2 de l'audit).
    """
    if xff_header:
        try:
            peer = ipaddress.ip_address(peer_ip)
        except ValueError:
            return peer_ip
        if any(peer in net for net in settings.trusted_networks()):
            first = xff_header.split(",")[0].strip()
            try:
                ipaddress.ip_address(first)
                return first
            except ValueError:
                pass
    return peer_ip


def resolve_campus(
    campus_param: str | None, ip: str, routing: CampusRouting
) -> tuple[CampusConfig, bool]:
    """Retourne (campus, inferred).

    - campus declare + IP dans son subnet  -> ok
    - campus declare mais IP hors subnet   -> erreur (parametre falsifie/bogue)
    - pas de campus mais IP dans un subnet -> inference par l'IP (sondes CNA)
    - rien ne correspond                   -> erreur
    """
    declared = routing.get(campus_param)
    if campus_param and declared is None:
        raise CampusValidationError(f"campus inconnu : {campus_param!r}")
    if declared is not None:
        if declared.contains(ip):
            return declared, False
        raise CampusValidationError(
            f"IP {ip} hors du subnet du campus {declared.id} ({declared.subnet})"
        )
    inferred = routing.find_by_ip(ip)
    if inferred is not None:
        return inferred, True
    raise CampusValidationError(f"aucun campus pour l'IP {ip}")
