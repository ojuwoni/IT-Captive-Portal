"""IP reelle du client et validation campus <-> subnet (DAT v2.1 par. 6.2)."""
from __future__ import annotations

import ipaddress

from itsdangerous import BadSignature, URLSafeTimedSerializer

from .config import CampusConfig, CampusRouting, Settings


class CampusValidationError(Exception):
    """La requete est incoherente : campus inconnu ou IP hors subnet."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _is_trusted(addr: str, settings: Settings) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in settings.trusted_networks())


def client_ip(peer_ip: str, xff_header: str | None, settings: Settings,
              forwarded_proto: str | None = None) -> str:
    """IP reelle du client, sans jamais croire ce que le client ecrit lui-meme.

    Chaque relais AJOUTE une adresse a la fin de X-Forwarded-For ; un client
    peut en ecrire au debut. On ne lit donc que la fin de la liste :

      [ ...ecrit par le client... , ajoute par le HAProxy externe , ajoute par l'ingress ]

    - Le dernier element est ce que l'ingress a vu comme source. S'il n'est
      pas un relais connu, c'est le client lui-meme.
    - S'il est un relais connu (HAProxy externe ou adresse de noeud), le
      client reel est l'element precedent — MAIS seulement sur la jambe
      HTTP, ou le HAProxy externe (mode http) l'a effectivement ajoute.
      Sur la jambe HTTPS (passthrough TCP) le HAProxy n'ajoute rien :
      l'element precedent serait ecrit par le client, donc on ne le croit pas.
    - L'appelant doit fournir TOUTES les lignes X-Forwarded-For jointes
      (un relais peut ajouter la sienne sur une ligne separee).

    Faille corrigee le 21/11/2026 : l'ancienne version lisait le PREMIER
    element, falsifiable depuis Internet.
    """
    if not xff_header or not _is_trusted(peer_ip, settings):
        return peer_ip
    chain = [p.strip() for p in xff_header.split(",") if p.strip()]
    if not chain:
        return peer_ip
    last = chain[-1]
    try:
        ipaddress.ip_address(last)
    except ValueError:
        return peer_ip
    if not _is_trusted(last, settings):
        return last
    # Jambe HTTPS : l'ingress impose toujours X-Forwarded-Proto=https (verifie
    # en production le 21/11 : une valeur forgee par le client est ecrasee).
    # Tout le reste (http, ou absent) est la jambe HTTP.
    proto = (forwarded_proto or "").split(",")[-1].strip().lower()
    if proto != "https" and len(chain) >= 2:
        prev = chain[-2]
        try:
            ipaddress.ip_address(prev)
            return prev
        except ValueError:
            pass
    return last


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


# ---------------------------------------------------------------- jeton d'IP
# Sur la jambe HTTP le portail connait l'IP reelle du client ; sur la jambe
# HTTPS (passthrough TCP) il ne voit que l'adresse d'un relais. Le portail
# se transmet donc l'IP a lui-meme, dans le lien de redirection, sous forme
# d'un jeton SIGNE et a duree courte : le client le transporte mais ne peut
# ni le fabriquer ni le modifier.
_TOKEN_SALT = "portal-client-ip-v1"


def make_ip_token(secret: str, ip: str) -> str:
    return URLSafeTimedSerializer(secret, salt=_TOKEN_SALT).dumps({"ip": ip})


def read_ip_token(secret: str, token: str, max_age: int) -> str | None:
    """IP contenue dans le jeton, ou None s'il est invalide, modifie ou expire."""
    try:
        data = URLSafeTimedSerializer(secret, salt=_TOKEN_SALT).loads(
            token, max_age=max_age)
        ip = data.get("ip") if isinstance(data, dict) else None
        ipaddress.ip_address(ip)
        return ip
    except (BadSignature, ValueError, TypeError):
        return None
