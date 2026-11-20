"""Jeton d'IP : transmission de l'IP reelle de la jambe HTTP a la jambe HTTPS."""
import time

import fakeredis.aioredis
import pytest
from starlette.testclient import TestClient

from app import main
from app.security import make_ip_token, read_ip_token

INGRESS = "10.42.0.7"     # pair direct du portail
SNAT = "10.42.12.0"       # ce que l'ingress voit comme source
CLIENT = "10.24.127.21"   # etudiant du campus UAC


# ------------------------------------------------------------ unitaires
def test_jeton_aller_retour():
    assert read_ip_token("s3cret", make_ip_token("s3cret", CLIENT), 300) == CLIENT


def test_jeton_modifie_rejete():
    token = make_ip_token("s3cret", CLIENT)
    assert read_ip_token("s3cret", token[:-2] + "xx", 300) is None
    assert read_ip_token("s3cret", "nimporte-quoi", 300) is None


def test_jeton_signe_avec_une_autre_cle_rejete():
    assert read_ip_token("s3cret", make_ip_token("autre-cle", CLIENT), 300) is None


def test_jeton_expire_rejete():
    token = make_ip_token("s3cret", CLIENT)
    time.sleep(2.1)
    assert read_ip_token("s3cret", token, 1) is None


# ------------------------------------------------------------ parcours
class _FromIngress:
    """Fait arriver les requetes de test depuis le pod de l'ingress."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope = dict(scope, client=(INGRESS, 40000))
        await self.app(scope, receive, send)


@pytest.fixture()
def client(monkeypatch):
    fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(main.authz.store, "_r", fake)
    monkeypatch.setattr(main.settings, "bounce_url", "")
    return TestClient(_FromIngress(main.app), follow_redirects=False,
                      base_url="https://portal.rber.bj")


def https(extra=None):
    h = {"host": "portal.rber.bj", "x-forwarded-for": SNAT,
         "x-forwarded-proto": "https"}
    h.update(extra or {})
    return h


def intercept(client, xff=f"{CLIENT}, {SNAT}"):
    """Jambe HTTP : requete interceptee par le pfSense (Host etranger)."""
    return client.get("http://neverssl.com/", headers={
        "host": "neverssl.com", "x-forwarded-for": xff})


def test_jambe_http_delivre_un_jeton(client):
    r = intercept(client)
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith("https://portal.rber.bj/?campus=uac&t=")
    token = loc.split("&t=")[1]
    assert read_ip_token(main.SECRET, token, 300) == CLIENT


def test_hors_campus_pas_de_jeton(client):
    r = intercept(client, xff=f"197.234.1.9, {SNAT}")
    assert r.headers["location"] == "https://portal.rber.bj/?nb=1"


def test_jambe_https_avec_jeton_affiche_la_connexion(client):
    token = intercept(client).headers["location"].split("&t=")[1]
    r = client.get(f"/?campus=uac&t={token}", headers=https())
    assert r.status_code == 200
    assert "Se connecter avec" in r.text
    assert CLIENT in r.text                      # l'IP reelle est retrouvee


def test_jambe_https_sans_jeton_hors_reseau(client):
    r = client.get("/?campus=uac", headers=https())
    assert "ne provient pas" in r.text


def test_jeton_falsifie_hors_reseau(client):
    r = client.get("/?campus=uac&t=faux.jeton.signe", headers=https())
    assert "ne provient pas" in r.text


def test_la_session_se_souvient_du_jeton(client):
    token = intercept(client).headers["location"].split("&t=")[1]
    client.get(f"/?campus=uac&t={token}", headers=https())
    # requete suivante sans jeton (ex. clic sur le bouton) : cookie de session
    r = client.get("/?campus=uac", headers=https())
    assert "Se connecter avec" in r.text


def test_xff_forge_en_https_ne_remplace_pas_le_jeton(client):
    # la faille du 21/11 ne doit pas revenir par un autre chemin
    r = client.get("/?campus=uac", headers=https({"x-forwarded-for": f"10.24.5.5, {SNAT}"}))
    assert "ne provient pas" in r.text


def test_renvoi_http_si_configure(client, monkeypatch):
    monkeypatch.setattr(main.settings, "bounce_url", "http://captive.rber.bj/")
    r = client.get("/", headers=https())
    assert r.status_code == 302 and r.headers["location"] == "http://captive.rber.bj/"
    # deja renvoye une fois (nb=1) : pas de boucle
    r = client.get("/?nb=1", headers=https())
    assert r.status_code == 200 and "ne provient pas" in r.text
