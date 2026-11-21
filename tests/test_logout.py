"""Parcours complet connexion -> deconnexion (OIDC et pfSense simules)."""
import time

import fakeredis.aioredis
import pytest
from starlette.responses import RedirectResponse
from starlette.testclient import TestClient

from app import main

INGRESS, SNAT, CLIENT = "10.42.0.7", "10.42.12.0", "10.24.127.28"


class _FromIngress:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope = dict(scope, client=(INGRESS, 40000))
        await self.app(scope, receive, send)


def https():
    return {"host": "portal.rber.bj", "x-forwarded-for": SNAT,
            "x-forwarded-proto": "https"}


@pytest.fixture()
def bench(monkeypatch):
    fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(main.authz, "_redis", fake)
    monkeypatch.setattr(main.authz.store, "_r", fake)
    monkeypatch.setattr(main.authz._arp, "_r", fake)
    monkeypatch.setattr(main.limiter, "_r", fake)
    monkeypatch.setattr(main.settings, "pfsense_mode", "mock")
    monkeypatch.setattr(main.settings, "bounce_url", "")
    main._mock_clients.clear()

    async def authorize_redirect(request, redirect_uri, **kw):
        return RedirectResponse("https://auth.rber.bj/login", status_code=302)

    async def authorize_access_token(request, **kw):
        return {"userinfo": {"preferred_username": "gildas", "email": "g@uac.bj"}}

    monkeypatch.setattr(main.oauth.keycloak, "authorize_redirect", authorize_redirect)
    monkeypatch.setattr(main.oauth.keycloak, "authorize_access_token", authorize_access_token)
    client = TestClient(_FromIngress(main.app), follow_redirects=False,
                        base_url="https://portal.rber.bj")
    return client


def connect(client):
    r = client.get("http://neverssl.com/", headers={
        "host": "neverssl.com", "x-forwarded-for": f"{CLIENT}, {SNAT}"})
    token = r.headers["location"].split("&t=")[1]
    assert client.get(f"/?campus=uac&t={token}", headers=https()).status_code == 200
    assert client.get("/login?campus=uac", headers=https()).status_code == 302
    r = client.get("/callback?code=x&state=y", headers=https())
    assert r.status_code == 302 and r.headers["location"] == "/success"
    return main._mock_clients["uac"]


def test_connexion_ouvre_l_acces(bench):
    pf = connect(bench)
    assert pf.alias == {CLIENT}
    r = bench.get("/success", headers=https())
    assert "Connexion reussie" in r.text and "gildas" in r.text


def test_deconnexion_immediate_ferme_l_acces(bench):
    pf = connect(bench)
    r = bench.get("/logout", headers=https())
    assert r.status_code == 200 and "deconnecte du reseau" in r.text
    assert pf.alias == set()


def test_deconnexion_apres_expiration_du_souvenir_du_jeton(bench, monkeypatch):
    # defaut du 21/11 : 27 minutes apres la connexion, la deconnexion
    # n'enlevait plus l'adresse de l'alias du pfSense
    pf = connect(bench)
    real = time.time
    monkeypatch.setattr(main.time, "time", lambda: real() + 27 * 60)
    r = bench.get("/logout", headers=https())
    assert "deconnecte du reseau" in r.text
    assert pf.alias == set()


def test_page_deja_connecte_apres_expiration(bench, monkeypatch):
    connect(bench)
    real = time.time
    monkeypatch.setattr(main.time, "time", lambda: real() + 27 * 60)
    r = bench.get("/", headers=https())
    assert "Deja connecte" in r.text and "gildas" in r.text


def test_deconnexion_ne_ferme_pas_l_acces_d_un_autre(bench, monkeypatch):
    # l'adresse a ete reattribuee a un autre utilisateur entre-temps :
    # la deconnexion du premier ne doit pas couper le second
    pf = connect(bench)
    import asyncio
    asyncio.get_event_loop().run_until_complete(
        main.authz.store.save("uac", CLIENT, {"user": "quelquun-d-autre"}))
    r = bench.get("/logout", headers=https())
    assert "Aucune connexion active" in r.text
    assert pf.alias == {CLIENT}


def test_deconnexion_sans_session(bench):
    r = bench.get("/logout", headers=https())
    assert r.status_code == 200 and "Aucune connexion active" in r.text
