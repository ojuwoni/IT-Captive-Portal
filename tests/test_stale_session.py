"""Session en memoire alors que le pfSense n'a plus l'adresse (21/11)."""
import time

from app import main
from tests.test_logout import CLIENT, SNAT, bench, connect, https  # noqa: F401


def intercept(client):
    r = client.get("http://neverssl.com/", headers={
        "host": "neverssl.com", "x-forwarded-for": f"{CLIENT}, {SNAT}"})
    return r.headers["location"].split("&t=")[1]


def test_interception_juste_apres_connexion_ne_casse_rien(bench):
    connect(bench)
    r = bench.get(f"/?campus=uac&t={intercept(bench)}", headers=https())
    assert "Deja connecte" in r.text


def test_interception_tardive_efface_la_session_fausse(bench, monkeypatch):
    pf = connect(bench)
    pf.alias.clear()                      # retrait a la main cote pfSense
    monkeypatch.setattr(main.settings, "stale_session_grace", -5)
    r = bench.get(f"/?campus=uac&t={intercept(bench)}", headers=https())
    assert "Deja connecte" not in r.text and "/login" in r.text
    # la reconnexion repart de zero et rouvre l'acces
    assert bench.get("/login?campus=uac", headers=https()).status_code == 302
    assert bench.get("/callback?code=x&state=y", headers=https()).status_code == 302
    assert pf.alias == {CLIENT}


def test_vieux_jeton_d_avant_connexion_est_ignore(bench):
    old = intercept(bench)
    connect(bench)
    time.sleep(1.1)
    r = bench.get(f"/?campus=uac&t={old}", headers=https())
    assert "Deja connecte" in r.text
