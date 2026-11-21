"""Coupure des connexions en cours au retrait (constat banc UAC 21/11)."""
import json

import httpx
import pytest

from app import main
from app.pfsense.restv2 import RestV2Client
from tests.test_logout import CLIENT, bench, connect, https  # noqa: F401


def test_deconnexion_coupe_les_connexions_en_cours(bench):
    pf = connect(bench)
    bench.get("/logout", headers=https())
    assert pf.alias == set() and pf.killed == [CLIENT]


def test_echec_de_coupure_ne_bloque_pas_la_deconnexion(bench, monkeypatch):
    pf = connect(bench)

    async def boom(ip):
        raise RuntimeError("API etats indisponible")

    monkeypatch.setattr(pf, "kill_states", boom)
    r = bench.get("/logout", headers=https())
    assert r.status_code == 200 and pf.alias == set()


def test_coupure_desactivable(bench, monkeypatch):
    monkeypatch.setattr(main.settings, "kill_states_on_revoke", False)
    pf = connect(bench)
    bench.get("/logout", headers=https())
    assert pf.killed == []


@pytest.mark.asyncio
async def test_requete_toujours_filtree_jamais_all(monkeypatch):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append((request.method, request.url.path, body))
        first = len(seen) == 1
        return httpx.Response(200, json={"data": [{"source": "x"}] if first else []})

    c = RestV2Client("https://pf", "k")
    monkeypatch.setattr(c, "_client", lambda: httpx.AsyncClient(
        base_url="https://pf", transport=httpx.MockTransport(handler)))
    assert await c.kill_states("10.24.1.2") == 1
    assert all(m == "DELETE" and p == "/api/v2/firewall/states" for m, p, _ in seen)
    for _, _, body in seen:
        assert "all" not in body
        assert body.get("source__startswith") == "10.24.1.2:" or body.get("source") == "10.24.1.2"


@pytest.mark.asyncio
async def test_ip_invalide_ne_part_jamais():
    with pytest.raises(ValueError):
        await RestV2Client("https://pf", "k").kill_states("")
