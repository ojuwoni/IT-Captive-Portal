import asyncio

import pytest

from app.authz import AuthorizationService
from app.pfsense import MockPfSenseClient


@pytest.fixture()
def service(redis, settings, routing):
    clients = {}

    def factory(campus):
        return clients.setdefault(
            campus.id, MockPfSenseClient(arp={"10.24.127.21": "AA:BB:CC:DD:EE:01"}))

    svc = AuthorizationService(redis, settings, factory)
    svc._clients = clients
    return svc


@pytest.mark.asyncio
async def test_autorisation_complete(service, routing):
    campus = routing.get("uac")
    session = await service.authorize(campus, "10.24.127.21", "etudiant1")
    client = service._clients["uac"]
    assert "10.24.127.21" in client.alias
    assert client.applied == 1
    assert session["mac"] == "AA:BB:CC:DD:EE:01"
    stored = await service.store.get("uac", "10.24.127.21")
    assert stored["user"] == "etudiant1"


@pytest.mark.asyncio
async def test_revocation(service, routing):
    campus = routing.get("uac")
    await service.authorize(campus, "10.24.127.21", "etudiant1")
    await service.revoke(campus, "10.24.127.21")
    client = service._clients["uac"]
    assert client.alias == set()
    assert await service.store.get("uac", "10.24.127.21") is None


@pytest.mark.asyncio
async def test_mac_inconnue_rafraichit_puis_none(service, routing):
    campus = routing.get("uac")
    mac = await service.mac_for(campus, "10.24.99.99")
    assert mac is None


@pytest.mark.asyncio
async def test_autorisations_concurrentes_serialisees(service, routing):
    # deux logins simultanes : les DEUX IP doivent etre dans l'alias (M1)
    campus = routing.get("uac")
    client = service._clients.setdefault(
        "uac", MockPfSenseClient(arp={}))
    client.arp = {"10.24.1.1": "AA:AA:AA:AA:AA:01",
                  "10.24.1.2": "AA:AA:AA:AA:AA:02"}
    client._latency = 0.02
    await asyncio.gather(
        service.authorize(campus, "10.24.1.1", "u1"),
        service.authorize(campus, "10.24.1.2", "u2"),
    )
    assert client.alias == {"10.24.1.1", "10.24.1.2"}
