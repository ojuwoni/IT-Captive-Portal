import pytest

from app.authz import AuthorizationService
from app.pfsense import MockPfSenseClient
from app.reconciler import reconcile_campus


@pytest.mark.asyncio
async def test_orpheline_retiree_et_sessions_kc(redis, settings, routing):
    campus = routing.get("uac")
    client = MockPfSenseClient(arp={"10.24.1.1": "AA:AA:AA:AA:AA:01"})
    svc = AuthorizationService(redis, settings, lambda c: client)

    # session valide + session dont le user n'a plus de session Keycloak
    await svc.authorize(campus, "10.24.1.1", "actif")
    client.alias.add("10.24.9.9")        # orpheline : dans l'alias, pas en Redis
    await svc.store.save("uac", "10.24.2.2", {"user": "parti"})
    client.alias.add("10.24.2.2")

    result = await reconcile_campus(svc, redis, campus, kc_active={"actif"})
    assert result["orphans_removed"] == 1
    assert result["kc_expired_removed"] == 1
    assert client.alias == {"10.24.1.1"}
    assert await svc.store.get("uac", "10.24.2.2") is None
    assert await svc.store.get("uac", "10.24.1.1") is not None


@pytest.mark.asyncio
async def test_keycloak_injoignable_ne_revoque_pas_en_masse(redis, settings, routing):
    campus = routing.get("uac")
    client = MockPfSenseClient(arp={"10.24.1.1": "AA:AA:AA:AA:AA:01"})
    svc = AuthorizationService(redis, settings, lambda c: client)
    await svc.authorize(campus, "10.24.1.1", "actif")

    result = await reconcile_campus(svc, redis, campus, kc_active=None)
    assert result["kc_expired_removed"] == 0
    assert client.alias == {"10.24.1.1"}


@pytest.mark.asyncio
async def test_ip_reattribuee_revoquee(redis, settings, routing):
    # scenario de Harris : le bail DHCP donne l'IP a un AUTRE appareil
    campus = routing.get("uac")
    client = MockPfSenseClient(arp={"10.24.1.1": "AA:AA:AA:AA:AA:01"})
    svc = AuthorizationService(redis, settings, lambda c: client)
    await svc.authorize(campus, "10.24.1.1", "etudiant1")

    client.arp["10.24.1.1"] = "BB:BB:BB:BB:BB:02"  # nouvel appareil
    result = await reconcile_campus(svc, redis, campus, kc_active={"etudiant1"})
    assert result["ip_reassigned_removed"] == 1
    assert client.alias == set()
    assert await svc.store.get("uac", "10.24.1.1") is None


@pytest.mark.asyncio
async def test_inactivite_revoquee_apres_grace(redis, settings, routing):
    campus = routing.get("uac")
    client = MockPfSenseClient(arp={"10.24.1.1": "AA:AA:AA:AA:AA:01"})
    svc = AuthorizationService(redis, settings, lambda c: client)
    await svc.authorize(campus, "10.24.1.1", "etudiant1")

    del client.arp["10.24.1.1"]  # l'appareil quitte le campus
    for cycle in range(settings.idle_grace_cycles - 1):
        result = await reconcile_campus(svc, redis, campus,
                                        kc_active={"etudiant1"})
        assert result["idle_removed"] == 0      # pendant la grace : conserve
    result = await reconcile_campus(svc, redis, campus, kc_active={"etudiant1"})
    assert result["idle_removed"] == 1
    assert client.alias == set()


@pytest.mark.asyncio
async def test_retour_du_client_remet_le_compteur_a_zero(redis, settings, routing):
    campus = routing.get("uac")
    client = MockPfSenseClient(arp={"10.24.1.1": "AA:AA:AA:AA:AA:01"})
    svc = AuthorizationService(redis, settings, lambda c: client)
    await svc.authorize(campus, "10.24.1.1", "etudiant1")

    del client.arp["10.24.1.1"]
    await reconcile_campus(svc, redis, campus, kc_active={"etudiant1"})
    client.arp["10.24.1.1"] = "AA:AA:AA:AA:AA:01"   # il revient
    await reconcile_campus(svc, redis, campus, kc_active={"etudiant1"})
    del client.arp["10.24.1.1"]
    for _ in range(settings.idle_grace_cycles - 1):
        result = await reconcile_campus(svc, redis, campus,
                                        kc_active={"etudiant1"})
    assert client.alias == {"10.24.1.1"}            # compteur reparti de zero
