import pytest

from app.security import CampusValidationError, client_ip, resolve_campus


def test_xff_ignore_si_pair_non_de_confiance(settings):
    # un client qui forge X-Forwarded-For ne doit pas etre cru (M2)
    assert client_ip("10.24.50.9", "1.2.3.4", settings) == "10.24.50.9"


def test_xff_accepte_depuis_ingress(settings):
    assert client_ip("10.42.0.7", "10.24.127.21", settings) == "10.24.127.21"


def test_campus_declare_et_coherent(routing):
    campus, inferred = resolve_campus("uac", "10.24.127.21", routing)
    assert campus.id == "uac" and inferred is False


def test_campus_falsifie_rejete(routing):
    # IP de l'UAC avec ?campus=up -> rejet (DAT 6.2 / 6.5)
    with pytest.raises(CampusValidationError):
        resolve_campus("up", "10.24.127.21", routing)


def test_campus_inconnu_rejete(routing):
    with pytest.raises(CampusValidationError):
        resolve_campus("nimporte", "10.24.127.21", routing)


def test_inference_par_ip(routing):
    campus, inferred = resolve_campus(None, "10.25.3.4", routing)
    assert campus.id == "up" and inferred is True


def test_ip_hors_de_tout_subnet(routing):
    with pytest.raises(CampusValidationError):
        resolve_campus(None, "192.168.1.10", routing)
