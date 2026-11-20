import pytest

from app.security import CampusValidationError, client_ip, resolve_campus


INGRESS = "10.42.0.7"       # pod de l'ingress (pair direct du portail)
SNAT = "10.42.12.0"         # adresse de noeud vue par l'ingress
HAPROXY = "10.29.113.21"    # HAProxy externe


def test_xff_ignore_si_pair_non_de_confiance(settings):
    assert client_ip("10.24.50.9", "1.2.3.4", settings) == "10.24.50.9"


def test_jambe_http_ip_reelle(settings):
    # HAProxy (mode http) ajoute le client, l'ingress ajoute sa source
    assert client_ip(INGRESS, f"10.24.127.21, {SNAT}", settings, "http") == "10.24.127.21"
    assert client_ip(INGRESS, f"10.24.127.21, {HAPROXY}", settings, "http") == "10.24.127.21"


def test_jambe_http_xff_forge_par_le_client(settings):
    # le client ecrit une fausse adresse au debut : elle est ignoree
    xff = f"10.24.5.5, 197.234.1.9, {SNAT}"
    assert client_ip(INGRESS, xff, settings, "http") == "197.234.1.9"


def test_jambe_https_xff_forge_depuis_internet(settings):
    # FAILLE du 21/11 : sur la jambe HTTPS le HAProxy n'ajoute rien, donc
    # l'element precedent est ecrit par le client -> jamais cru
    assert client_ip(INGRESS, f"10.24.5.5, {SNAT}", settings, "https") == SNAT
    assert client_ip(INGRESS, f"10.24.5.5, {HAPROXY}", settings, "https") == HAPROXY


def test_jambe_http_sans_entete_proto(settings):
    # sur la jambe HTTP l'ingress peut ne poser aucun X-Forwarded-Proto
    assert client_ip(INGRESS, f"10.24.127.21, {SNAT}", settings, None) == "10.24.127.21"
    assert client_ip(INGRESS, f"10.24.5.5, 197.234.1.9, {SNAT}", settings, None) == "197.234.1.9"


def test_source_directe_vue_par_l_ingress(settings):
    # si l'ingress voit le client lui-meme (pas de relais), c'est lui
    assert client_ip(INGRESS, "10.24.5.5, 10.24.127.30", settings, "https") == "10.24.127.30"


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


def test_lignes_d_entete_multiples_lues_en_entier():
    # regression du 21/11 : le relais ajoute sa valeur sur une 2e ligne ;
    # lire seulement la 1re revenait a croire le client
    from starlette.requests import Request
    from app.main import ip_of
    scope = {"type": "http", "method": "GET", "path": "/", "query_string": b"",
             "client": ("10.42.0.7", 1234),
             "headers": [(b"x-forwarded-for", b"10.24.5.5"),
                         (b"x-forwarded-for", b"10.42.12.0"),
                         (b"x-forwarded-proto", b"http"),
                         (b"x-forwarded-proto", b"https")]}
    assert ip_of(Request(scope)) == "10.42.12.0"
