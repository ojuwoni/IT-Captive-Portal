"""Epinglage du certificat auto-signe d'un pfSense."""
import http.server
import shutil
import ssl
import subprocess
import threading

import httpx
import pytest

from app.security import pfsense_verify, pinned_tls_context

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None,
                                reason="openssl absent")


def _selfsigned(tmp_path, name):
    key, crt = tmp_path / f"{name}.key", tmp_path / f"{name}.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-keyout", str(key), "-out", str(crt),
         "-subj", "/CN=pfSense-5f8a1b2c3d4e"],   # ne correspond PAS a 127.0.0.1
        check=True, capture_output=True)
    return key, crt


@pytest.fixture()
def pfsense(tmp_path):
    """Faux pfSense en HTTPS avec un certificat auto-signe."""
    key, crt = _selfsigned(tmp_path, "vrai")

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"data": {}}')

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{srv.server_address[1]}", crt
    srv.shutdown()


def test_verification_standard_refuse_l_auto_signe(pfsense):
    url, _ = pfsense
    with pytest.raises(httpx.ConnectError):      # l'erreur vue en production
        httpx.get(url, verify=True, timeout=5)


def test_certificat_epingle_accepte(pfsense):
    url, crt = pfsense
    r = httpx.get(url, verify=pinned_tls_context(str(crt)), timeout=5)
    assert r.status_code == 200


def test_autre_certificat_refuse(pfsense, tmp_path):
    # un imposteur avec son propre certificat auto-signe n'est pas accepte
    url, _ = pfsense
    _, autre = _selfsigned(tmp_path, "imposteur")
    with pytest.raises(httpx.ConnectError):
        httpx.get(url, verify=pinned_tls_context(str(autre)), timeout=5)


def test_choix_du_mode_par_campus(pfsense, tmp_path):
    _, crt = pfsense
    d = tmp_path / "certs"
    d.mkdir()
    shutil.copy(crt, d / "uac.pem")
    assert isinstance(pfsense_verify("uac", str(d), "", True), ssl.SSLContext)
    assert pfsense_verify("up", str(d), "", True) is True          # pas de fichier
    assert pfsense_verify("up", str(d), "/ca.pem", True) == "/ca.pem"
