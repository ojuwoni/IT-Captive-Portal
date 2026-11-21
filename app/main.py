"""Portail Captif SSO RBER — application FastAPI (v2).

Flux (DAT v2.1 par. 6.1) :
  / -> validation campus/IP -> login.html -> /login (OIDC Keycloak)
    -> /callback -> autorisation de l'IP -> /success
Les sondes de detection de portail (CNA) arrivent ici via la redirection
NAT des pfSense : toute requete dont le Host n'est pas le portail recoit
un 302 vers /?campus=<deduit de l'IP source>.
"""
from __future__ import annotations

import calendar
import logging
import time
from pathlib import Path

import redis.asyncio as aioredis
from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, Request
from fastapi.responses import (HTMLResponse, JSONResponse, PlainTextResponse,
                               RedirectResponse)
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.middleware.sessions import SessionMiddleware

from .authz import AuthorizationService, errstr, jlog
from .config import CampusConfig, CampusRouting, settings
from .pfsense import MockPfSenseClient, RestV2Client
from .security import (CampusValidationError, client_ip,
                       ip_token_issued_at, make_ip_token,
                       pfsense_verify, read_ip_token, resolve_campus)
from .sessions import RateLimiter
from .themes import ThemeRegistry

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("portal")

app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None)
SECRET = settings.secret_key or "dev-only"
app.add_middleware(SessionMiddleware, secret_key=SECRET,
                   https_only=not settings.debug, same_site="lax")

routing = CampusRouting(settings.routing_path)
themes = ThemeRegistry(settings.themes_dir)

_env = Environment(
    loader=FileSystemLoader([settings.themes_dir, settings.templates_dir]),
    autoescape=select_autoescape(["html"]),
)

_mock_clients: dict[str, MockPfSenseClient] = {}


def _api_key(campus: CampusConfig) -> str:
    return (Path(settings.secrets_dir) / campus.api_key_secret).read_text().strip()


def make_client(campus: CampusConfig):
    """Fabrique du client pfSense. PFSENSE_MODE=mock pour le dev."""
    if settings.pfsense_mode == "mock":
        return _mock_clients.setdefault(campus.id, MockPfSenseClient())
    verify = pfsense_verify(campus.id, settings.pfsense_certs_dir,
                            settings.pfsense_ca_bundle,
                            settings.pfsense_verify_tls)
    return RestV2Client(
        base_url=campus.pfsense_url, api_key=_api_key(campus),
        alias_name=campus.pfsense_alias, verify=verify,
        timeout=settings.pfsense_timeout,
    )


redis = aioredis.from_url(settings.redis_url, decode_responses=True)
authz = AuthorizationService(redis, settings, make_client)
limiter = RateLimiter(redis, settings.rate_limit_per_minute,
                      settings.rate_limit_enabled)

oauth = OAuth()
oauth.register(
    name="keycloak",
    client_id=settings.keycloak_client_id,
    client_secret=settings.keycloak_secret(),
    server_metadata_url=settings.keycloak_metadata_url,
    # PKCE S256 : exige par le client captive-portal dans RBERConnect
    # (sans lui : « Missing parameter: code_challenge_method », constate le 20/11)
    client_kwargs={"scope": "openid profile email",
                   "code_challenge_method": "S256"},
)

if Path(settings.static_dir).exists():
    app.mount("/static", StaticFiles(directory=settings.static_dir), name="static")
if Path(settings.themes_dir).exists():
    app.mount("/themes", StaticFiles(directory=settings.themes_dir), name="themes")


# ---------------------------------------------------------------- rendu
def render(name: str, theme_id: str, **ctx) -> HTMLResponse:
    override = Path(settings.themes_dir) / theme_id / "templates" / name
    tpl = f"{theme_id}/templates/{name}" if override.exists() else name
    theme = themes.get(theme_id)
    html = _env.get_template(tpl).render(
        theme=theme, css_variables=themes.css_variables(theme), **ctx)
    return HTMLResponse(html)


def ip_of(request: Request) -> str:
    peer = request.client.host if request.client else "0.0.0.0"
    # Un relais peut ajouter SA valeur sur une ligne d'en-tete separee :
    # il faut lire toutes les lignes, pas seulement la premiere (qui peut
    # etre celle ecrite par le client).
    xff = ", ".join(request.headers.getlist("x-forwarded-for")) or None
    protos = request.headers.getlist("x-forwarded-proto")
    return client_ip(peer, xff, settings, protos[-1] if protos else None)


def effective_ip(request: Request, token: str | None = None) -> str:
    """IP a autoriser pour ce client.

    1. Si l'adresse lue dans les en-tetes est deja celle d'un campus (jambe
       HTTP), on la prend.
    2. Sinon (jambe HTTPS) : jeton signe recu dans le lien, puis souvenir
       de ce jeton dans la session (cookie signe), pendant verified_ip_ttl.
    3. Sinon : l'adresse lue (celle d'un relais) -> aucun campus.
    """
    seen = ip_of(request)
    if routing.find_by_ip(seen) is not None:
        return seen
    if token:
        tip = read_ip_token(SECRET, token, settings.ip_token_ttl)
        if tip and routing.find_by_ip(tip) is not None:
            request.session["vip"] = {"ip": tip,
                                      "exp": time.time() + settings.verified_ip_ttl}
            return tip
        jlog("ip_token_rejected", seen=seen)
    vip = request.session.get("vip")
    if isinstance(vip, dict) and vip.get("exp", 0) > time.time():
        return vip.get("ip", seen)
    return seen


async def own_authorization(request: Request):
    """L'autorisation ouverte par CE navigateur, si elle est encore active.

    A la connexion, le portail note dans la session (cookie signe) quelle
    adresse il a ouverte et pour qui. Cela permet de la refermer plus tard
    (deconnexion) meme quand le souvenir du jeton d'IP a expire. On ne s'en
    sert jamais pour ouvrir un acces : seulement pour afficher l'etat et
    fermer, et seulement si l'autorisation en place est bien celle de ce
    meme utilisateur (l'adresse a pu etre reattribuee depuis).

    Retourne (campus, ip, session) ou None.
    """
    auth = request.session.get("auth")
    user = request.session.get("user")
    if not isinstance(auth, dict) or not user:
        return None
    campus = routing.get(auth.get("campus"))
    ip = auth.get("ip")
    if campus is None or not ip:
        return None
    current = await authz.store.get(campus.id, ip)
    if current and current.get("user") == user:
        return campus, ip, current
    return None


def _login_epoch(session: dict) -> float:
    try:
        return calendar.timegm(time.strptime(session.get("login_time", ""),
                                             "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, TypeError):
        return 0.0


def session_is_stale(session: dict, token: str | None) -> bool:
    """Session enregistree alors que le pfSense intercepte encore ce client.

    Un jeton emis APRES la connexion prouve que l'adresse n'est plus dans
    l'alias (retrait manuel, alias restaure, pfSense reinitialise...). La
    session est alors un souvenir faux : sans ce controle, le client voit
    « Deja connecte » sans Internet jusqu'a l'expiration (constate le 21/11).
    La marge couvre le delai d'application de l'alias juste apres la
    connexion (sondes des appareils encore interceptees ~2 s)."""
    if not token:
        return False
    issued = ip_token_issued_at(SECRET, token, settings.ip_token_ttl)
    if issued is None:
        return False
    return issued > _login_epoch(session) + settings.stale_session_grace


def error_page(theme_id: str, message: str, status: int = 400) -> HTMLResponse:
    resp = render("error.html", theme_id, message=message)
    resp.status_code = status
    return resp


# ---------------------------------------------------------------- interception
def _is_intercepted(request: Request) -> bool:
    """Requete d'un client WiFi interceptee par le pfSense : son Host n'est
    pas celui du portail. Vaut pour TOUS les chemins — les appareils sondent
    /generate_204 (Android), /hotspot-detect.html (Apple),
    /connecttest.txt (Windows)... pas seulement « / »."""
    host = request.headers.get("host", "").split(":")[0].lower()
    if not host or host == settings.public_host or "localhost" in host:
        return False
    path = request.url.path
    # sondes du cluster (Host = IP du pod) et defis ACME d'autres domaines
    return path != "/health" and not path.startswith("/.well-known/")


@app.middleware("http")
async def intercept_foreign_hosts(request: Request, call_next):
    if not _is_intercepted(request):
        return await call_next(request)
    # Jambe HTTP : c'est ICI que l'IP reelle est connue. On la joint au
    # lien sous forme de jeton signe, pour la jambe HTTPS qui suit.
    ip = ip_of(request)
    try:
        found, _ = resolve_campus(None, ip, routing)
        target = (f"{settings.public_base_url}/?campus={found.id}"
                  f"&t={make_ip_token(SECRET, ip)}")
    except CampusValidationError:
        # nb=1 : « deja renvoye », evite une boucle de renvois
        target = f"{settings.public_base_url}/?nb=1"
    return RedirectResponse(target, status_code=302)


# ---------------------------------------------------------------- routes
@app.get("/health")
async def health():
    try:
        await redis.ping()
        redis_ok = True
    except Exception:
        redis_ok = False
    return JSONResponse({"status": "ok" if redis_ok else "degraded",
                         "redis": redis_ok,
                         "campuses": len(routing.all())},
                        status_code=200 if redis_ok else 503)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, campus: str | None = None,
                t: str | None = None, nb: str | None = None):
    # Requete sans Host : health check du HAProxy externe (GET / HTTP/1.0).
    # Reponse courte, sans journal (plusieurs par seconde).
    if not request.headers.get("host"):
        return PlainTextResponse("ok")

    ip = effective_ip(request, t)
    try:
        found, inferred = resolve_campus(campus, ip, routing)
    except CampusValidationError as exc:
        # Navigateur deja connecte qui revient sur le portail (sans jeton) :
        # on lui montre son etat et le bouton de deconnexion.
        own = await own_authorization(request)
        if own:
            own_campus, _, own_session = own
            return render("already_connected.html", own_campus.theme,
                          campus=own_campus, session=own_session)
        # Arrive directement en HTTPS, sans jeton : on le renvoie une fois
        # vers une adresse HTTP ou son IP reelle sera lue (si configuree).
        if settings.bounce_url and not nb and not t:
            return RedirectResponse(settings.bounce_url, status_code=302)
        # IP hors de tout subnet campus : visiteur externe (ou parametre
        # falsifie). Un selecteur serait une boucle inutile — page claire.
        if campus or t:
            jlog("campus_rejected", ip=ip, param=campus, reason=exc.reason)
        return render("out_of_network.html", "_default", client_ip=ip)

    existing = await authz.store.get(found.id, ip)
    if existing and session_is_stale(existing, t):
        jlog("stale_session", campus=found.id, ip=ip,
             user=existing.get("user"), since=existing.get("login_time"))
        await authz.store.delete(found.id, ip)
        request.session.pop("auth", None)
        request.session.pop("user", None)
        existing = None
    if existing:
        return render("already_connected.html", found.theme,
                      campus=found, session=existing)
    return render("login.html", found.theme, campus=found,
                  client_ip=ip, inferred=inferred)


@app.get("/login")
async def login(request: Request, campus: str | None = None):
    ip = effective_ip(request)
    if not await limiter.allow(ip):
        return error_page("_default", "Trop de tentatives. Reessayez dans une minute.", 429)
    try:
        found, _ = resolve_campus(campus, ip, routing)
    except CampusValidationError as exc:
        return error_page("_default", f"Campus invalide : {exc.reason}", 400)

    request.session["campus"] = found.id
    request.session["ip"] = ip
    redirect_uri = f"{settings.public_base_url}/callback"
    return await oauth.keycloak.authorize_redirect(request, redirect_uri)


@app.get("/callback")
async def callback(request: Request):
    ip = effective_ip(request)
    if not await limiter.allow(ip):
        return error_page("_default", "Trop de tentatives. Reessayez dans une minute.", 429)

    campus_id = request.session.get("campus")
    session_ip = request.session.get("ip")
    found = routing.get(campus_id)
    if found is None or session_ip != ip:
        jlog("callback_rejected", ip=ip, campus=campus_id,
             reason="session absente ou IP changee")
        return error_page("_default",
                          "Session de connexion expiree ou invalide. "
                          "Reconnectez-vous au WiFi puis reessayez.", 400)
    try:
        token = await oauth.keycloak.authorize_access_token(request)
    except Exception as exc:  # erreur OIDC : page claire, jamais de 500 brut
        jlog("oidc_error", ip=ip, campus=campus_id, error=errstr(exc))
        return error_page(found.theme,
                          "Echec de l'authentification. Reessayez.", 400)

    userinfo = token.get("userinfo") or {}
    username = userinfo.get("preferred_username") or userinfo.get("sub") or "inconnu"
    try:
        await authz.authorize(found, ip, username,
                              email=userinfo.get("email", ""))
    except Exception as exc:
        jlog("authorize_error", ip=ip, campus=found.id, user=username,
             error=errstr(exc))
        return error_page(found.theme,
                          "Authentification reussie mais autorisation reseau "
                          "en echec. Signalez-le au support.", 502)

    request.session["user"] = username
    request.session["auth"] = {"campus": found.id, "ip": ip}
    return RedirectResponse("/success", status_code=302)


@app.get("/success", response_class=HTMLResponse)
async def success(request: Request):
    own = await own_authorization(request)
    if own is None:
        return RedirectResponse("/", status_code=302)
    found, _, session = own
    return render("success.html", found.theme, campus=found, session=session,
                  ttl_hours=settings.session_ttl // 3600)


@app.get("/logout")
async def logout(request: Request):
    """Referme l'acces ouvert par ce navigateur, puis oublie la session.

    L'adresse a retirer est celle notee a la connexion (own_authorization),
    pas celle lue sur la requete : en HTTPS le portail ne voit qu'un relais,
    et le souvenir du jeton d'IP n'est garde que quelques minutes (defaut
    constate le 21/11 : deconnexion sans effet apres 15 minutes).
    """
    own = await own_authorization(request)
    theme_id = "_default"
    done = False
    if own:
        found, ip, _ = own
        theme_id = found.theme
        try:
            await authz.revoke(found, ip, reason="logout")
            done = True
        except Exception as exc:
            jlog("revoke_error", ip=ip, campus=found.id, error=errstr(exc))
            return error_page(found.theme,
                              "La deconnexion n'a pas pu etre appliquee. "
                              "Reessayez dans un instant.", 502)
    request.session.clear()
    return render("logged_out.html", theme_id, done=done)


@app.get("/status")
async def status(request: Request):
    ip = effective_ip(request)
    found = routing.find_by_ip(ip)
    if found is None:
        return {"connected": False, "reason": "campus inconnu", "ip": ip}
    session = await authz.store.get(found.id, ip)
    if session is None:
        return {"connected": False, "campus": found.id, "ip": ip}
    return {"connected": True, "campus": found.id, "ip": ip,
            "user": session.get("user"), "since": session.get("login_time")}
