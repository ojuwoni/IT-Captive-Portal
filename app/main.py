"""Portail Captif SSO RBER — application FastAPI (v2).

Flux (DAT v2.1 par. 6.1) :
  / -> validation campus/IP -> login.html -> /login (OIDC Keycloak)
    -> /callback -> autorisation de l'IP -> /success
Les sondes de detection de portail (CNA) arrivent ici via la redirection
NAT des pfSense : toute requete dont le Host n'est pas le portail recoit
un 302 vers /?campus=<deduit de l'IP source>.
"""
from __future__ import annotations

import logging
from pathlib import Path

import redis.asyncio as aioredis
from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.middleware.sessions import SessionMiddleware

from .authz import AuthorizationService, jlog
from .config import CampusConfig, CampusRouting, settings
from .pfsense import MockPfSenseClient, RestV2Client
from .security import CampusValidationError, client_ip, resolve_campus
from .sessions import RateLimiter
from .themes import ThemeRegistry

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("portal")

app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key or "dev-only",
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
    """Fabrique du client pfSense. PORTAL_PFSENSE_MODE=mock pour le dev."""
    import os
    if os.environ.get("PORTAL_PFSENSE_MODE") == "mock":
        return _mock_clients.setdefault(campus.id, MockPfSenseClient())
    verify: bool | str = settings.pfsense_ca_bundle or settings.pfsense_verify_tls
    return RestV2Client(
        base_url=campus.pfsense_url, api_key=_api_key(campus),
        alias_name=campus.pfsense_alias, verify=verify,
        timeout=settings.pfsense_timeout,
    )


redis = aioredis.from_url(settings.redis_url, decode_responses=True)
authz = AuthorizationService(redis, settings, make_client)
limiter = RateLimiter(redis, settings.rate_limit_per_minute)

oauth = OAuth()
oauth.register(
    name="keycloak",
    client_id=settings.keycloak_client_id,
    client_secret=settings.keycloak_secret(),
    server_metadata_url=settings.keycloak_metadata_url,
    client_kwargs={"scope": "openid profile email"},
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
    return client_ip(peer, request.headers.get("x-forwarded-for"), settings)


def error_page(theme_id: str, message: str, status: int = 400) -> HTMLResponse:
    resp = render("error.html", theme_id, message=message)
    resp.status_code = status
    return resp


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
async def index(request: Request, campus: str | None = None):
    ip = ip_of(request)
    host = request.headers.get("host", "").split(":")[0].lower()

    # Sonde CNA ou trafic intercepte : Host etranger -> 302 vers le portail
    if host and host != settings.public_host and "localhost" not in host:
        try:
            found, _ = resolve_campus(None, ip, routing)
            target = f"{settings.public_base_url}/?campus={found.id}"
        except CampusValidationError:
            target = settings.public_base_url
        return RedirectResponse(target, status_code=302)

    try:
        found, inferred = resolve_campus(campus, ip, routing)
    except CampusValidationError as exc:
        jlog("campus_rejected", ip=ip, param=campus, reason=exc.reason)
        return render("select_campus.html", "_default",
                      campuses=routing.all(), client_ip=ip)

    existing = await authz.store.get(found.id, ip)
    if existing:
        return render("already_connected.html", found.theme,
                      campus=found, session=existing)
    return render("login.html", found.theme, campus=found,
                  client_ip=ip, inferred=inferred)


@app.get("/login")
async def login(request: Request, campus: str | None = None):
    ip = ip_of(request)
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
    ip = ip_of(request)
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
        jlog("oidc_error", ip=ip, campus=campus_id, error=str(exc)[:200])
        return error_page(found.theme,
                          "Echec de l'authentification. Reessayez.", 400)

    userinfo = token.get("userinfo") or {}
    username = userinfo.get("preferred_username") or userinfo.get("sub") or "inconnu"
    try:
        await authz.authorize(found, ip, username,
                              email=userinfo.get("email", ""))
    except Exception as exc:
        jlog("authorize_error", ip=ip, campus=found.id, user=username,
             error=str(exc)[:200])
        return error_page(found.theme,
                          "Authentification reussie mais autorisation reseau "
                          "en echec. Signalez-le au support.", 502)

    request.session["user"] = username
    return RedirectResponse("/success", status_code=302)


@app.get("/success", response_class=HTMLResponse)
async def success(request: Request):
    ip = ip_of(request)
    campus_id = request.session.get("campus")
    found = routing.get(campus_id)
    if found is None:
        return RedirectResponse("/", status_code=302)
    session = await authz.store.get(found.id, ip)
    if session is None:
        return RedirectResponse("/", status_code=302)
    return render("success.html", found.theme, campus=found, session=session,
                  ttl_hours=settings.session_ttl // 3600)


@app.get("/logout")
async def logout(request: Request):
    ip = ip_of(request)
    campus_id = request.session.get("campus")
    found = routing.get(campus_id) or routing.find_by_ip(ip)
    if found is not None:
        try:
            await authz.revoke(found, ip, reason="logout")
        except Exception as exc:
            jlog("revoke_error", ip=ip, campus=found.id, error=str(exc)[:200])
    request.session.clear()
    return RedirectResponse("/", status_code=302)


@app.get("/status")
async def status(request: Request):
    ip = ip_of(request)
    found = routing.find_by_ip(ip)
    if found is None:
        return {"connected": False, "reason": "campus inconnu", "ip": ip}
    session = await authz.store.get(found.id, ip)
    if session is None:
        return {"connected": False, "campus": found.id, "ip": ip}
    return {"connected": True, "campus": found.id, "ip": ip,
            "user": session.get("user"), "since": session.get("login_time")}
