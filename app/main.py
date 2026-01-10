# app/main.py
import subprocess
import logging
import sys
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
import redis.asyncio as redis
import httpx

from config.settings import settings
from config.theme import theme, get_css_variables

# Import conditionnel pour pfSense API
if settings.auth_method == "pfsense_api":
    sys.path.insert(0, '/opt/captive-portal')
    from scripts.pfsense_api import (
        authorize_mac_pfsense,
        revoke_mac_pfsense,
        get_mac_from_pfsense
    )

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(title=settings.app_name)
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)

# Templates
templates = Jinja2Templates(directory="templates")

# Fichiers statiques (logo, favicon, etc.)
from fastapi.staticfiles import StaticFiles

# Redis client
redis_client: Optional[redis.Redis] = None

# OAuth setup
oauth = OAuth()
oauth.register(
    name="keycloak",
    client_id=settings.keycloak_client_id,
    client_secret=settings.keycloak_client_secret,
    server_metadata_url=settings.keycloak_metadata_url,
    client_kwargs={"scope": "openid profile email"}
)


@app.on_event("startup")
async def startup():
    global redis_client
    redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    
    # Monter les fichiers statiques
    import os
    static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
    if os.path.exists(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
    
    logger.info(f"Portail captif démarré - Méthode auth: {settings.auth_method}")


@app.on_event("shutdown")
async def shutdown():
    if redis_client:
        await redis_client.close()


# ============================================
# Utilitaires réseau
# ============================================

def get_mac_from_ip_arp(ip: str) -> Optional[str]:
    """Récupère l'adresse MAC depuis la table ARP locale."""
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True,
            text=True,
            timeout=5
        )
        # Format: "192.168.1.10 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        parts = result.stdout.strip().split()
        if "lladdr" in parts:
            mac_index = parts.index("lladdr") + 1
            return parts[mac_index].upper()
    except Exception as e:
        logger.error(f"Erreur ARP lookup pour {ip}: {e}")
    return None


async def get_mac_from_ip(ip: str) -> Optional[str]:
    """
    Récupère l'adresse MAC selon la méthode configurée.

    - pfsense_api: interroge les DHCP Leases via API pfSense
    - nftables/radius_coa: utilise la table ARP locale
    """
    if settings.auth_method == "pfsense_api":
        try:
            mac = await get_mac_from_pfsense(ip)
            if mac:
                return mac
            # Fallback sur ARP si pfSense ne trouve pas
            logger.warning(f"pfSense n'a pas trouvé la MAC pour {ip}, essai ARP")
        except Exception as e:
            logger.error(f"Erreur pfSense API pour {ip}: {e}")

    # Méthode ARP (nftables, radius_coa, ou fallback)
    return get_mac_from_ip_arp(ip)


def get_client_ip(request: Request) -> str:
    """Récupère l'IP client (gère les proxies)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


# ============================================
# Gestion des autorisations réseau
# ============================================

async def authorize_mac_nftables(mac: str, username: str) -> bool:
    """Autorise une MAC via nftables."""
    try:
        # Ajouter au set nftables
        cmd = [
            "nft", "add", "element",
            settings.nft_table, settings.nft_chain,
            settings.nft_set, "{", mac, "}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            logger.info(f"MAC {mac} autorisée (nftables) pour {username}")
            return True
        else:
            logger.error(f"Erreur nftables: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Exception nftables: {e}")
        return False


async def revoke_mac_nftables(mac: str) -> bool:
    """Révoque une MAC via nftables."""
    try:
        cmd = [
            "nft", "delete", "element",
            settings.nft_table, settings.nft_chain,
            settings.nft_set, "{", mac, "}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            logger.info(f"MAC {mac} révoquée (nftables)")
            return True
        return False
    except Exception as e:
        logger.error(f"Exception revoke nftables: {e}")
        return False


async def authorize_mac_radius_coa(mac: str, username: str) -> bool:
    """Autorise via RADIUS Change of Authorization."""
    try:
        from pyrad.client import Client
        from pyrad import dictionary, packet
        
        # Charger le dictionnaire RADIUS
        dict_path = "/etc/freeradius/3.0/dictionary"
        radius_dict = dictionary.Dictionary(dict_path)
        
        # Créer le client CoA
        client = Client(
            server=settings.radius_nas_ip,
            secret=settings.radius_secret.encode(),
            dict=radius_dict
        )
        client.timeout = 5
        
        # Créer le paquet CoA
        req = client.CreateCoAPacket()
        req["User-Name"] = username
        req["Calling-Station-Id"] = mac.replace(":", "-")
        
        # Envoyer
        reply = client.SendPacket(req)
        
        if reply.code == packet.CoAACK:
            logger.info(f"CoA ACK reçu pour {mac} ({username})")
            return True
        else:
            logger.warning(f"CoA NAK pour {mac}")
            return False
            
    except Exception as e:
        logger.error(f"Erreur RADIUS CoA: {e}")
        return False


async def authorize_mac_pfsense_api(mac: str, username: str) -> bool:
    """Autorise une MAC via l'API pfSense."""
    try:
        success = await authorize_mac_pfsense(mac, username)
        if success:
            logger.info(f"MAC {mac} autorisée (pfSense API) pour {username}")
        return success
    except Exception as e:
        logger.error(f"Erreur pfSense API authorize: {e}")
        return False


async def authorize_mac(mac: str, username: str) -> bool:
    """Autorise une MAC selon la méthode configurée."""
    # Stocker dans Redis avec TTL
    await redis_client.setex(
        f"session:{mac}",
        settings.session_timeout,
        f"{username}:{datetime.utcnow().isoformat()}"
    )

    if settings.auth_method == "nftables":
        return await authorize_mac_nftables(mac, username)
    elif settings.auth_method == "radius_coa":
        return await authorize_mac_radius_coa(mac, username)
    elif settings.auth_method == "pfsense_api":
        return await authorize_mac_pfsense_api(mac, username)
    else:
        logger.error(f"Méthode d'auth inconnue: {settings.auth_method}")
        return False


async def revoke_mac_pfsense_api(mac: str) -> bool:
    """Révoque une MAC via l'API pfSense."""
    try:
        success = await revoke_mac_pfsense(mac)
        if success:
            logger.info(f"MAC {mac} révoquée (pfSense API)")
        return success
    except Exception as e:
        logger.error(f"Erreur pfSense API revoke: {e}")
        return False


async def revoke_mac(mac: str) -> bool:
    """Révoque une MAC."""
    await redis_client.delete(f"session:{mac}")

    if settings.auth_method == "nftables":
        return await revoke_mac_nftables(mac)
    elif settings.auth_method == "pfsense_api":
        return await revoke_mac_pfsense_api(mac)
    # CoA disconnect serait ici pour RADIUS
    return True


# ============================================
# Routes
# ============================================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Page d'accueil du portail captif."""
    client_ip = get_client_ip(request)
    mac = await get_mac_from_ip(client_ip)
    
    # Vérifier si déjà autorisé
    if mac:
        session_data = await redis_client.get(f"session:{mac}")
        if session_data:
            return templates.TemplateResponse("already_connected.html", {
                "request": request,
                "username": session_data.split(":")[0],
                "theme": theme,
                "css_variables": get_css_variables()
            })
    
    return templates.TemplateResponse("login.html", {
        "request": request,
        "client_ip": client_ip,
        "mac": mac or "Non détectée",
        "theme": theme,
        "css_variables": get_css_variables()
    })


@app.get("/login")
async def login(request: Request):
    """Initie le flow OIDC vers Keycloak."""
    client_ip = get_client_ip(request)
    mac = await get_mac_from_ip(client_ip)
    
    if not mac:
        raise HTTPException(
            status_code=400,
            detail="Impossible de détecter ton adresse MAC. Vérifie ta connexion WiFi."
        )
    
    # Stocker IP et MAC dans la session
    request.session["client_ip"] = client_ip
    request.session["client_mac"] = mac
    
    # Redirect vers Keycloak
    redirect_uri = settings.callback_url
    return await oauth.keycloak.authorize_redirect(request, redirect_uri)


@app.get("/callback")
async def callback(request: Request):
    """Callback OIDC après authentification Keycloak."""
    try:
        # Récupérer le token
        token = await oauth.keycloak.authorize_access_token(request)
        userinfo = token.get("userinfo", {})
        
        username = userinfo.get("preferred_username") or userinfo.get("sub")
        email = userinfo.get("email", "")
        
        # Récupérer MAC depuis la session
        mac = request.session.get("client_mac")
        
        if not mac:
            raise HTTPException(
                status_code=400,
                detail="Session expirée. Reconnecte-toi au WiFi."
            )
        
        # Autoriser l'accès réseau
        success = await authorize_mac(mac, username)
        
        if not success:
            raise HTTPException(
                status_code=500,
                detail="Erreur lors de l'autorisation réseau."
            )
        
        # Stocker les infos user dans la session
        request.session["user"] = {
            "username": username,
            "email": email,
            "mac": mac,
            "login_time": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Login réussi: {username} ({mac})")
        
        # Redirection vers la page de succès ou URL configurée
        return RedirectResponse(url="/success")
        
    except Exception as e:
        logger.error(f"Erreur callback: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/success", response_class=HTMLResponse)
async def success(request: Request):
    """Page de succès après connexion."""
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/")
    
    return templates.TemplateResponse("success.html", {
        "request": request,
        "username": user["username"],
        "redirect_url": settings.success_redirect_url,
        "session_timeout": settings.session_timeout // 3600,  # En heures
        "theme": theme,
        "css_variables": get_css_variables()
    })


@app.get("/logout")
async def logout(request: Request):
    """Déconnexion et révocation de l'accès."""
    user = request.session.get("user")
    
    if user and user.get("mac"):
        await revoke_mac(user["mac"])
        logger.info(f"Logout: {user['username']} ({user['mac']})")
    
    request.session.clear()
    return RedirectResponse(url="/")


@app.get("/status")
async def status(request: Request):
    """Vérifie le statut de connexion (API)."""
    client_ip = get_client_ip(request)
    mac = await get_mac_from_ip(client_ip)
    
    if not mac:
        return {"connected": False, "reason": "MAC non détectée"}
    
    session_data = await redis_client.get(f"session:{mac}")
    
    if session_data:
        parts = session_data.split(":")
        return {
            "connected": True,
            "username": parts[0],
            "mac": mac,
            "since": parts[1] if len(parts) > 1 else None
        }
    
    return {"connected": False, "mac": mac}


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "auth_method": settings.auth_method}


# ============================================
# Main
# ============================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=settings.debug
    )
