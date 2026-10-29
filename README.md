# Portail Captif SSO RBER — v2

Portail captif centralisé multi-campus : une seule instance (Kubernetes
RKE2, Fidjrossè) sert les 11 sites universitaires du RBER via le MPLS.
Authentification OIDC Keycloak (RBERConnect), autorisation réseau par
adresse IP pilotée sur le pfSense de chaque campus (API REST v2).

**Référence d'architecture : DAT Portail Captif SSO v2.1** (IDADU TECH).
La v1 (branche `ojuwoni`) est conservée comme référence d'audit — ne pas
l'utiliser : son mécanisme d'autorisation par MAC n'est pas applicable par
pfSense et sa révocation fuit (voir le rapport d'audit).

## Ce que la v2 corrige (audit d'août 2026)

| Référence | Correction |
|---|---|
| B1 | Autorisation par **IP** dans l'alias `authorized_clients` (pf ne filtre pas par MAC) ; MAC relevée via la **table ARP** pour validation et journal |
| B2 | Client **REST API v2** (`X-API-Key`, base URL avec port web, ex. `:10443`) |
| B3 | **Réconciliation alias-first** (`app/reconciler.py`) : aucune IP ne survit dans l'alias sans session valide |
| M1 | Écritures d'alias **sérialisées** par verrou Redis par campus |
| M2 | IP réelle : X-Forwarded-For accepté **uniquement** depuis l'ingress (proxies de confiance) |
| M3 | **Cache** des tables ARP (45 s) + **rate limiting** — dimensionné pour les sondes CNA (≈20 req/min/poste observées en test) |
| M4/M5 | Client admin Keycloak **paginé**, cache de token corrigé |

## Arborescence

```
app/            application FastAPI
  config.py     settings + table de routing multi-campus (routing.json)
  security.py   IP réelle + validation campus <-> subnet
  authz.py      autoriser / révoquer / MAC via ARP (coeur du cycle de vie)
  sessions.py   sessions Redis (JSON), verrous, cache ARP, rate limit
  pfsense/      interface + client REST v2 + mock de développement
  keycloak_admin.py  lecture paginée des sessions (reconciler)
  reconciler.py réconciliation alias-first (CronJob */5 min)
templates/      gabarits de base (surchargables par thème)
themes/         personnalisation design — voir docs/THEMING.md
docs/           THEMING.md (design) · CONFIGURATION.md (tous les parametres)
config/         routing.example.json (ConfigMap en production)
deploy/k8s/     manifests RKE2 (namespace, portal, redis, ingress, cronjob)
tests/          pytest (15 tests, pfSense mocké, Redis simulé)
```

## Développement local (sans firewall ni Keycloak de prod)

```bash
docker compose -f docker-compose.dev.yml up --build
# http://localhost:8000/?campus=uac   — pfSense simulé (PORTAL_PFSENSE_MODE=mock)
```

Tests :
```bash
pip install -r requirements-dev.txt
pytest
```

## Production (RKE2)

1. Construire et pousser l'image : `registry.idadu.tech/captive-portal:v2`
2. Créer les Secrets : `portal-secret-key`, `keycloak-client`,
   `keycloak-reconciler`, et le Secret unique `pfsense-keys`
   (une entrée par site — voir docs/CONFIGURATION.md)
3. Créer la ConfigMap `campus-routing` à partir de `config/routing.json`
   (subnets réels confirmés site par site)
4. `kubectl apply -f deploy/k8s/`

## Points en attente des relevés A1 (volontairement isolés)

Tout est dans `app/pfsense/restv2.py`, derrière l'interface `PfSenseClient` :
- endpoint **unitaire** d'ajout/retrait d'adresse d'alias (si le Swagger T4
  le confirme, remplacer le lecture+PATCH actuel — le verrou campus couvre
  déjà la concurrence dans les deux cas) ;
- forme exacte de la réponse `diagnostics/arp_table` (clés `ip`/`mac`).

## Journalisation

Chaque autorisation/révocation émet une ligne JSON sur stdout
(`event`, `campus`, `ip`, `mac`, `user`) — collectée par la stack de logs
du cluster (obligation de traçabilité, DAT §12).
