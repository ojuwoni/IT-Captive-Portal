# Configuration du portail — tous les paramètres

Règle du projet : **aucune valeur métier dans le code**. Trois lieux de
configuration, chacun avec son rôle :

| Lieu | Contient | Modifié par |
|---|---|---|
| Variables d'environnement | comportement du portail (TTL, limites, URLs) | exploitation |
| `routing.json` (ConfigMap `campus-routing`) | les sites : subnets, pfSense, thème | exploitation |
| `themes/` (ConfigMap `portal-themes`) | toute l'apparence | équipes design (voir THEMING.md) |

## Variables d'environnement

Toute variable se définit en MAJUSCULES (ex. `SESSION_TTL=14400`), via
l'environnement, un fichier `.env` en dev, ou les manifests K8s.

### Application
| Variable | Défaut | Rôle |
|---|---|---|
| `PUBLIC_BASE_URL` | `https://portal.rber.bj` | URL publique du portail (redirections, callback OIDC) |
| `SECRET_KEY` | — | **Obligatoire en prod** : signature du cookie de session |
| `DEBUG` | `false` | Mode développement (cookies non-https) |

### Keycloak (RBERConnect)
| Variable | Défaut | Rôle |
|---|---|---|
| `KEYCLOAK_URL` | `https://auth.rber.bj` | Base Keycloak |
| `KEYCLOAK_REALM` | `rber` | Realm |
| `KEYCLOAK_CLIENT_ID` | `captive-portal` | Client OIDC du portail |
| `KEYCLOAK_CLIENT_SECRET` / `_FILE` | — | Secret du client (fichier prioritaire — Secret K8s) |
| `KEYCLOAK_ADMIN_CLIENT_ID` | `portal-reconciler` | Compte de service du réconciliateur |
| `KEYCLOAK_ADMIN_CLIENT_SECRET` / `_FILE` | — | Son secret |
| `KEYCLOAK_ADMIN_PAGE_SIZE` | `100` | Pagination de la lecture des sessions |

### Sessions, autorisations, protection
| Variable | Défaut | Rôle |
|---|---|---|
| `SESSION_TTL` | `28800` (8 h) | Durée d'une autorisation WiFi |
| `RATE_LIMIT_ENABLED` | `true` | Active la limitation sur /login et /callback |
| `RATE_LIMIT_PER_MINUTE` | `20` | Tentatives par IP et par minute |
| `ARP_CACHE_TTL` | `45` | Cache des tables ARP (s) — protège l'API pfSense |
| `CAMPUS_LOCK_TTL_MS` | `5000` | Durée max du verrou d'écriture d'alias |
| `CAMPUS_LOCK_RETRY_MS` | `50` | Attente entre deux essais de verrou |

### pfSense
| Variable | Défaut | Rôle |
|---|---|---|
| `PFSENSE_MODE` | `restv2` | `mock` = firewall simulé (dev/démo sans pfSense) |
| `PFSENSE_VERIFY_TLS` | `true` | Vérification TLS des API pfSense |
| `PFSENSE_CA_BUNDLE` | — | CA interne RBER (chemin) — prioritaire |
| `PFSENSE_TIMEOUT` | `10.0` | Timeout des appels API (s) |

### Réseau / fichiers
| Variable | Défaut | Rôle |
|---|---|---|
| `TRUSTED_PROXIES` | `127.0.0.1/32,10.42.0.0/16` | CIDR autorisés à transmettre X-Forwarded-For (ingress) |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis |
| `ROUTING_PATH` | `config/routing.json` | Table des campus |
| `SECRETS_DIR` | `secrets` | Dossier des clés API pfSense |
| `THEMES_DIR` / `TEMPLATES_DIR` / `STATIC_DIR` | `themes` / `templates` / `static` | Répertoires |

## routing.json — la liste des sites

Une entrée par campus ; le portail la **recharge automatiquement** quand le
fichier change (mise à jour de la ConfigMap, sans redéploiement) :

```json
"nouveau": {
  "site": "Nom affiché",
  "universite": "Université de rattachement",
  "subnet": "10.27.0.0/16",
  "pfsense_url": "https://10.27.112.34:10443",
  "pfsense_alias": "authorized_clients",
  "api_key_secret": "pfsense-key-nouveau",
  "theme": "uac"
}
```

### Ajouter un 12e site — checklist complète
1. Côté pfSense du site : package REST API v2, alias, règles, host override
   (protocole T-SITE).
2. Ajouter la clé API au Secret unique :
   `kubectl -n captive-portal patch secret pfsense-keys -p '{"stringData":{"pfsense-key-nouveau":"<CLÉ>"}}'`
3. Ajouter l'entrée dans la ConfigMap `campus-routing`.
4. C'est tout : aucun redéploiement, aucun code, aucun manifest.

## Ce qui n'est PAS paramétrable (volontairement)
- Le sens de la réconciliation (alias-first) et la validation
  campus ↔ subnet : ce sont des invariants de sécurité du DAT v2.1.
- Les chemins des endpoints pfSense : isolés dans `app/pfsense/restv2.py`,
  ajustés une fois pour toutes d'après les relevés A1.
