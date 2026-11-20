# Audit du code IT-Captive-Portal (v1)

**Dépôt** : github.com/ojuwoni/IT-Captive-Portal — dernier commit 5bd1ec7 (10 janv. 2026)
**Volume** : 1 659 lignes Python (main.py 435, pfsense_api.py 501, sync_sessions.py 302, radius_coa.py 228, config 193)
**Cible** : adaptation v2 multi-campus RBER — registre image `registry.idadu.tech`
**Auditeur** : Claude pour IDADU TECH — 20 août 2026

---

## Verdict global

La couche OIDC/Keycloak, le theming et la structure FastAPI sont sains et réutilisables (~40 % du code). Le cœur du système — l'autorisation réseau via pfSense — est **non fonctionnel en l'état** et doit être réécrit, pas adapté. Trois bloquants rendent la v1 inutilisable en production, même mono-site.

---

## 1. Bloquants (le code ne peut pas fonctionner en production)

### B1 — Filtrage MAC impossible dans pfSense
`add_mac_to_alias()` insère des adresses MAC dans un alias de type `host`. Les alias pfSense de type host contiennent des IP/FQDN ; les règles firewall pf travaillent en L3 et **ne peuvent pas filtrer par MAC**. Le mécanisme central de la méthode `pfsense_api` est donc invalide. Conséquence : tout le modèle d'autorisation doit passer aux **IP** (conforme au DAT v2, alias `authorized_clients`), la MAC ne servant qu'à la validation et à la journalisation.

### B2 — Client API pfSense obsolète et partiellement faux
- Le code cible `pfSense-pkg-API v1` (`/api/v1/...`, header `Authorization: key secret`). Ce package est abandonné et incompatible avec pfSense Plus 24.x. Le DAT v2 impose la **REST API v2** (`/api/v2/...`, auth `X-API-Key`/Bearer, endpoints différents, réponses différentes). Réécriture complète du client.
- En mode FauxAPI, `get_dhcp_leases()` appelle `action=system_stats`, qui ne retourne pas les baux DHCP. Ce chemin de code n'a jamais pu fonctionner.
- La détection automatique pkg-api/fauxapi ajoute de la complexité pour deux APIs dont aucune n'est la cible. À supprimer.

### B3 — Fuite d'autorisation permanente à l'expiration des sessions
Chaîne du bug :
1. `authorize_mac()` écrit `session:{mac}` dans Redis avec TTL (8 h) et ajoute la MAC à l'alias.
2. À l'expiration du TTL, Redis supprime la clé — **personne ne retire la MAC de l'alias**.
3. `sync_sessions.py` itère sur les clés Redis pour décider des révocations ; la clé ayant disparu, la MAC orpheline n'est jamais vue.

Résultat : toute entrée d'alias devient un **accès permanent** après 8 h. L'alias grossit indéfiniment. La réconciliation doit itérer sur **l'alias pfSense** (source de vérité côté réseau) et le comparer à Redis/Keycloak, pas l'inverse.

---

## 2. Défauts majeurs (fonctionnent en apparence, cassent en charge ou sous attaque)

### M1 — Race condition read-modify-write sur l'alias
`add_mac_to_alias`/`remove_mac_from_alias` lisent la liste puis réécrivent la liste complète (PUT). Deux logins simultanés = une autorisation écrasée. Avec 2 réplicas K8s et 11 sites, c'est certain à la rentrée. Correctif : endpoints atomiques add/delete de l'API v2 + verrou Redis par site.

### M2 — X-Forwarded-For non fiable
`get_client_ip()` prend le premier XFF sans liste de proxies de confiance : header forgeable par le client. Pire en v2 : la chaîne HAProxy externe (TCP passthrough) → ingress ne produit pas de XFF représentant le client WiFi. Il faut le **PROXY protocol** de bout en bout ou s'appuyer sur l'IP source réelle vue par l'ingress, puis valider IP ∈ subnet du campus déclaré.

### M3 — Appels API pfSense non cachés sur `/` et `/status`
Chaque hit déclenche un GET DHCP leases vers pfSense. Les sondes captive-portal des OS (generate_204, hotspot-detect) multiplient les hits par client. À l'échelle d'un campus, le portail sature l'API du Netgate. Correctif : cache Redis des leases (TTL 30-60 s) + endpoints CNA dédiés.

### M4 — Pagination Keycloak absente dans sync_sessions.py
`get_active_sessions()` ne passe pas `first`/`max` ; Keycloak pagine par défaut. Au-delà de la première page, les utilisateurs actifs sont invisibles → **révoqués à tort** par le sync. En période de pointe, déconnexions massives injustifiées.

### M5 — Bug de cache du token admin Keycloak
`self.token_expires = datetime.utcnow()` — `expires_in` est calculé puis jamais appliqué. Le cache est toujours expiré : un token demandé à chaque appel. Charge inutile sur Keycloak.

### M6 — TLS et secrets
`PFSENSE_VERIFY_SSL=false` par défaut : Bearer token exposé à l'interception sur le MPLS. `SECRET_KEY` par défaut faible dans le code. Correctif v2 : CA interne ou pinning des certs pfSense, secrets K8s obligatoires, aucune valeur par défaut de production.

---

## 3. Écart avec le DAT v2 (fonctionnalités absentes)

| Exigence DAT v2 | État dans le code |
|---|---|
| Routing multi-campus `?campus=` | Absent — un seul `PFSENSE_URL` global |
| ConfigMap `routing.json` (11 sites) | Absent |
| Secrets par campus (`pfsense-key-*`) | Absent — un seul couple key/secret |
| Campus conservé entre login et callback | Absent (seuls IP/MAC en session) |
| Page fallback campus manquant | Absente |
| Alias IP `authorized_clients` | Non — alias MAC (invalide, cf. B1) |
| REST API v2 Bearer | Non — pkg-API v1 / FauxAPI |
| Image `registry.idadu.tech/captive-portal:v2` | Dockerfile root + compose `privileged: true` — incompatible PodSecurity K8s |

## 4. Défauts mineurs

1. Sessions Redis stockées en `"username:timestamp-ISO"` puis `split(":")` — l'ISO contient des `:`, le timestamp est tronqué. Passer à JSON.
2. Fallback ARP (`ip neigh`) et nftables : code mort en déploiement centralisé (jamais le même L2 que les clients). À retirer de l'image v2 avec les paquets système associés.
3. `@app.on_event` déprécié (FastAPI ≥ 0.109) → lifespan.
4. Service account `realm-admin` recommandé par le README : privilèges excessifs, `view-users` suffit.
5. Aucun test automatisé, aucun linting, aucune CI.
6. Journalisation non structurée, pas de trace user↔MAC↔IP↔campus horodatée (obligation légale de rétention).

## 5. Ce qui est réutilisable tel quel

1. Flux OIDC Authlib (login/callback/logout) — corriger la gestion d'erreur du callback (500 génériques).
2. Theming par variables d'env + templates Jinja2 — base des 4 thèmes universités.
3. Structure FastAPI + settings Pydantic.
4. Squelette de sync_sessions.py (logique inversée à corriger, cf. B3).

## 6. Plan de reprise recommandé (ordre)

| # | Chantier | Portée |
|---|---|---|
| 1 | Client REST API v2 pfSense (IP alias, endpoints atomiques, Bearer, TLS vérifié) | Réécriture pfsense_api.py |
| 2 | Modèle d'autorisation IP + validation MAC via leases + validation subnet/campus | main.py |
| 3 | Routing multi-campus (routing.json, secrets montés, session campus, fallback) | main.py + config |
| 4 | Réconciliation alias-first + TTL + pagination Keycloak + fix token cache | sync_sessions.py |
| 5 | Cache leases + endpoints CNA + rate limiting | main.py |
| 6 | Image non-root sans nftables, manifests K8s, logs structurés JSON | Dockerfile + deploy |
| 7 | Tests (unitaires client API, e2e flux campus simulé) | nouveau |

Estimation : chantiers 1-4 sont le chemin critique avant tout pilote UAC. Les chantiers 5-7 peuvent suivre pendant le pilote.

---

## Conclusion

Ne pas "adapter" la v1 : son mécanisme central (MAC dans un alias pf) n'a jamais été viable sur pfSense, et la révocation fuit par construction. Repartir de la base OIDC/theming (saine) et réécrire la couche réseau selon le DAT v2, en corrigeant les quatre points que le DAT lui-même ne couvre pas : atomicité des écritures d'alias, réconciliation alias-first, validation IP/subnet, cache des leases.
