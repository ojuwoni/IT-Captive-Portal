# CI/CD et GitOps — comment le portail se déploie

## Vue d'ensemble

```
développeur ── push v2 ──> GitHub Actions
                             1. pytest (15 tests)
                             2. build de l'image Docker
                             3. push registre.rber.bj/rber/captive-portal:<sha>
                             4. commit du tag dans deploy/k8s/kustomization.yaml
                                        │
cluster RKE2 <── sync ── ArgoCD ────────┘  (surveille deploy/k8s, branche v2)
```

Personne ne lance `kubectl apply` à la main : **git est la seule source de
vérité**. Ce qui tourne sur le cluster = le contenu de `deploy/k8s` au
dernier commit. Toute modification est tracée, revue, réversible.

## Mise en place (une fois)

### 1. Secrets GitHub Actions
Dépôt GitHub → Settings → Secrets and variables → Actions → New repository secret :
- `REGISTRY_USERNAME` = `robot$rber+dev-autonomie`
- `REGISTRY_PASSWORD` = le secret du robot (jamais dans le code)

### 2. Secrets du cluster (hors git, volontairement)
```bash
kubectl create namespace captive-portal
kubectl -n captive-portal create secret docker-registry regcred \
  --docker-server=registre.rber.bj \
  --docker-username='robot$rber+dev-autonomie' \
  --docker-password='<SECRET_ROBOT>'
kubectl -n captive-portal create secret generic portal-secret-key \
  --from-literal=secret-key="$(openssl rand -hex 32)"
kubectl -n captive-portal create secret generic keycloak-client \
  --from-literal=client-secret='<SECRET_CLIENT_OIDC>'
kubectl -n captive-portal create secret generic keycloak-reconciler \
  --from-literal=admin-secret='<SECRET_RECONCILER>'
kubectl -n captive-portal create secret generic pfsense-keys \
  --from-literal=pfsense-key-uac='<CLE_API_UAC>'   # + un par site
kubectl -n captive-portal create configmap campus-routing \
  --from-file=routing.json=config/routing.json
```

### 3. ArgoCD
```bash
kubectl create namespace argocd
kubectl apply -n argocd \
  -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
kubectl apply -f deploy/argocd/application.yaml
# Interface web : kubectl -n argocd port-forward svc/argocd-server 8080:443
# Mot de passe initial :
kubectl -n argocd get secret argocd-initial-admin-secret \
  -o jsonpath='{.data.password}' | base64 -d
```

## Vie courante

| Besoin | Geste |
|---|---|
| Déployer une évolution du code | push sur `v2` — la CI fait le reste |
| Changer un paramètre (TTL, rate limit…) | éditer `deploy/k8s/20-portal.yaml`, push — ArgoCD applique |
| Ajouter un site | ConfigMap + Secret (docs/CONFIGURATION.md) — hors git car secret |
| **Rollback** | remettre l'ancien sha dans `kustomization.yaml` (`git revert` du commit `ci: deploie …`), push |
| Voir ce qui tourne | interface ArgoCD, ou `git log deploy/k8s/kustomization.yaml` |

## Garde-fous
- `[skip ci]` sur les commits de la CI : pas de boucle infinie.
- `concurrency` : un seul pipeline à la fois par branche.
- ArgoCD `selfHeal` : une modification manuelle du cluster est écrasée —
  c'est voulu, tout passe par git.
- Les secrets ne sont **jamais** dans le dépôt : GitHub Secrets côté CI,
  Secrets Kubernetes côté cluster.
