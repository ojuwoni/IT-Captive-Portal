# Fenêtre PROXY protocol — Dossier d'exécution

> **STATUT : SUSPENDU — NE PAS EXÉCUTER EN L'ÉTAT (21/11/2026).**
> La tentative du 20/11 a coupé le HTTPS du cluster et a été annulée par
> rollback. Deux hypothèses de ce dossier étaient fausses :
> 1. le service de l'ingress est en `externalTrafficPolicy: Cluster` : le
>    cluster réécrit l'adresse source, l'ingress voit `10.42.x.0` et non
>    l'adresse du HAProxy — la règle `proxy-protocol` ne s'applique jamais ;
> 2. il y a DEUX serveurs HAProxy (10.29.113.21 et .22, adresse virtuelle
>    .20) : la règle doit lister les deux, et le fichier doit être posé
>    sur les deux.
> Le besoin du portail est couvert autrement (voir `Jeton_IP.md`). Une
> reprise demande d'abord : service ingress en `Local`, liste .21 + .22,
> 21 lignes sur les deux serveurs, et une répétition préalable.

## 0. Le pourquoi, en langage simple (à lire avant tout)

**Le problème.** Pour ouvrir Internet à un étudiant, le portail doit
connaître son adresse IP — c'est elle qu'il inscrit dans le firewall de
son campus. Or entre l'étudiant et le portail il y a un relais, le HAProxy
(10.29.113.21). Ce relais fonctionne comme quelqu'un qui reçoit votre
lettre, la met dans SA propre enveloppe, et la poste : le portail ne voit
que l'adresse du relais. Tous les étudiants du Bénin semblent s'appeler
« 10.29.113.21 » — impossible de savoir qui autoriser. C'est exactement ce
que les tests du banc ont montré : page « hors réseau campus » pour tout
le monde. Sans corriger cela, le portail ne peut pas fonctionner.

**La solution.** Le PROXY protocol est une convention toute simple : le
relais écrit une première ligne au début de chaque envoi —
« expéditeur d'origine : 10.24.127.22 » — puis le contenu normal. Le
destinataire (l'ingress du cluster, 10.29.113.201) lit cette ligne, la
retire, et sait enfin à qui il parle.

**Aucune adresse ne remplace une autre.** La chaîne reste :
étudiant → relais .21 → destinataire .201 → portail. La « .21 » qu'on
inscrit côté cluster n'est pas du routage : c'est le nom du livreur
concerné par la nouvelle règle (« de la part de .21, j'attends désormais
la ligne d'expéditeur »).

**Pourquoi une coupure, et pourquoi elle touche aussi les autres services.**
La convention est un accord de langue entre les deux bouts du tuyau :

| Le relais écrit la ligne | Le destinataire l'attend | Résultat |
|---|---|---|
| Non | Non | Ça marche (situation actuelle) |
| Oui | Oui | Ça marche (situation cible) |
| Oui | Non | Cassé — le destinataire lit du charabia |
| Non | Oui | Cassé — le destinataire rejette |

On ne peut pas actionner les deux interrupteurs au même instant exact :
pendant les quelques secondes entre les deux, on est dans un cas « cassé ».
C'est toute la coupure : l'instant du changement de langue. Elle touche
tous les services du cluster (Keycloak, Moodle, Harbor, Gitea, ArgoCD,
Grafana…) parce qu'ils voyagent dans le même tuyau — la
langue se change pour le tuyau entier, pas site par site. Après, ils
fonctionnent exactement comme avant : la première ligne est lue et
retirée, le reste ne change pas pour eux.

**Temporaire ou définitif ?** La configuration est DÉFINITIVE — une fois
posée, chaque connexion portera pour toujours l'adresse réelle du client,
et plus personne n'y retouche. Seule la COUPURE est temporaire : quelques
secondes, le temps que les deux maillons changent de langue ensemble.
D'où une fenêtre courte, préparée, à heure creuse.

---

**Objet.** Faire voyager l'adresse IP réelle des clients WiFi jusqu'au portail
captif sur la jambe HTTPS (frontend TCP/SNI). Dernier prérequis du pilote
T-INT : après cette fenêtre, un client du banc UAC verra la page de
connexion au lieu de « hors réseau campus ».

**Périmètre impacté.** Toutes les connexions du HAProxy externe vers l'ingress
RKE2 (10.29.113.201) — 21 lignes `server` dans le fichier — soit tous les services publiés via le cluster : auth.rber.bj (Keycloak), les 4 Moodle, cloud, transport-u, teleenseignement, rber.bj, portail, ET forge, registre (Harbor — pushes CI), git (Gitea), support (Zammad), fichiers, backstage, ops (ArgoCD, interface web), docs, wiki, grafana. Coupure effective : **moins d'une minute** si le déroulé est préparé ;
fenêtre réservée : 30 minutes.

**Pourquoi tout doit basculer en même temps (lu dans la doc officielle du
contrôleur) :** l'option ConfigMap `proxy-protocol` liste des sources ; dès
qu'une source y figure, toute connexion venant d'elle SANS en-tête PROXY
est rejetée (400 Bad Request). Le HAProxy externe (10.29.113.21) étant la
source de tout le trafic public, l'acceptation côté ingress et l'envoi
côté HAProxy doivent être activés dans la même minute — et les health
checks du HAProxy doivent eux-mêmes envoyer l'en-tête (`check-send-proxy`),
sans quoi ils échoueraient et marqueraient les backends morts.

---

## 1. Préparation (J-1, hors fenêtre, sans impact)

### 1.0 — Pré-vérification obligatoire : quelle adresse l'ingress voit-il ?
La règle côté ingress liste la source autorisée à parler PROXY protocol
(10.29.113.21). Si le cluster réécrit l'adresse source en route (SNAT du
service LoadBalancer), l'ingress verrait une adresse de nœud au lieu de
.21 — la règle ne s'appliquerait pas et tout casserait. On le vérifie
AVANT, avec le journal du portail (qui affiche l'adresse vue par l'ingress) :
```bash
# depuis la VM 10.29.113.163 (passe par le HAProxy .21) :
curl -sk -o /dev/null --resolve portal.rber.bj:443:10.29.113.21 "https://portal.rber.bj/?campus=uac"
# depuis le bastion :
kubectl -n captive-portal logs -l app=portal --tail=100 | grep campus_rejected | tail -1
```
- `"ip": "10.29.113.21"` → OK, la valeur de la ConfigMap (§ 1.2) est la bonne.
- Toute autre adresse (nœud 10.29.113.x, 10.42.x.x) → STOP : le service
  LoadBalancer réécrit la source ; il faut d'abord passer son
  `externalTrafficPolicy` à `Local` (ou adapter la liste) — à revoir
  avec IDADU TECH avant de fixer la date.

### 1.1 — Le fichier HAProxy de la fenêtre (fourni, prêt)
Fichier : `haproxy_FENETRE_PROXY_protocol.cfg`, établi à partir de la
configuration de production actuelle. **Les 21 lignes `server` qui visent
l'ingress (10.29.113.201)** — et pas seulement les deux backends du
portail : forge, registre, gitea, support, fichiers, backstage, ops, docs,
wiki, grafana (en 80 et 443) et bk_k8s_ingress(_https) — reçoivent
`send-proxy-v2` et `check-send-proxy`. Rien d'autre ne change.

Pourquoi toutes : la règle côté ingress s'applique à TOUTE connexion venant
de .21. Une seule ligne oubliée = un service coupé après la fenêtre.

```bash
sudo cp haproxy_FENETRE_PROXY_protocol.cfg /root/haproxy.cfg.proxyproto
sudo haproxy -c -f /root/haproxy.cfg.proxyproto      # DOIT être valid
diff /etc/haproxy/haproxy.cfg /root/haproxy.cfg.proxyproto | grep '^>' | grep -c send-proxy-v2
#    attendu : 21
```
Si la production a changé depuis le 20/11 (nouveau service ajouté),
redemander le fichier à jour : toute nouvelle ligne vers .201 doit aussi
porter `send-proxy-v2 check-send-proxy`.

### 1.2 — Préparer les deux commandes kubectl (bastion)
```bash
# Activation (sera lancée en T1) :
kubectl -n haproxy-controller patch configmap haproxy-kubernetes-ingress \
  -p '{"data":{"proxy-protocol":"10.29.113.21/32"}}'

# Rollback côté ingress (en cas de besoin) :
kubectl -n haproxy-controller patch configmap haproxy-kubernetes-ingress \
  --type=json -p='[{"op":"remove","path":"/data/proxy-protocol"}]'
```
Vérifier le nom exact de la ConfigMap :
`kubectl -n haproxy-controller get cm` (attendu : haproxy-kubernetes-ingress).

### 1.3 — Annonce
Prévenir les équipes : interruption possible < 1 minute sur tous les services publiés via le cluster : auth.rber.bj (Keycloak), les 4 Moodle, cloud, transport-u, teleenseignement, rber.bj, portail, ET forge, registre (Harbor — pushes CI), git (Gitea), support (Zammad), fichiers, backstage, ops (ArgoCD, interface web), docs, wiki, grafana, à l'heure choisie
(heure creuse recommandée : tôt le matin).

### 1.4 — Postes de contrôle pendant la fenêtre
- Fenêtre A (bastion) : les deux commandes kubectl prêtes.
- Fenêtre B (rber-ldb-int-01) : copie du fichier + reload prêts.
- Fenêtre C : les commandes de vérification du § 3 prêtes à coller.
- Un testeur joignable sur le banc UAC (Gildas) pour la vérification finale.

---

## 2. Déroulé minuté (jour J)

| T | Qui | Action |
|---|-----|--------|
| T0 | B | `sudo cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak-$(date +%F-%H%M)` |
| T1 | A | Lancer le patch ConfigMap (§ 1.2). **La coupure commence** (le contrôleur recharge et exige l'en-tête PROXY depuis .21) |
| T1+10s | B | `sudo cp /root/haproxy.cfg.proxyproto /etc/haproxy/haproxy.cfg && sudo haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy`. **La coupure se termine** |
| T2 | C | Dérouler les vérifications du § 3 dans l'ordre |
| T2+5min | Banc | Vérification finale depuis le poste du banc (§ 3, point 5) |

En cas d'échec à n'importe quelle étape → § 4 Rollback (les deux côtés,
toujours par paire).

---

## 3. Vérifications (dans l'ordre, toutes doivent passer)

```bash
# 1. TOUS les backends vers l'ingress sont UP (preuve que check-send-proxy marche)
echo "show stat" | sudo socat stdio /run/haproxy/admin.sock | grep -E "k8s-ingress|haproxy-ingress|forge1|registre1" | cut -d, -f1,2,18
#    attendu : UP partout (21 lignes) — aucun DOWN

# 2. Les services existants répondent (jambe HTTPS/TCP)
curl -sk -o /dev/null -w "auth: %{http_code}\n" https://auth.rber.bj/realms/RBERConnect/.well-known/openid-configuration
curl -sk -o /dev/null -w "moodle: %{http_code}\n" https://elearning.uac.bj/
curl -sk -o /dev/null -w "registre: %{http_code}\n" https://registre.rber.bj/v2/
curl -sk -o /dev/null -w "ops: %{http_code}\n" https://ops.rber.bj/
#    attendu : 200 (ou 30x pour moodle) — PAS de 400, PAS de timeout

# 3. La jambe HTTP vit toujours (redirections connues + interception)
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" -H "Host: auth.rber.bj" http://10.29.113.21/
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" -H "Host: neverssl.com" http://10.29.113.21/
#    attendu : 301 https://auth... puis 302 https://portal...

# 4. Pas de flot d'erreurs côté contrôleur
kubectl -n haproxy-controller logs deploy/haproxy-kubernetes-ingress --tail=30 | grep -i -c "400\|error"

# 5. LE TEST FINAL — depuis le poste du banc UAC :
#    ouvrir https://portal.rber.bj/ dans le navigateur
#    attendu : la PAGE DE CONNEXION UAC (« Se connecter avec mon compte
#    universitaire »), et non plus « hors réseau campus ».
#    C'est le critère de réussite de toute la fenêtre.
```

Vérification complémentaire dans les minutes qui suivent : le journal du
portail doit montrer les IP réelles des clients —
`kubectl -n captive-portal logs deploy/portal --tail=20`.

## 4. Rollback (symétrique, toujours les DEUX côtés)

```bash
# B : restaurer le fichier et recharger
sudo cp /etc/haproxy/haproxy.cfg.bak-<date> /etc/haproxy/haproxy.cfg
sudo systemctl reload haproxy
# A : retirer la clé de la ConfigMap (commande du § 1.2)
```
Retour à l'état actuel en moins d'une minute ; la page « hors réseau
campus » redevient le comportement du banc.

## 5. Après la fenêtre

1. Les testeurs enchaînent directement T-INT-3 (connexion complète PC avec
   un compte RBERConnect) puis T-INT-4 (téléphones) — protocole T-INT § 4.
2. Consigner l'heure, la durée de coupure réelle et les sorties du § 3
   dans un relevé (même format que les précédents).
3. IDADU TECH met à jour le DAT (v2.2) : PROXY protocol actif, chaîne
   complète documentée telle que construite.

---
*Référence : DAT v2.1 § 8 · Note_preparation_HAProxy.docx (oct. 2026) ·
doc officielle du contrôleur (ConfigMap `proxy-protocol`, exigence stricte
pour les sources listées). La seule décision restante est la date.*
