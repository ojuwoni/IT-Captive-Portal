# Fenêtre PROXY protocol — Dossier d'exécution

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

**Pourquoi une coupure, et pourquoi elle touche Keycloak et les Moodle.**
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
Keycloak et les Moodle parce qu'ils voyagent dans le même tuyau — la
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

**Périmètre impacté.** Tout le trafic passant par les backends
`bk_k8s_ingress` (80) et `bk_k8s_ingress_https` (443) du HAProxy externe :
auth.rber.bj (Keycloak), les 4 Moodle, cloud, transport-u, teleenseignement,
rber.bj, portail. Coupure effective : **moins d'une minute** si le
déroulé est préparé ; fenêtre réservée : 30 minutes.

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

### 1.1 — Préparer la configuration HAProxy modifiée
Sur `rber-ldb-int-01`, préparer (sans l'appliquer) une copie du fichier où
SEULES les deux lignes `server` des backends K8s changent :

```
backend bk_k8s_ingress
    mode http
    balance roundrobin
    option httpchk
    http-check send meth GET uri /
    http-check expect rstatus ^(2|3|4)[0-9][0-9]
    server k8s-ingress 10.29.113.201:80 send-proxy-v2 check check-send-proxy inter 5s fall 3 rise 2

backend bk_k8s_ingress_https
    mode tcp
    balance roundrobin
    option ssl-hello-chk
    timeout tunnel 86400s
    timeout server 86400s
    server k8s-ingress 10.29.113.201:443 send-proxy-v2 check check-send-proxy inter 5s fall 3 rise 2
```
(= ajout de `send-proxy-v2` et `check-send-proxy` sur chaque ligne server ;
rien d'autre ne change dans le fichier.)

```bash
sudo cp /etc/haproxy/haproxy.cfg /root/haproxy.cfg.proxyproto   # copie de travail
# ... éditer les 2 lignes server comme ci-dessus ...
sudo haproxy -c -f /root/haproxy.cfg.proxyproto                 # DOIT être valid
```

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
Prévenir les équipes : interruption possible < 1 minute sur auth.rber.bj,
les Moodle, cloud, transport-u, teleenseignement, rber.bj, à l'heure choisie
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
# 1. Les backends sont UP côté HAProxy (preuve que check-send-proxy marche)
echo "show stat" | sudo socat stdio /run/haproxy/admin.sock | grep k8s-ingress | cut -d, -f1,2,18
#    attendu : ...,k8s-ingress,UP  (les deux backends)

# 2. Les services existants répondent (jambe HTTPS/TCP)
curl -sk -o /dev/null -w "auth: %{http_code}\n" https://auth.rber.bj/realms/RBERConnect/.well-known/openid-configuration
curl -sk -o /dev/null -w "moodle: %{http_code}\n" https://elearning.uac.bj/
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
