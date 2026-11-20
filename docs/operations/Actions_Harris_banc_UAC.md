# Actions Harris — Banc de test UAC (pilote T-INT)

**Contexte.** Le portail v2 est en production sur le cluster (https://portal.rber.bj,
certificat valide). Le banc de test UAC doit maintenant être re-câblé de
l'ancienne cible (le simulateur sur la VM 10.29.113.163, qui a pris sa retraite)
vers la vraie chaîne de production (HAProxy externe 10.29.113.21). Le symptôme
actuel — « Afficher la page de connexion du réseau » qui tourne sans fin —
vient très probablement d'un re-câblage incomplet.

---

## 1. D'abord : relever l'état actuel des trois objets du banc

Avant de rien changer, noter la valeur ACTUELLE de ces trois objets sur le
pfSense UAC (c'est ce que signifie « confirmer l'état » : on veut savoir
d'où on part, pour comprendre le symptôme et savoir quoi changer) :

| # | Objet | Où le voir | Valeur actuelle à noter |
|---|-------|------------|-------------------------|
| 1 | **Host override** `portal.rber.bj` | Services → DNS Resolver → Host Overrides | IP : 10.29.113.163 (VM) ou 10.29.113.21 (HAProxy) ? |
| 2 | **Port forward** du port 80 (interface du banc) | Firewall → NAT → Port Forward | Redirect target : VM:80 ou autre ? |
| 3 | **Règle firewall n°3** du banc (accès portail) | Firewall → Rules → interface du banc | Destination et ports autorisés : VM seule ? |

---

## 2. Ensuite : la configuration CIBLE (celle du pilote)

### 2.1 — Host override → HAProxy
```
Services → DNS Resolver → Host Overrides → portal.rber.bj
  IP Address : 10.29.113.21          ← le HAProxy externe, plus la VM
Save + Apply
```

### 2.2 — Règle firewall du banc : autoriser le chemin du portail réel
La règle qui autorisait les clients non authentifiés vers la VM doit
désormais autoriser le HAProxy, en HTTP et HTTPS :
```
Firewall → Rules → interface du banc — règle « accès portail » :
  Source      : any (clients non authentifiés)
  Destination : 10.29.113.21
  Ports       : 80 et 443
Save + Apply
```
(Garder aussi la destination VM tant qu'on veut pouvoir revenir en
arrière, ou la retirer — au choix ; noter ce qui est fait.)

### 2.3 — Port forward du port 80 : rediriger vers le HAProxy
```
Firewall → NAT → Port Forward — règle du port 80 :
  Source           : ! authorized_clients_test   (inchangé)
  Destination      : any — port 80               (inchangé)
  Redirect target  : 10.29.113.21 — port 80      ← au lieu de la VM
Save + Apply
```
Le HAProxy route le port 80 de portal.rber.bj vers le cluster, qui
redirige en HTTPS — c'est le chemin de production.

### 2.4 — Rien d'autre ne change
L'alias `authorized_clients_test`, les règles DNS/DHCP et le reste du
banc restent tels quels. L'access list de l'API (déjà faite) n'est pas
concernée.

---

## 3. Vérifications après le re-câblage (depuis le poste du banc)

```bash
nslookup portal.rber.bj
#  attendu : 10.29.113.21

curl -v http://neverssl.com
#  attendu : 302 → https://portal.rber.bj/?campus=uac

curl -v https://portal.rber.bj/
#  attendu : certificat Let's Encrypt VALIDE (sans -k) + une page du portail
```

Puis le test du bouton « Afficher la page de connexion du réseau » :
la page du portail doit s'afficher (plus de rotation infinie).

## 4. Point d'attention — ce que la page affichera

Si la page qui s'affiche dit **« hors réseau campus »** au lieu de
proposer la connexion : ce n'est PAS une erreur de câblage. Cela signifie
que l'adresse IP réelle du client ne traverse pas encore la chaîne
(PROXY protocol — vérification en cours côté datacenter, hors périmètre
pfSense). Dans ce cas : s'arrêter là et le signaler, le câblage du banc
est bon et c'est l'autre chantier qui doit aboutir d'abord.

## 5. Relevés à renvoyer

1. État AVANT (tableau du § 1 rempli).
2. Captures des trois objets APRÈS modification.
3. Sorties des trois commandes du § 3.
4. Ce que montre le bouton de connexion réseau (capture du poste/téléphone).
