# Comment le portail connaît l'adresse réelle du client (jeton d'IP)

## Le problème
Pour ouvrir Internet à un étudiant, le portail doit connaître son adresse
IP. Un client passe par deux chemins :

| Chemin | Ce que voit le portail |
|---|---|
| **HTTP** (requête interceptée par le pfSense) | L'adresse réelle : le HAProxy externe l'ajoute dans l'en-tête X-Forwarded-For |
| **HTTPS** (page du portail) | Seulement l'adresse d'un relais : le HAProxy transmet le flux chiffré sans pouvoir rien y ajouter |

## La solution retenue (21/11/2026)
Le portail se transmet l'adresse à lui-même :

1. Le client est intercepté en HTTP. Le portail connaît son adresse réelle
   et répond : « va sur `https://portal.rber.bj/?campus=uac&t=<jeton>` ».
2. Le jeton contient l'adresse, **signée** avec la clé secrète du portail
   (`SECRET_KEY`) et valable 5 minutes. Le client le transporte mais ne
   peut ni le fabriquer ni le modifier.
3. En HTTPS, le portail vérifie la signature, lit l'adresse, et s'en
   souvient 15 minutes dans la session (cookie signé) pour la suite du
   parcours : connexion RBERConnect, retour, autorisation.

Aucun changement sur le HAProxy, l'ingress ou les autres services.

## Ce que ça ne fait pas
- Un client qui ouvre directement `https://portal.rber.bj` sans avoir été
  intercepté n'a pas de jeton : il voit la page « hors réseau campus ».
  Pour le renvoyer automatiquement chercher un jeton, définir `BOUNCE_URL`
  (voir CONFIGURATION.md) avec un nom HTTP qui pointe sur le HAProxy.
- Les autres applications (Keycloak, Moodle) continuent de ne pas voir les
  adresses réelles en HTTPS. C'est l'objet du chantier PROXY protocol,
  suspendu.

## Règles de sécurité à ne pas défaire
- Le portail ne lit que la **fin** de X-Forwarded-For (ce que les relais
  ont ajouté) et **toutes** les lignes de l'en-tête. L'adresse écrite par
  le client n'est jamais crue (faille corrigée le 21/11).
- L'adresse fournie par le HAProxy n'est crue que sur le chemin HTTP.
- `SECRET_KEY` doit rester identique sur tous les réplicas et secrète :
  qui la connaît peut fabriquer des jetons.

## Vérifier depuis le banc
```bash
curl -v http://neverssl.com
#  attendu : 302, Location: https://portal.rber.bj/?campus=uac&t=...
```
Ouvrir ensuite ce lien : la page de connexion UAC doit s'afficher.
