# Certificat d'un pfSense : l'épingler dans le portail

## Pourquoi
Chaque pfSense présente un certificat auto-signé. Le portail refuse par
défaut de lui parler (`CERTIFICATE_VERIFY_FAILED`) : accepter n'importe
quel certificat permettrait à un équipement placé sur le réseau de se
faire passer pour le pfSense et de récupérer la clé API.

On « épingle » donc le certificat : pour chaque campus, on donne au
portail LE certificat de son pfSense. Il n'acceptera que celui-là.

## Procédure (par site, 5 minutes)

### 1. Récupérer le certificat, depuis le portail lui-même
```bash
kubectl -n captive-portal exec deploy/portal -- python -c \
  "import ssl; print(ssl.get_server_certificate(('10.24.112.34', 10443)))" > uac.pem
openssl x509 -in uac.pem -noout -fingerprint -sha256 -subject -enddate
```

### 2. Vérifier l'empreinte avec l'administrateur du pfSense — NE PAS SAUTER
L'empreinte SHA-256 affichée doit être identique à celle du certificat de
l'interface web du pfSense, relevée par un autre chemin (navigateur de
l'administrateur sur `https://10.24.112.34:10443` → cadenas → certificat →
empreinte SHA-256). Sans cette comparaison, on pourrait épingler le
certificat d'un imposteur.

### 3. Le donner au portail
```bash
# première fois
kubectl -n captive-portal create configmap pfsense-certs --from-file=uac.pem=uac.pem
# sites suivants : ajouter un fichier <campus>.pem
kubectl -n captive-portal create configmap pfsense-certs \
  --from-file=uac.pem=uac.pem --from-file=up.pem=up.pem \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n captive-portal rollout restart deploy/portal
```
Le nom du fichier est l'identifiant du campus dans `routing.json`
(`uac.pem`, `fss.pem`, ...).

### 4. Contrôler
Au cycle suivant du réconciliateur (5 minutes), l'erreur
`CERTIFICATE_VERIFY_FAILED` doit avoir disparu pour ce campus.

## À savoir
- Si le certificat du pfSense est régénéré (réinstallation, renouvellement),
  l'erreur revient : refaire la procédure.
- Un campus sans fichier garde la vérification standard.
- Le certificat est public : une ConfigMap suffit, pas besoin d'un Secret.
