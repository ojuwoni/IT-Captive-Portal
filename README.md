# Portail Captif SSO avec Keycloak

Portail captif WiFi avec authentification OIDC Keycloak. Une seule authentification pour le WiFi et toutes les applications.

## Pourquoi ce projet ?

Problèmes résolus :
1. **pfSense captive portal ne scale pas** : erreurs "bad gateway" autour de 4000 sessions
2. **Double authentification** : WiFi puis applications = 2 logins
3. **Pas de SSO** : le portail pfSense ne supporte pas OIDC/SAML

## Architecture globale

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              INTERNET                                        │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────────────────┐
│                              pfSense                                         │
│                    (Firewall/NAT/DHCP/Gateway)                              │
│              Portail captif natif DÉSACTIVÉ après migration                  │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                    Alias: authorized_macs                            │   │
│   │        (Liste des MACs autorisées, gérée via API pfSense)           │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
└───────┬──────────────────┬──────────────────┬──────────────────┬────────────┘
        │                  │                  │                  │
   ┌────▼────┐       ┌─────▼─────┐      ┌─────▼─────┐      ┌─────▼─────┐
   │ VLAN 10 │       │  VLAN 20  │      │  VLAN 30  │      │  VLAN xx  │
   │  WiFi   │       │   Admin   │      │  Serveurs │      │   ...     │
   │ Guests  │       │           │      │           │      │           │
   └────┬────┘       └───────────┘      └─────┬─────┘      └───────────┘
        │                                     │
        │                          ┌──────────┴──────────┐
   ┌────▼────┐                     │                     │
   │ Bornes  │              ┌──────▼──────┐       ┌──────▼──────┐
   │  WiFi   │              │   Portail   │       │  Keycloak   │
   │         │              │   Captif    │       │ (RBER Conn) │
   └─────────┘              │  (FastAPI)  │       └─────────────┘
                            └──────┬──────┘
                                   │
                            ┌──────▼──────┐
                            │    Redis    │
                            │ (sessions)  │
                            └─────────────┘
```

---

## Comment différencier le trafic autorisé du trafic non-autorisé ?

C'est LA question centrale d'un portail captif. Quand un client WiFi se connecte, il doit d'abord s'authentifier via le portail (Keycloak) avant d'accéder à Internet. La question est : **comment le réseau sait-il qui est autorisé et qui ne l'est pas ?**

Ce projet supporte **3 méthodes** selon votre infrastructure :

| Méthode | Quand l'utiliser | Complexité |
|---------|------------------|------------|
| **pfSense API** | Environnement pfSense, multi-VLAN | Moyenne |
| **RADIUS CoA** | Bornes enterprise, infra RADIUS existante | Élevée |
| **nftables** | Lab, petit réseau, même VLAN | Faible |

---

### Méthode 1 : pfSense API (RECOMMANDÉE)

**Principe :** pfSense gère l'autorisation via un **Alias** (liste de MACs). Le portail captif met à jour cet Alias via l'**API pfSense** après authentification Keycloak.

```
┌─────────────────────────────────────────────────────────────────┐
│                        FLUX pfSense API                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Client WiFi                     pfSense                       │
│   ┌─────────┐                    ┌─────────────────────┐       │
│   │ MAC: AA │                    │ Alias: authorized   │       │
│   │ IP: .50 │                    │ ┌─────────────────┐ │       │
│   └────┬────┘                    │ │ (vide)          │ │       │
│        │                         │ └─────────────────┘ │       │
│        │ 1. HTTP request         └──────────┬──────────┘       │
│        ├────────────────────────────────────┤                  │
│        │                                    │                  │
│        │ 2. MAC pas dans Alias = BLOQUÉ    │                  │
│        │    Redirigé vers Portail          │                  │
│        │                                    │                  │
│        ▼                                    │                  │
│   ┌─────────┐     3. Auth Keycloak         │                  │
│   │ Portail │◄─────────────────────────────┤                  │
│   │ Captif  │                              │                  │
│   └────┬────┘                              │                  │
│        │                                    │                  │
│        │ 4. Keycloak OK → Token reçu       │                  │
│        │                                    │                  │
│        │ 5. API pfSense: ajouter MAC       │                  │
│        ├───────────────────────────────────►│                  │
│        │    POST /api/v1/firewall/alias    │                  │
│        │                                    │                  │
│        │                         ┌──────────┴──────────┐       │
│        │                         │ Alias: authorized   │       │
│        │                         │ ┌─────────────────┐ │       │
│        │                         │ │ AA:BB:CC:DD:EE  │ │       │
│        │                         │ └─────────────────┘ │       │
│        │                         └──────────┬──────────┘       │
│        │                                    │                  │
│   ┌────┴────┐ 6. MAC dans Alias = AUTORISÉ │                  │
│   │ Client  │◄──────────────────────────────┤                  │
│   │  WiFi   │    Accès Internet OK          │                  │
│   └─────────┘                               │                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Comment ça marche :**

1. pfSense maintient un **Alias** appelé `authorized_macs` (liste de MACs)
2. Les **règles firewall** pfSense :
   - Si MAC dans Alias → **PASS** (trafic autorisé)
   - Sinon → **REDIRECT** vers le portail captif
3. Le client s'authentifie via **Keycloak**
4. Le portail appelle l'**API pfSense** pour ajouter la MAC à l'Alias
5. pfSense applique les règles → client autorisé

**Comment le portail récupère la MAC ?**

Le portail n'est pas sur le même VLAN que les clients, donc il ne peut pas voir leur MAC directement. Il interroge les **DHCP Leases** de pfSense via l'API :

```
IP du client (header X-Forwarded-For)
    → API pfSense: GET /api/v1/services/dhcpd/lease
    → Trouver le lease avec cette IP
    → Récupérer la MAC associée
```

**Avantages :**
- Fonctionne avec **n'importe quelle topologie** (VLANs, sous-réseaux)
- pfSense reste le **point central** de contrôle
- Le portail peut être sur un **autre VLAN**
- Pas besoin de FreeRADIUS

**Inconvénients :**
- Nécessite **pfSense-pkg-API** ou **FauxAPI** sur pfSense

**Configuration requise :** Voir section [Intégration pfSense API](#intégration-pfsense-api)

---

### Méthode 2 : RADIUS avec FreeRADIUS + CoA

**Principe :** Un serveur **RADIUS** (FreeRADIUS) gère l'authentification réseau. Le portail envoie des paquets **CoA (Change of Authorization)** pour autoriser/révoquer l'accès des clients.

```
┌─────────────────────────────────────────────────────────────────┐
│                        FLUX RADIUS CoA                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Client WiFi         Borne/NAS          FreeRADIUS            │
│   ┌─────────┐        ┌─────────┐        ┌───────────┐          │
│   │ MAC: AA │        │ Cisco   │        │  RADIUS   │          │
│   └────┬────┘        │ /Aruba  │        │  Server   │          │
│        │             └────┬────┘        └─────┬─────┘          │
│        │                  │                   │                 │
│        │ 1. Connect WiFi  │                   │                 │
│        ├─────────────────►│                   │                 │
│        │                  │                   │                 │
│        │                  │ 2. Access-Request │                 │
│        │                  ├──────────────────►│                 │
│        │                  │    (MAC: AA)      │                 │
│        │                  │                   │                 │
│        │                  │ 3. Access-Accept  │                 │
│        │                  │◄──────────────────┤                 │
│        │                  │   (accès limité)  │                 │
│        │                  │                   │                 │
│        │ 4. IP + accès    │                   │                 │
│        │◄─────────────────┤                   │                 │
│        │    restreint     │                   │                 │
│        │                  │                   │                 │
│        │      ... Auth Keycloak via Portail ...                │
│        │                  │                   │                 │
│        │                  │    Portail        │                 │
│        │                  │   ┌───────┐       │                 │
│        │                  │   │       │ 5. CoA-Request         │
│        │                  │   │       ├──────►│                 │
│        │                  │   └───────┘       │                 │
│        │                  │                   │                 │
│        │                  │ 6. CoA (autoriser)│                 │
│        │                  │◄──────────────────┤                 │
│        │                  │                   │                 │
│        │ 7. Accès complet │                   │                 │
│        │◄─────────────────┤                   │                 │
│        │   Internet OK    │                   │                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Comment ça marche :**

1. Client se connecte au WiFi
2. La **borne/NAS** envoie une requête RADIUS à FreeRADIUS
3. FreeRADIUS répond **Access-Accept** avec accès limité
4. Client est redirigé vers le portail, s'authentifie via Keycloak
5. Le portail envoie un **CoA-Request** à FreeRADIUS
6. FreeRADIUS envoie un **CoA à la borne/NAS**
7. La borne change l'état du client → accès complet

**Le protocole RADIUS (RFC 2865, RFC 5176) :**

```
┌─────────────────────────────────────────┐
│           Paquets RADIUS                │
├─────────────────────────────────────────┤
│ Access-Request    → Demande d'auth      │
│ Access-Accept     → Auth OK             │
│ Access-Reject     → Auth refusée        │
│ CoA-Request       → Changer autorisation│
│ CoA-ACK           → Changement OK       │
│ CoA-NAK           → Changement refusé   │
│ Disconnect-Request→ Déconnecter client  │
└─────────────────────────────────────────┘
```

**Avantages :**
- **Standard industriel** (RFC 5176)
- Fonctionne avec équipements **enterprise** (Cisco, Aruba, HP)
- Contrôle fin (VLAN dynamique, QoS, etc.)
- Peut combiner avec **802.1X**

**Inconvénients :**
- Nécessite **FreeRADIUS**
- Configuration plus **complexe**
- Les bornes doivent **supporter CoA** (pas toutes le font)

**Quand l'utiliser :**
- Bornes WiFi enterprise (Cisco WLC, Aruba, HP)
- Infrastructure RADIUS existante
- Besoin de 802.1X en plus du portail captif

**Configuration requise :** Voir section [Configuration RADIUS/FreeRADIUS](#configuration-radiusfreeradius)

---

### Méthode 3 : nftables (réseau plat uniquement)

**Principe :** Le serveur portail contrôle **directement** le trafic avec **nftables** (firewall Linux moderne).

**⚠️ Limitation importante :** Le serveur portail **DOIT** être sur le **même segment réseau** (Layer 2 / même VLAN) que les clients WiFi. **Ne fonctionne PAS** à travers un routeur.

```
┌─────────────────────────────────────────────────────────────────┐
│                        FLUX nftables                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│        MÊME SEGMENT RÉSEAU (Layer 2 / même VLAN)               │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │                                                         │  │
│   │   Client WiFi              Serveur Portail              │  │
│   │   ┌─────────┐             ┌─────────────────┐          │  │
│   │   │ MAC: AA │             │    nftables     │          │  │
│   │   │ IP: .50 │             │ ┌─────────────┐ │          │  │
│   │   └────┬────┘             │ │ allowed_macs│ │          │  │
│   │        │                  │ │ (vide)      │ │          │  │
│   │        │                  │ └─────────────┘ │          │  │
│   │        │                  └────────┬────────┘          │  │
│   │        │                           │                    │  │
│   │        │ 1. Le serveur VOIT la MAC │                    │  │
│   │        │    directement via ARP    │                    │  │
│   │        │    (table ARP locale)     │                    │  │
│   │        │                           │                    │  │
│   │        │ 2. MAC pas dans set       │                    │  │
│   │        │    = trafic BLOQUÉ        │                    │  │
│   │        │                           │                    │  │
│   │        │    ... Auth Keycloak ...  │                    │  │
│   │        │                           │                    │  │
│   │        │ 3. nft add element        │                    │  │
│   │        │    allowed_macs {AA:BB}   │                    │  │
│   │        │                           │                    │  │
│   │        │                  ┌────────┴────────┐          │  │
│   │        │                  │ ┌─────────────┐ │          │  │
│   │        │                  │ │ allowed_macs│ │          │  │
│   │        │                  │ │ AA:BB:CC:DD │ │          │  │
│   │        │                  │ └─────────────┘ │          │  │
│   │        │                  └────────┬────────┘          │  │
│   │        │                           │                    │  │
│   │        │ 4. MAC dans set           │                    │  │
│   │        │    = trafic AUTORISÉ      │                    │  │
│   │        │◄──────────────────────────┤                    │  │
│   │                                                         │  │
│   └─────────────────────────────────────────────────────────┘  │
│                                                                 │
│   ⚠️  NE FONCTIONNE PAS si le client est sur un autre VLAN    │
│       car le serveur ne voit pas la MAC (routeur entre les 2)  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Comment ça marche :**

1. Le serveur utilise **nftables** avec un **set** de MACs autorisées
2. Règles nftables :
   - MAC dans le set → **ACCEPT**
   - MAC pas dans le set → **DROP** ou **REDIRECT**
3. Récupère la MAC via la **table ARP** locale (`ip neigh show`)
4. Après auth Keycloak, ajoute la MAC au set

**Commandes nftables :**

```bash
# Voir les MACs autorisées
nft list set inet filter allowed_macs

# Ajouter une MAC
nft add element inet filter allowed_macs { AA:BB:CC:DD:EE:FF }

# Supprimer une MAC
nft delete element inet filter allowed_macs { AA:BB:CC:DD:EE:FF }
```

**Avantages :**
- **Simple** à mettre en place
- **Pas de dépendance** externe
- **Rapide** (tout en local)

**Inconvénients :**
- **Ne fonctionne que si même segment L2** (même VLAN)
- Ne voit **pas les MACs** à travers un routeur
- **Limité** aux petits réseaux

**Quand l'utiliser :**
- Lab / environnement de test
- Petit réseau plat (pas de VLANs)
- Le serveur portail est sur le **même VLAN** que les clients WiFi

---

### Tableau comparatif détaillé

| Critère | pfSense API | RADIUS CoA | nftables |
|---------|-------------|------------|----------|
| **Topologie supportée** | Multi-VLAN | Multi-VLAN | Même VLAN uniquement |
| **Dépendances** | pfSense + API pkg | FreeRADIUS | Aucune |
| **Récupération MAC** | DHCP Leases API | Attribut RADIUS | Table ARP locale |
| **Complexité config** | Moyenne | Élevée | Faible |
| **Équipements requis** | pfSense | Bornes enterprise | Serveur Linux |
| **Scalabilité** | Bonne | Excellente | Limitée |
| **Standard** | Propriétaire | RFC 5176 | Linux natif |
| **Cas d'usage** | Université avec pfSense | Grande entreprise | Lab/test |

---

## Intégration pfSense API

### Prérequis pfSense

1. **pfSense 2.5+** avec package `pfSense-pkg-API` ou accès SSH
2. **Créer un utilisateur API** dans pfSense :
   - System → User Manager → Add
   - Username: `captive-portal-api`
   - Privileges: `WebCfg - All pages` (ou plus restrictif)

3. **Activer l'API** (si package installé) :
   - System → API → Settings
   - Enable API: checked

### Créer l'Alias pour les MACs autorisées

**Dans pfSense** : Firewall → Aliases → Add

| Champ | Valeur |
|-------|--------|
| Name | `authorized_macs` |
| Type | Host(s) |
| Description | MACs autorisées par le portail captif |

Laisser la liste vide (sera remplie par le portail).

### Configurer les règles Firewall pfSense

**Dans pfSense** : Firewall → Rules → [Interface WiFi]

Ajouter les règles **dans cet ordre** :

| # | Action | Source | Destination | Port | Description |
|---|--------|--------|-------------|------|-------------|
| 1 | **Pass** | `authorized_macs` | any | any | Trafic autorisé |
| 2 | **Pass** | any | Portail Captif IP | 80, 443, 8000 | Accès portail |
| 3 | **Pass** | any | Keycloak IP | 443 | Accès Keycloak |
| 4 | **Pass** | any | any | 53 | DNS |
| 5 | **Pass** | any | any | 67, 68 | DHCP |
| 6 | **Block** | any | any | any | Bloquer le reste |

**Pour la redirection HTTP** : Firewall → NAT → Port Forward

| Champ | Valeur |
|-------|--------|
| Interface | WIFI |
| Protocol | TCP |
| Source | ! `authorized_macs` (inverser) |
| Destination | any |
| Destination port | 80 |
| Redirect target IP | IP du Portail |
| Redirect target port | 8000 |

### Configuration du portail pour pfSense API

```bash
# .env
AUTH_METHOD=pfsense_api

# pfSense API
PFSENSE_URL=https://192.168.1.1
PFSENSE_API_KEY=your-api-key
PFSENSE_API_SECRET=your-api-secret
PFSENSE_ALIAS_NAME=authorized_macs
PFSENSE_VERIFY_SSL=false
```

### Récupération de la MAC via DHCP Leases

Comme le portail n'est pas sur le même segment L2, il ne peut pas voir la MAC directement. Il doit interroger pfSense :

```
Client IP (header X-Forwarded-For)
    → Requête API pfSense /api/v1/services/dhcpd/lease
    → Trouver le lease avec cette IP
    → Récupérer la MAC associée
```

---

## Configuration RADIUS/FreeRADIUS

### Architecture RADIUS complète

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FLUX RADIUS DÉTAILLÉ                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────┐    (1) Connect WiFi    ┌─────────┐                            │
│  │ Client  │───────────────────────►│   AP    │                            │
│  │  WiFi   │                        │  /NAS   │                            │
│  └─────────┘                        └────┬────┘                            │
│                                          │                                  │
│                    (2) Access-Request    │                                  │
│                    MAC: AA:BB:CC:DD:EE   │                                  │
│                                          ▼                                  │
│                                    ┌───────────┐                           │
│                                    │FreeRADIUS │                           │
│                                    │  Server   │                           │
│                                    └─────┬─────┘                           │
│                                          │                                  │
│                    (3) Access-Accept     │                                  │
│                    (accès restreint)     │                                  │
│                                          ▼                                  │
│  ┌─────────┐◄───────────────────────┌────┴────┐                            │
│  │ Client  │    IP + accès limité   │   AP    │                            │
│  └────┬────┘                        └─────────┘                            │
│       │                                                                     │
│       │ (4) HTTP Request                                                    │
│       ▼                                                                     │
│  ┌─────────┐    (5) Redirect         ┌─────────┐                           │
│  │ Portail │◄────────────────────────│ pfSense │                           │
│  │ Captif  │                         │   NAT   │                           │
│  └────┬────┘                         └─────────┘                           │
│       │                                                                     │
│       │ (6) Auth OIDC                                                       │
│       ▼                                                                     │
│  ┌─────────┐                                                               │
│  │Keycloak │                                                               │
│  └────┬────┘                                                               │
│       │                                                                     │
│       │ (7) Token OK                                                        │
│       ▼                                                                     │
│  ┌─────────┐    (8) CoA-Request      ┌───────────┐                         │
│  │ Portail │────────────────────────►│FreeRADIUS │                         │
│  │ Captif  │    User: john           │  Server   │                         │
│  └─────────┘    MAC: AA:BB:CC:DD:EE  └─────┬─────┘                         │
│                                            │                                │
│                    (9) CoA au NAS          │                                │
│                                            ▼                                │
│                                      ┌─────────┐                           │
│                                      │   AP    │                           │
│                                      │  /NAS   │                           │
│                                      └────┬────┘                           │
│                                           │                                 │
│                    (10) Client autorisé   │                                 │
│                    Accès Internet OK      │                                 │
│                                           ▼                                 │
│  ┌─────────┐◄─────────────────────────────┘                                │
│  │ Client  │    INTERNET ACCESS                                            │
│  └─────────┘                                                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Installation FreeRADIUS

```bash
# Ubuntu/Debian
sudo apt-get install freeradius freeradius-utils

# CentOS/RHEL
sudo dnf install freeradius freeradius-utils
```

### Configuration FreeRADIUS

#### 1. Configurer les clients NAS

**Fichier** : `/etc/freeradius/3.0/clients.conf`

```conf
# pfSense comme client RADIUS
client pfsense {
    ipaddr = 192.168.1.1
    secret = pfsense-radius-secret
    shortname = pfsense
    nastype = other
}

# Portail Captif (pour envoyer CoA)
client captive-portal {
    ipaddr = 10.0.0.10
    secret = portal-radius-secret
    shortname = captive-portal
}

# Bornes WiFi (si elles supportent RADIUS)
client wifi-ap-building-a {
    ipaddr = 10.0.0.100
    secret = ap-radius-secret
    shortname = ap-building-a
    nastype = cisco  # ou autre selon le fabricant
}
```

#### 2. Configurer les utilisateurs (optionnel)

**Fichier** : `/etc/freeradius/3.0/users`

Pour un portail captif, on accepte généralement tout le monde au niveau RADIUS et on laisse Keycloak gérer l'auth :

```conf
# Accepter toutes les MACs avec accès restreint par défaut
DEFAULT Auth-Type := Accept
    Reply-Message = "Accès restreint - Authentification portail requise",
    Session-Timeout = 3600,
    Idle-Timeout = 600
```

#### 3. Activer CoA (Dynamic Authorization)

**Fichier** : `/etc/freeradius/3.0/sites-available/default`

Décommenter la section `listen` pour CoA :

```conf
listen {
    type = coa
    ipaddr = *
    port = 3799
    virtual_server = coa
}
```

**Fichier** : `/etc/freeradius/3.0/sites-available/coa`

```conf
server coa {
    listen {
        type = coa
        ipaddr = *
        port = 3799
    }

    recv CoA-Request {
        # Log la requête
        linelog

        # Vérifier le client
        if (!client) {
            reject
        }

        # Accepter la requête CoA
        ok
    }

    send CoA-ACK {
        ok
    }

    send CoA-NAK {
        ok
    }
}
```

Activer le site :

```bash
cd /etc/freeradius/3.0/sites-enabled
ln -s ../sites-available/coa coa
```

#### 4. Démarrer FreeRADIUS

```bash
# Test de configuration
sudo freeradius -CX

# Démarrer en mode debug (pour tests)
sudo freeradius -X

# Démarrer en production
sudo systemctl enable freeradius
sudo systemctl start freeradius
```

### Configuration pfSense pour RADIUS

**Dans pfSense** : System → User Manager → Authentication Servers → Add

| Champ | Valeur |
|-------|--------|
| Type | RADIUS |
| Hostname or IP | IP du serveur FreeRADIUS |
| Shared Secret | `pfsense-radius-secret` |
| Services offered | Authentication and Accounting |
| Authentication port | 1812 |
| Accounting port | 1813 |

### Configuration du portail pour RADIUS CoA

```bash
# .env
AUTH_METHOD=radius_coa

# RADIUS CoA
RADIUS_SERVER=10.0.0.5          # IP du serveur FreeRADIUS
RADIUS_SECRET=portal-radius-secret
RADIUS_COA_PORT=3799
RADIUS_NAS_IP=192.168.1.1       # IP du NAS (pfSense ou AP)
RADIUS_NAS_SECRET=pfsense-radius-secret
```

### Tester RADIUS

```bash
# Tester l'authentification
radtest testuser testpass localhost 0 testing123

# Tester CoA depuis le portail
python scripts/radius_coa.py test --nas 192.168.1.1 --secret pfsense-radius-secret

# Envoyer un CoA d'autorisation
python scripts/radius_coa.py authorize \
    --nas 192.168.1.1 \
    --secret pfsense-radius-secret \
    --mac AA:BB:CC:DD:EE:FF \
    --user john.doe
```

### Attributs RADIUS courants

| Attribut | Description | Exemple |
|----------|-------------|---------|
| `User-Name` | Nom d'utilisateur | `john.doe` |
| `Calling-Station-Id` | MAC du client | `AA-BB-CC-DD-EE-FF` |
| `Called-Station-Id` | MAC/SSID de l'AP | `00-11-22-33-44-55:WiFi-Guest` |
| `NAS-IP-Address` | IP du NAS/AP | `192.168.1.1` |
| `Acct-Session-Id` | ID de session | `AB123456` |
| `Session-Timeout` | Durée max session (sec) | `28800` |
| `Idle-Timeout` | Timeout inactivité (sec) | `600` |

### Vendors spécifiques

#### Cisco

```conf
# clients.conf
client cisco-wlc {
    ipaddr = 10.0.0.50
    secret = cisco-secret
    nastype = cisco
}
```

Attributs Cisco VSA pour CoA :
- `Cisco-AVPair = "subscriber:command=account-logon"`
- `Cisco-AVPair = "subscriber:command=account-logoff"`

#### Aruba

```conf
# clients.conf
client aruba-controller {
    ipaddr = 10.0.0.60
    secret = aruba-secret
    nastype = aruba
}
```

#### Ubiquiti UniFi

UniFi Controller supporte RADIUS mais CoA est limité. Utiliser l'API UniFi Controller comme alternative.

---

## Flux d'authentification

```
1. Client se connecte au WiFi → obtient IP (accès restreint)
2. Client ouvre navigateur → redirigé vers portail
3. Portail redirige vers Keycloak (OIDC)
4. Utilisateur s'authentifie → session SSO créée
5. Callback → portail autorise le client :
   - pfSense API : ajoute MAC à l'Alias
   - RADIUS CoA : envoie CoA à FreeRADIUS
   - nftables : ajoute MAC au set (si même L2)
6. Client navigue librement
7. Apps reconnaissent la session Keycloak → pas de re-login
```

---

## Prérequis

- Python 3.10+
- Redis
- Keycloak 20+ avec realm configuré
- **Et selon la méthode choisie :**
  - pfSense API : pfSense 2.5+ avec API ou accès SSH
  - RADIUS CoA : FreeRADIUS 3.x
  - nftables : serveur sur même segment L2 que clients

---

## Installation

### 1. Cloner et configurer

```bash
git clone git@github.com:ojuwoni/IT-Captive-Portal.git
cd IT-Captive-Portal
cp .env.example .env
nano .env  # Éditer avec tes valeurs
```

### 2. Configurer Keycloak

Créer un client OIDC dans Keycloak :

| Paramètre | Valeur |
|-----------|--------|
| Client ID | captive-portal |
| Client Protocol | openid-connect |
| Access Type | confidential |
| Valid Redirect URIs | http://portal.university.edu/callback |
| Web Origins | http://portal.university.edu |

Récupérer le client secret dans l'onglet Credentials.

Pour la synchronisation des sessions, créer un client service account :

| Paramètre | Valeur |
|-----------|--------|
| Client ID | admin-cli |
| Service Accounts Enabled | ON |
| Roles | realm-admin (ou view-users, view-clients) |

### 3. Choisir la méthode d'autorisation

#### Option A : pfSense API (recommandé)

```bash
# .env
AUTH_METHOD=pfsense_api
PFSENSE_URL=https://192.168.1.1
PFSENSE_API_KEY=your-key
PFSENSE_API_SECRET=your-secret
PFSENSE_ALIAS_NAME=authorized_macs
```

Voir [Intégration pfSense API](#intégration-pfsense-api)

#### Option B : RADIUS CoA

```bash
# .env
AUTH_METHOD=radius_coa
RADIUS_SERVER=10.0.0.5
RADIUS_SECRET=portal-secret
RADIUS_COA_PORT=3799
RADIUS_NAS_IP=192.168.1.1
```

Voir [Configuration RADIUS/FreeRADIUS](#configuration-radiusfreeradius)

#### Option C : nftables (réseau plat)

```bash
# .env
AUTH_METHOD=nftables
```

```bash
sudo bash scripts/setup_nftables.sh
```

### 4. Lancer avec Docker

```bash
docker-compose up -d
```

### 5. Lancer sans Docker

```bash
# Redis
sudo systemctl start redis

# Portail
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Sync sessions (dans un autre terminal)
python scripts/sync_sessions.py --daemon
```

---

## Personnalisation du thème

### Fichiers statiques

Placer dans le dossier `static/` :

| Fichier | Dimensions | Description |
|---------|------------|-------------|
| `logo.png` | 120x120px | Logo société |
| `favicon.ico` | 32x32px | Icône navigateur |
| `background.jpg` | 1920x1080px | Image de fond (optionnel) |

### Variables d'environnement

```bash
# .env
THEME_COMPANY_NAME=IDADU TECH
THEME_PORTAL_TITLE=Portail WiFi
THEME_PRIMARY_COLOR=#00A651
THEME_PRIMARY_HOVER=#008C44
THEME_LOGO_URL=/static/logo.png
THEME_BACKGROUND_TYPE=gradient
THEME_BACKGROUND_GRADIENT_START=#004D25
THEME_BACKGROUND_GRADIENT_END=#00A651
```

### Exemples de palettes

**IDADU TECH (vert)**
```
PRIMARY: #00A651
HOVER: #008C44
GRADIENT: #004D25 → #00A651
```

**EdTech (orange)**
```
PRIMARY: #F97316
HOVER: #EA580C
GRADIENT: #7C2D12 → #F97316
```

**FinTech (bleu)**
```
PRIMARY: #0EA5E9
HOVER: #0284C7
GRADIENT: #0C4A6E → #0EA5E9
```

### Textes personnalisables

```bash
THEME_LOGIN_BUTTON_TEXT=Se connecter avec mon compte IDADU
THEME_SUCCESS_MESSAGE=Bienvenue sur le réseau IDADU TECH
THEME_FOOTER_TEXT=© 2024 IDADU TECH - Conditions d'utilisation
THEME_TERMS_URL=https://idadu.tech/cgu
```

---

## Migration depuis pfSense

### Prérequis

- Une VM ou serveur dédié pour le portail (Ubuntu 22.04/24.04 recommandé)
- Accès admin à pfSense
- Client Keycloak configuré (voir section Installation)

### Étape 1 : Préparer le serveur portail

```bash
# Sur le nouveau serveur (pas pfSense)
# 1. Cloner le projet
git clone git@github.com:ojuwoni/IT-Captive-Portal.git /opt/captive-portal
cd /opt/captive-portal

# 2. Configurer
cp .env.example .env
nano .env  # Remplir les valeurs Keycloak + pfSense API

# 3. Ajouter le logo dans static/
cp /chemin/vers/logo.png static/logo.png

# 4. Installer
sudo bash install.sh

# 5. Vérifier que ça tourne
curl http://localhost:8000/health
# Doit retourner: {"status":"ok","auth_method":"pfsense_api"}
```

### Étape 2 : Configurer pfSense

1. **Créer l'Alias** : Firewall → Aliases → Add
   - Name: `authorized_macs`
   - Type: Host(s)

2. **Configurer les règles Firewall** : Voir [Intégration pfSense API](#intégration-pfsense-api)

3. **Désactiver l'ancien portail captif** :
   - Services → Captive Portal
   - Décocher "Enable Captive Portal"
   - Save

### Étape 3 : Tester

```bash
# Test 1 : Health check
curl http://portal.university.edu/health

# Test 2 : Depuis un client WiFi non-auth
# Ouvrir http://example.com → doit rediriger vers portail

# Test 3 : Auth complète
# Se connecter via Keycloak → vérifier accès Internet
```

### Rollback (si problème)

```bash
# 1. Sur pfSense : réactiver le captive portal
# Services → Captive Portal → Enable

# 2. Supprimer les règles firewall ajoutées
# Firewall → Rules → supprimer les règles du portail

# 3. Apply Changes
```

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Page d'accueil portail |
| `GET /login` | Initie le flow OIDC |
| `GET /callback` | Callback OIDC |
| `GET /logout` | Déconnexion |
| `GET /status` | Statut connexion (JSON) |
| `GET /health` | Health check |

---

## Synchronisation des sessions

Le script `sync_sessions.py` vérifie périodiquement :
- Session Keycloak expirée → révoque l'accès réseau
- Sessions orphelines → nettoyage

```bash
# Mode daemon (recommandé)
python scripts/sync_sessions.py --daemon --interval 300

# Exécution unique (cron)
python scripts/sync_sessions.py --once
```

---

## Production

### Nginx reverse proxy

```nginx
server {
    listen 80;
    server_name portal.university.edu;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Systemd services

```bash
sudo cp config/captive-portal.service /etc/systemd/system/
sudo cp config/captive-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now captive-portal captive-sync
```

---

## Dépannage

### MAC non détectée

| Méthode | Solution |
|---------|----------|
| pfSense API | Vérifier que le portail peut accéder à l'API DHCP Leases |
| RADIUS | Vérifier que Calling-Station-Id est transmis |
| nftables | Vérifier que le serveur est sur le même segment L2 |

### Session Keycloak non créée

- Vérifier les logs Keycloak
- Vérifier que le callback URL est exact
- Tester avec `curl` le endpoint token

### pfSense API erreur

```bash
# Tester l'accès API
curl -k https://192.168.1.1/api/v1/system/status \
  -H "Authorization: your-api-key your-api-secret"
```

### RADIUS CoA non reçu

```bash
# Vérifier que FreeRADIUS écoute sur le port CoA
sudo ss -ulnp | grep 3799

# Tester avec radclient
echo "User-Name=test" | radclient -x 10.0.0.5:3799 coa portal-secret
```

### Erreur "bad gateway" (anciennement pfSense)

Ce projet résout ce problème. Redis gère les sessions sans limite.

---

## Structure du projet

```
captive-portal-sso/
├── app/
│   ├── __init__.py
│   └── main.py              # Application FastAPI
├── config/
│   ├── settings.py          # Configuration générale
│   ├── theme.py             # Configuration thème
│   ├── nginx.conf
│   └── *.service            # Services systemd
├── scripts/
│   ├── setup_nftables.sh    # Config nftables
│   ├── sync_sessions.py     # Sync Keycloak
│   └── radius_coa.py        # Client RADIUS CoA
├── static/                  # Logo, favicon, images
├── templates/               # Pages HTML
├── .env.example
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── install.sh
```

---

## Résumé des méthodes d'autorisation

| Méthode | Quand l'utiliser | Prérequis | Complexité |
|---------|------------------|-----------|------------|
| **pfSense API** | Environnement pfSense existant, multi-VLAN | pfSense 2.5+, API | Moyenne |
| **RADIUS CoA** | Infra RADIUS existante, bornes enterprise | FreeRADIUS, NAS compatible | Élevée |
| **nftables** | Lab, petit réseau, même segment L2 | Serveur sur même VLAN | Faible |

---

## Licence

MIT
