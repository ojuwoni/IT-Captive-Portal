# Personnaliser l'interface du portail — guide des équipes design

Le portail est personnalisable **sans toucher au code et sans redéploiement**.
Toute la personnalisation vit dans le dossier `themes/`.

## Trois niveaux de personnalisation

### Niveau 1 — Couleurs, textes, logo (5 minutes)
Éditer `themes/<universite>/theme.json` :

```json
{
  "name": "Université d'Abomey-Calavi",
  "portal_title": "WiFi UAC",
  "login_button": "Se connecter avec mon compte UAC",
  "logo": "/themes/uac/static/logo.png",
  "colors": {
    "primary": "#0d4f8b",
    "primary_hover": "#0a3d6d",
    "background_start": "#0d2b4e",
    "background_end": "#0d4f8b"
  }
}
```
Toute clé absente hérite de `themes/_default/theme.json`, puis des valeurs
intégrées. Le fichier est relu automatiquement quand il change.

### Niveau 2 — CSS libre
Créer `themes/<universite>/custom.css` : il est chargé après les variables
et peut redéfinir n'importe quel style. Les classes stables sont :
`.card`, `.btn`, `.sub`, `.meta`, `.err`, `ul.campus`.

### Niveau 3 — Refonte complète d'une page
Créer `themes/<universite>/templates/login.html` (ou `success.html`,
`error.html`, `already_connected.html`) : ce gabarit Jinja2 remplace
entièrement celui de base pour cette université. Variables disponibles :
`theme`, `campus`, `client_ip`, `session`, `css_variables`.

## Règle absolue (mini-navigateur captif)

**Aucune ressource externe.** Les clients non authentifiés n'ont accès
qu'au portail : une police Google Fonts, une image sur un CDN ou un script
externe ne chargeront pas et peuvent bloquer la page dans le
mini-navigateur des téléphones. Tout doit être dans
`themes/<universite>/static/` (servi sous `/themes/<universite>/static/`).

## Tester en local

```bash
docker compose -f docker-compose.dev.yml up
# http://localhost:8000/?campus=uac  (pfSense simulé, pas de firewall requis)
```
Le dossier `themes/` est monté en volume : chaque sauvegarde est visible
au rafraîchissement de la page.

## En production
Les thèmes sont livrés via la ConfigMap `portal-themes` (ou un volume
dédié) : la mise à jour d'un thème ne redéploie pas le portail.
