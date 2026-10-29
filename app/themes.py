"""Theming libre pour les equipes design — sans toucher au code.

Un theme = un dossier themes/<id>/ contenant :
  theme.json        couleurs, textes, logo (fusionne sur _default)
  custom.css        (optionnel) CSS libre, charge apres les variables
  static/           (optionnel) logo, fond, polices locales
  templates/        (optionnel) surcharge COMPLETE d'un gabarit Jinja2

Resolution d'un gabarit : themes/<id>/templates/ d'abord, puis templates/
(gabarits de base). Les designers peuvent donc aller du simple changement
de couleur a la refonte totale d'une page. Recharge a chaud : theme.json
et custom.css sont relus quand leur date de modification change.

CONTRAINTE (mini-navigateur captif, DAT par. 10) : aucune ressource
externe — polices, images et CSS doivent etre LOCAUX au theme.
"""
from __future__ import annotations

import json
from pathlib import Path

DEFAULTS = {
    "name": "RBER",
    "portal_title": "Portail WiFi",
    "portal_subtitle": "Authentification reseau",
    "login_button": "Se connecter avec mon compte universitaire",
    "success_message": "Vous etes connecte au reseau WiFi.",
    "footer": "En vous connectant, vous acceptez les conditions d'utilisation du reseau.",
    "logo": "",
    "colors": {
        "primary": "#1a365d", "primary_hover": "#2d5a87",
        "background_start": "#1a365d", "background_end": "#2d5a87",
        "card": "#ffffff", "text": "#2d3748", "muted": "#718096",
        "error": "#e53e3e",
    },
}


class ThemeRegistry:
    def __init__(self, themes_dir: str):
        self._dir = Path(themes_dir)
        self._cache: dict[str, tuple[float, dict]] = {}

    def _load_json(self, theme_id: str) -> dict:
        path = self._dir / theme_id / "theme.json"
        if not path.exists():
            return {}
        mtime = path.stat().st_mtime
        cached = self._cache.get(theme_id)
        if cached and cached[0] == mtime:
            return cached[1]
        data = json.loads(path.read_text(encoding="utf-8"))
        self._cache[theme_id] = (mtime, data)
        return data

    def get(self, theme_id: str) -> dict:
        merged = json.loads(json.dumps(DEFAULTS))  # copie profonde
        for layer in ("_default", theme_id):
            data = self._load_json(layer)
            for key, value in data.items():
                if isinstance(value, dict) and isinstance(merged.get(key), dict):
                    merged[key].update(value)
                else:
                    merged[key] = value
        merged["id"] = theme_id
        merged["has_custom_css"] = (self._dir / theme_id / "custom.css").exists()
        return merged

    def css_variables(self, theme: dict) -> str:
        colors = theme["colors"]
        pairs = "".join(f"--{k.replace('_', '-')}:{v};" for k, v in colors.items())
        return f":root{{{pairs}}}"

    def template_dirs(self, base_templates: str) -> list[str]:
        dirs = []
        if self._dir.exists():
            for sub in sorted(self._dir.iterdir()):
                tpl = sub / "templates"
                if tpl.is_dir():
                    dirs.append(str(tpl))
        dirs.append(base_templates)
        return dirs
