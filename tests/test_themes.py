import json

from app.themes import ThemeRegistry


def test_fusion_defaut_et_theme(tmp_path):
    (tmp_path / "_default").mkdir()
    (tmp_path / "_default" / "theme.json").write_text(
        json.dumps({"portal_title": "Portail RBER"}))
    (tmp_path / "uac").mkdir()
    (tmp_path / "uac" / "theme.json").write_text(
        json.dumps({"name": "UAC", "colors": {"primary": "#123456"}}))

    reg = ThemeRegistry(str(tmp_path))
    theme = reg.get("uac")
    assert theme["name"] == "UAC"
    assert theme["portal_title"] == "Portail RBER"          # herite du defaut
    assert theme["colors"]["primary"] == "#123456"          # surcharge
    assert theme["colors"]["card"] == "#ffffff"             # defaut conserve
    assert "--primary:#123456;" in reg.css_variables(theme)


def test_theme_inconnu_retombe_sur_defaut(tmp_path):
    reg = ThemeRegistry(str(tmp_path))
    theme = reg.get("inexistant")
    assert theme["colors"]["primary"]
