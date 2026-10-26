import json
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("WGPANEL_DATA", BASE_DIR / "data"))
SETTINGS_FILE = DATA_DIR / "settings.json"
DB_FILE = DATA_DIR / "panel.db"
WG_CONF_FILE = DATA_DIR / "wg0.conf"
CERT_FILE = DATA_DIR / "cert.pem"
KEY_FILE = DATA_DIR / "key.pem"

IS_WINDOWS = sys.platform == "win32"
WG_EXE = os.environ.get(
    "WGPANEL_WG_EXE",
    r"C:\Program Files\WireGuard\wg.exe" if IS_WINDOWS else "wg",
)
# Mock mode: keys are still generated, but the live interface is never touched.
# Used for local testing on machines without a running WireGuard tunnel.
MOCK = os.environ.get("WGPANEL_MOCK") == "1"

DEFAULTS = {
    "interface": "wg0",
    "endpoint_host": "",
    "listen_port": 51820,
    "subnet": "10.8.0.0/24",
    "dns": "1.1.1.1, 8.8.8.8",
    "panel_host": "0.0.0.0",
    "panel_port": 8443,
    "server_private_key": "",
    "server_public_key": "",
    "admin_password_hash": "",
    "session_secret": "",
}


def load_settings() -> dict:
    if not SETTINGS_FILE.exists():
        raise SystemExit(
            f"Настройки не найдены: {SETTINGS_FILE}. Сначала запусти: python -m app.init_panel"
        )
    data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    return {**DEFAULTS, **data}


def save_settings(settings: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(
        json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8"
    )
