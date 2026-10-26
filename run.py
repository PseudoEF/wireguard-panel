"""Точка входа службы: python run.py"""

import uvicorn

from app.config import CERT_FILE, KEY_FILE, load_settings

if __name__ == "__main__":
    s = load_settings()
    uvicorn.run(
        "app.main:app",
        host=s["panel_host"],
        port=s["panel_port"],
        ssl_certfile=str(CERT_FILE),
        ssl_keyfile=str(KEY_FILE),
        proxy_headers=False,
        server_header=False,
    )
