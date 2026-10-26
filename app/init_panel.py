"""Первичная настройка панели.

    python -m app.init_panel --endpoint 1.2.3.4
    python -m app.init_panel --set-password

Повторный запуск безопасен: ключи сервера и клиенты не перегенерируются.
Пароль можно передать через переменную окружения WGPANEL_ADMIN_PASSWORD.
"""

import argparse
import datetime
import getpass
import ipaddress
import os
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import db, wg
from .config import CERT_FILE, DATA_DIR, DEFAULTS, KEY_FILE, SETTINGS_FILE, load_settings, save_settings
from .security import hash_password


def ask_password() -> str:
    pw = os.environ.get("WGPANEL_ADMIN_PASSWORD")
    if pw:
        return pw
    while True:
        pw = getpass.getpass("Пароль администратора панели: ")
        if len(pw) < 8:
            print("Минимум 8 символов.")
            continue
        if pw != getpass.getpass("Повтори пароль: "):
            print("Не совпадает.")
            continue
        return pw


def make_self_signed_cert(host: str) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host or "wg-panel")])
    try:
        san = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san = x509.DNSName(host or "wg-panel")
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .sign(key, hashes.SHA256())
    )
    KEY_FILE.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--endpoint", help="Публичный IP или домен VPS")
    p.add_argument("--listen-port", type=int)
    p.add_argument("--panel-port", type=int)
    p.add_argument("--subnet")
    p.add_argument("--dns")
    p.add_argument("--set-password", action="store_true", help="Только сменить пароль")
    args = p.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    settings = load_settings() if SETTINGS_FILE.exists() else dict(DEFAULTS)

    if args.set_password:
        settings["admin_password_hash"] = hash_password(ask_password())
        # новый ключ сессий: все, кто вошёл со старым паролем, будут разлогинены
        settings["session_secret"] = secrets.token_hex(32)
        save_settings(settings)
        print("Пароль обновлён, все старые входы в панель сброшены. Перезапусти службу: Restart-Service wg-panel")
        return

    if args.endpoint:
        settings["endpoint_host"] = args.endpoint
    if args.listen_port:
        settings["listen_port"] = args.listen_port
    if args.panel_port:
        settings["panel_port"] = args.panel_port
    if args.dns:
        settings["dns"] = args.dns
    if args.subnet:
        if db.DB_FILE.exists() and db.list_clients() and args.subnet != settings["subnet"]:
            raise SystemExit("Нельзя менять подсеть, когда уже есть клиенты.")
        ipaddress.ip_network(args.subnet)  # валидация
        settings["subnet"] = args.subnet

    if not settings["endpoint_host"]:
        raise SystemExit("Укажи --endpoint (публичный IP или домен VPS)")

    if not settings["server_private_key"]:
        settings["server_private_key"], settings["server_public_key"] = wg.gen_keypair()
        print("Сгенерированы ключи сервера.")
    if not settings["session_secret"]:
        settings["session_secret"] = secrets.token_hex(32)
    if not settings["admin_password_hash"]:
        settings["admin_password_hash"] = hash_password(ask_password())

    save_settings(settings)
    db.init_db()
    wg.write_server_conf(settings, db.list_clients())

    if not CERT_FILE.exists():
        make_self_signed_cert(settings["endpoint_host"])
        print("Создан самоподписанный HTTPS-сертификат.")

    print(f"Готово. Конфиг сервера: {wg.WG_CONF_FILE}")


if __name__ == "__main__":
    main()
