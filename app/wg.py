"""Работа с WireGuard: ключи, конфиги, живое управление пирами через wg.exe."""

import base64
import ipaddress
import os
import subprocess
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .config import DATA_DIR, IS_WINDOWS, MOCK, WG_CONF_FILE, WG_EXE

_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW


# ---------- ключи ----------

def gen_keypair() -> tuple[str, str]:
    priv = X25519PrivateKey.generate()
    priv_b = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_b = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(priv_b).decode(), base64.b64encode(pub_b).decode()


def gen_psk() -> str:
    return base64.b64encode(os.urandom(32)).decode()


# ---------- адреса ----------

def server_address(settings: dict) -> str:
    net = ipaddress.ip_network(settings["subnet"])
    return f"{next(net.hosts())}/{net.prefixlen}"


def next_free_address(settings: dict, used: set[str]) -> str:
    net = ipaddress.ip_network(settings["subnet"])
    hosts = net.hosts()
    next(hosts)  # .1 занят сервером
    for ip in hosts:
        if str(ip) not in used:
            return str(ip)
    raise RuntimeError("В подсети закончились свободные адреса")


# ---------- конфиги ----------

def render_server_conf(settings: dict, clients: list[dict]) -> str:
    # ВАЖНО: у пиров сервера только /32. Никогда не ставить сюда 0.0.0.0/0 —
    # WireGuard для Windows тогда включит kill-switch и можно потерять RDP.
    lines = [
        "[Interface]",
        f"PrivateKey = {settings['server_private_key']}",
        f"ListenPort = {settings['listen_port']}",
        f"Address = {server_address(settings)}",
        "",
    ]
    for c in clients:
        if not c["enabled"]:
            continue
        lines += [
            "[Peer]",
            f"# client id={c['id']}",
            f"PublicKey = {c['public_key']}",
            f"PresharedKey = {c['preshared_key']}",
            f"AllowedIPs = {c['address']}/32",
            "",
        ]
    return "\n".join(lines)


def render_client_conf(settings: dict, client: dict, allowed_ips: list[str]) -> str:
    return "\n".join([
        "[Interface]",
        f"PrivateKey = {client['private_key']}",
        f"Address = {client['address']}/32",
        f"DNS = {settings['dns']}",
        "",
        "[Peer]",
        f"PublicKey = {settings['server_public_key']}",
        f"PresharedKey = {client['preshared_key']}",
        f"Endpoint = {settings['endpoint_host']}:{settings['listen_port']}",
        f"AllowedIPs = {', '.join(allowed_ips)}",
        "PersistentKeepalive = 25",
        "",
    ])


def write_server_conf(settings: dict, clients: list[dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = WG_CONF_FILE.with_suffix(".tmp")
    tmp.write_text(render_server_conf(settings, clients), encoding="utf-8")
    os.replace(tmp, WG_CONF_FILE)


# ---------- живой интерфейс ----------

def _wg(*args: str) -> str:
    res = subprocess.run(
        [WG_EXE, *args],
        capture_output=True,
        text=True,
        timeout=15,
        creationflags=_NO_WINDOW,
    )
    if res.returncode != 0:
        raise RuntimeError(f"wg {' '.join(args[:2])}: {res.stderr.strip() or res.stdout.strip()}")
    return res.stdout


def add_peer(iface: str, client: dict) -> None:
    if MOCK:
        return
    psk_file = DATA_DIR / f"psk-{client['id']}.tmp"
    psk_file.write_text(client["preshared_key"] + "\n", encoding="ascii")
    try:
        _wg("set", iface, "peer", client["public_key"],
            "preshared-key", str(psk_file),
            "allowed-ips", f"{client['address']}/32")
    finally:
        psk_file.unlink(missing_ok=True)


def remove_peer(iface: str, public_key: str) -> None:
    if MOCK:
        return
    _wg("set", iface, "peer", public_key, "remove")


def dump(iface: str) -> dict[str, dict]:
    """Статистика по пирам: {public_key: {...}}."""
    if MOCK:
        return {}
    out = _wg("show", iface, "dump")
    peers = {}
    for line in out.strip().splitlines()[1:]:  # первая строка — сам интерфейс
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        pub, _psk, endpoint, _allowed, handshake, rx, tx, _ka = parts[:8]
        peers[pub] = {
            "endpoint": "" if endpoint == "(none)" else endpoint,
            "latest_handshake": int(handshake),
            "rx": int(rx),
            "tx": int(tx),
        }
    return peers


def is_online(latest_handshake: int) -> bool:
    # handshake обновляется примерно каждые 2 минуты, пока клиент активен
    return latest_handshake > 0 and time.time() - latest_handshake < 180


def reconcile(iface: str, clients: list[dict]) -> None:
    """Привести живой интерфейс в соответствие с базой (после старта/перезагрузки)."""
    if MOCK:
        return
    live = dump(iface)
    wanted = {c["public_key"]: c for c in clients if c["enabled"]}
    for pub in live:
        if pub not in wanted:
            remove_peer(iface, pub)
    for pub, c in wanted.items():
        if pub not in live:
            add_peer(iface, c)


def ensure_forwarding(iface: str) -> None:
    """Включить маршрутизацию IPv4 на wg-интерфейсе и на внешнем интерфейсе.

    Интерфейс wg пересоздаётся при каждом старте туннеля, поэтому делаем это
    при каждом запуске панели. Правила фаервола и RDP это не затрагивает.
    """
    if MOCK or not IS_WINDOWS:
        return
    ps = (
        f"Set-NetIPInterface -InterfaceAlias '{iface}' -AddressFamily IPv4 -Forwarding Enabled; "
        "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1; "
        "if ($r) { Set-NetIPInterface -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -Forwarding Enabled }"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True, timeout=30, creationflags=_NO_WINDOW,
    )
