"""Раздельное туннелирование: какие адреса клиент пускает мимо VPN.

Решение принимает клиент по AllowedIPs, поэтому исключения превращаются в
AllowedIPs = 0.0.0.0/0 минус исключённые сети.
"""

import ipaddress
import re
import socket
import threading
import time

LAN_NETS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",  # link-local
    "224.0.0.0/4",     # multicast (обнаружение устройств в сети)
]

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_DNS_TTL = 300
_dns_cache: dict[str, tuple[float, list[str]]] = {}
_dns_lock = threading.Lock()


class EntryError(ValueError):
    pass


def parse_entry(raw: str) -> tuple[str, str]:
    """-> ("net", "1.2.3.0/24") или ("domain", "example.com")."""
    s = raw.strip().lower()
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        pass
    else:
        if str(net) != s and "/" in s and net.network_address != ipaddress.ip_interface(s).ip:
            # 1.2.3.4/8 — скорее опечатка, молча расширять до 1.0.0.0/8 опасно
            raise EntryError(f"{raw}: адрес не совпадает с началом подсети — имелось в виду {net}?")
        if net.version != 4:
            raise EntryError(f"{raw}: поддерживается только IPv4")
        if net.prefixlen < 8:
            raise EntryError(f"{raw}: слишком широкая сеть (минимум /8)")
        return "net", str(net)
    # разрешаем вставлять ссылку целиком: https://site.ru:443/path -> site.ru
    s = re.sub(r"^[a-z]+://", "", s).split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if not s.isascii():
        raise EntryError(f"{raw}: кириллические домены не поддерживаются — укажи IP сайта")
    if not _DOMAIN_RE.match(s):
        raise EntryError(f"{raw}: не IP, не подсеть и не домен")
    return "domain", s


def parse_text(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    entries, errors, seen = [], [], set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            e = parse_entry(line)
        except EntryError as ex:
            errors.append(str(ex))
            continue
        if e not in seen:
            seen.add(e)
            entries.append(e)
    return entries, errors


def resolve(domain: str) -> list[str]:
    """IPv4-адреса домена. Кэш на 5 минут; если DNS временно недоступен —
    отдаём последний удачный результат."""
    now = time.time()
    with _dns_lock:
        cached = _dns_cache.get(domain)
    if cached and now - cached[0] < _DNS_TTL:
        return cached[1]
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = sorted({i[4][0] for i in infos}, key=ipaddress.ip_address)
    except OSError:
        if cached:
            return cached[1]
        raise EntryError(f"{domain}: не удалось получить IP (DNS)")
    with _dns_lock:
        _dns_cache[domain] = (now, ips)
    return ips


def compute(settings: dict, client: dict) -> dict:
    """Считает AllowedIPs клиента.

    Возвращает {"allowed": [...], "resolved": {entry: [ips]}, "endpoint": [ips], "errors": [...]}.
    """
    entries, errors = parse_text(client.get("exclusions") or "")
    excluded = []
    resolved = {}
    if client.get("exclude_lan"):
        excluded += [ipaddress.ip_network(n) for n in LAN_NETS]
    for kind, value in entries:
        if kind == "net":
            excluded.append(ipaddress.ip_network(value))
        else:
            try:
                ips = resolve(value)
            except EntryError as ex:
                errors.append(str(ex))
                continue
            resolved[value] = ips
            excluded += [ipaddress.ip_network(f"{ip}/32") for ip in ips]

    # Если есть исключения, AllowedIPs перестаёт быть 0.0.0.0/0 и клиенты на Linux
    # (wg-quick, NetworkManager) уже не уводят пакеты к самому серверу мимо туннеля:
    # адрес сервера попадает в один из диапазонов, и туннель заворачивает сам себя.
    # Поэтому адрес сервера исключаем всегда, когда исключения вообще есть.
    endpoint_ips = []
    if excluded:
        host = settings.get("endpoint_host") or ""
        try:
            endpoint_ips = [str(ipaddress.ip_address(host))]
        except ValueError:
            try:
                endpoint_ips = resolve(host) if host else []
            except EntryError as ex:
                errors.append(f"адрес сервера {host}: {ex}")
        excluded += [ipaddress.ip_network(f"{ip}/32") for ip in endpoint_ips if ":" not in ip]

    allowed = [ipaddress.ip_network("0.0.0.0/0")]
    for ex in ipaddress.collapse_addresses(excluded):
        nxt = []
        for net in allowed:
            if ex.supernet_of(net):
                continue
            if net.supernet_of(ex):
                nxt += net.address_exclude(ex)
            else:
                nxt.append(net)
        allowed = nxt
    # подсеть VPN всегда через туннель (иначе «локальные сети» 10/8 её бы съели)
    allowed.append(ipaddress.ip_network(settings["subnet"]))
    allowed = sorted(ipaddress.collapse_addresses(allowed))
    return {
        "allowed": [str(n) for n in allowed],
        "resolved": resolved,
        "endpoint": endpoint_ips,
        "errors": errors,
    }
