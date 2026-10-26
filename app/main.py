import io
import logging
import re
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import qrcode
import qrcode.constants
import qrcode.exceptions
import qrcode.image.svg
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import db, split, wg
from .config import BASE_DIR, load_settings
from .security import verify_password

log = logging.getLogger("wg-panel")
HERE = Path(__file__).parent
CHECK_ROUTE_BAT = BASE_DIR / "client-tools" / "check-route.bat"

settings = load_settings()
IFACE = settings["interface"]
_lock = threading.Lock()  # все изменения пиров — строго по одному
_login_fails: dict[str, list[float]] = {}


def sync_server_conf() -> None:
    wg.write_server_conf(settings, db.list_clients())


def _maintenance_loop(stop: threading.Event) -> None:
    # После перезагрузки панель может стартовать раньше туннеля, а при рестарте
    # туннеля интерфейс пересоздаётся и теряет forwarding. Поэтому периодически
    # переприменяем forwarding и сверяем пиров с базой.
    delay = 5
    while not stop.is_set():
        try:
            with _lock:
                wg.ensure_forwarding(IFACE)
                wg.reconcile(IFACE, db.list_clients())
            delay = 300
        except Exception as e:
            log.warning("Интерфейс %s пока недоступен: %s", IFACE, e)
            delay = 10
        stop.wait(delay)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    sync_server_conf()
    stop = threading.Event()
    threading.Thread(target=_maintenance_loop, args=(stop,), daemon=True).start()
    yield
    stop.set()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings["session_secret"],
    session_cookie="wgpanel",
    max_age=7 * 24 * 3600,
    same_site="strict",
    https_only=True,
)
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
templates = Jinja2Templates(directory=HERE / "templates")


# ---------- helpers ----------

def authed(request: Request) -> bool:
    return request.session.get("auth") is True


def require_auth(request: Request) -> None:
    if not authed(request):
        raise HTTPException(status_code=401)


@app.exception_handler(401)
async def unauthorized(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return RedirectResponse("/login", status_code=303)


def get_client_or_404(client_id: int) -> dict:
    c = db.get_client(client_id)
    if not c:
        raise HTTPException(status_code=404, detail="Клиент не найден")
    return c


def clean_name(name: str) -> str:
    name = " ".join(name.split())[:64]
    if not name:
        raise HTTPException(status_code=400, detail="Пустое имя")
    return name


_TRANSLIT = dict(zip(
    "абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
    ["a", "b", "v", "g", "d", "e", "e", "zh", "z", "i", "y", "k", "l", "m", "n", "o", "p",
     "r", "s", "t", "u", "f", "h", "ts", "ch", "sh", "sch", "", "y", "", "e", "yu", "ya"],
))


def conf_filename(client: dict) -> str:
    # Имя файла = имя туннеля в приложении WireGuard: только [a-zA-Z0-9_=+.-], до 32 символов
    s = "".join(_TRANSLIT.get(ch, ch) for ch in client["name"].lower())
    s = re.sub(r"[^a-z0-9_=+.-]+", "-", s).strip("-") or f"client{client['id']}"
    return f"wg-{s}"[:32] + ".conf"


def stats_rows() -> tuple[list[dict], str | None]:
    clients = db.list_clients()
    try:
        live = wg.dump(IFACE)
        error = None
    except Exception as e:
        live, error = {}, str(e)
    rows = []
    for c in clients:
        s = live.get(c["public_key"], {})
        hs = s.get("latest_handshake", 0)
        if hs > c["last_seen"]:
            db.update_client(c["id"], last_seen=hs)
            c["last_seen"] = hs
        rows.append({
            "id": c["id"],
            "name": c["name"],
            "address": c["address"],
            "enabled": bool(c["enabled"]),
            "created_at": c["created_at"],
            "online": c["enabled"] and wg.is_online(hs),
            "endpoint": s.get("endpoint", ""),
            "last_seen": c["last_seen"],
            "rx": s.get("rx", 0),
            "tx": s.get("tx", 0),
        })
    return rows, error


def config_status(client: dict, allowed: list[str]) -> str:
    """new — конфиг ещё не выдавался, stale — выданный устарел, ok — актуален."""
    issued = client.get("issued_allowed_ips")
    if issued is None:
        return "new"
    return "ok" if issued == ", ".join(allowed) else "stale"


def issue_config(client: dict) -> tuple[str, list[str]]:
    """Собрать конфиг клиента и запомнить, какие AllowedIPs ему выданы."""
    allowed = split.compute(settings, client)["allowed"]
    text = wg.render_client_conf(settings, client, allowed)
    return text, allowed


def mark_issued(client: dict, allowed: list[str]) -> None:
    db.update_client(client["id"], issued_allowed_ips=", ".join(allowed))


# ---------- auth ----------

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login")
def login(request: Request, password: str = Form(...)):
    ip = request.client.host if request.client else "?"
    now = time.time()
    fails = [t for t in _login_fails.get(ip, []) if now - t < 600]
    if len(fails) >= 5:
        return templates.TemplateResponse(
            request, "login.html", {"error": "Слишком много попыток, подожди 10 минут"},
            status_code=429,
        )
    if not verify_password(password, settings["admin_password_hash"]):
        fails.append(now)
        _login_fails[ip] = fails
        return templates.TemplateResponse(
            request, "login.html", {"error": "Неверный пароль"}, status_code=401,
        )
    _login_fails.pop(ip, None)
    request.session["auth"] = True
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ---------- pages ----------

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    require_auth(request)
    rows, error = stats_rows()
    clients = {c["id"]: c for c in db.list_clients()}
    for r in rows:
        c = clients[r["id"]]
        allowed = split.compute(settings, c)["allowed"]
        r["config_status"] = config_status(c, allowed)
        r["exclusions_count"] = len(split.parse_text(c["exclusions"])[0])
        r["exclude_lan"] = bool(c["exclude_lan"])
    return templates.TemplateResponse(request, "index.html", {
        "rows": rows,
        "error": error,
        "endpoint": f"{settings['endpoint_host']}:{settings['listen_port']}",
    })


@app.get("/api/stats")
def api_stats(request: Request):
    require_auth(request)
    rows, error = stats_rows()
    return {"clients": rows, "error": error, "now": int(time.time())}


# ---------- clients ----------

@app.post("/clients")
def create_client(request: Request, name: str = Form(...)):
    require_auth(request)
    name = clean_name(name)
    with _lock:
        used = {c["address"] for c in db.list_clients()}
        address = wg.next_free_address(settings, used)
        priv, pub = wg.gen_keypair()
        client_id = db.add_client(name, priv, pub, wg.gen_psk(), address)
        client = db.get_client(client_id)
        try:
            wg.add_peer(IFACE, client)
        except Exception as e:
            db.delete_client(client_id)
            raise HTTPException(status_code=500, detail=f"Не удалось добавить пира: {e}")
        sync_server_conf()
    return RedirectResponse(f"/?new={client_id}", status_code=303)


@app.post("/clients/{client_id}/rename")
def rename_client(request: Request, client_id: int, name: str = Form(...)):
    require_auth(request)
    get_client_or_404(client_id)
    db.update_client(client_id, name=clean_name(name))
    return RedirectResponse("/", status_code=303)


@app.post("/clients/{client_id}/toggle")
def toggle_client(request: Request, client_id: int):
    require_auth(request)
    with _lock:
        c = get_client_or_404(client_id)
        if c["enabled"]:
            wg.remove_peer(IFACE, c["public_key"])
            db.update_client(client_id, enabled=0)
        else:
            wg.add_peer(IFACE, c)
            db.update_client(client_id, enabled=1)
        sync_server_conf()
    return RedirectResponse("/", status_code=303)


@app.post("/clients/{client_id}/delete")
def delete_client(request: Request, client_id: int):
    require_auth(request)
    with _lock:
        c = get_client_or_404(client_id)
        if c["enabled"]:
            wg.remove_peer(IFACE, c["public_key"])
        db.delete_client(client_id)
        sync_server_conf()
    return RedirectResponse("/", status_code=303)


@app.get("/clients/{client_id}/config")
def download_config(request: Request, client_id: int):
    require_auth(request)
    c = get_client_or_404(client_id)
    text, allowed = issue_config(c)
    mark_issued(c, allowed)
    return Response(
        text,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{conf_filename(c)}"',
            "Cache-Control": "no-store",
        },
    )


@app.get("/clients/{client_id}/qr")
def config_qr(request: Request, client_id: int):
    require_auth(request)
    c = get_client_or_404(client_id)
    text, allowed = issue_config(c)
    try:
        # уровень коррекции L: QR менее плотный, большие конфиги легче сканировать с экрана
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            image_factory=qrcode.image.svg.SvgPathImage,
            box_size=10,
            border=2,
        )
        qr.add_data(text)
        img = qr.make_image()
    except (qrcode.exceptions.DataOverflowError, ValueError):
        # слишком много исключений — в QR не влезает, остаётся только файл
        return Response("too large", status_code=413)
    mark_issued(c, allowed)
    buf = io.BytesIO()
    img.save(buf)
    return Response(buf.getvalue(), media_type="image/svg+xml",
                    headers={"Cache-Control": "no-store"})


@app.get("/tools/check-route.bat")
def download_check_route(request: Request):
    """Батник для Windows-клиента: идёт ли адрес через VPN или напрямую (+ трассировка)."""
    require_auth(request)
    if not CHECK_ROUTE_BAT.exists():
        raise HTTPException(status_code=404, detail="check-route.bat не найден")
    return FileResponse(
        CHECK_ROUTE_BAT,
        media_type="application/octet-stream",
        filename="check-route.bat",
    )


# ---------- маршруты (исключения из туннеля) ----------

def routes_context(c: dict, form_errors: list[str] | None = None) -> dict:
    result = split.compute(settings, c)
    return {
        "c": c,
        "entries": split.parse_text(c["exclusions"])[0],
        "resolved": result["resolved"],
        "endpoint": result["endpoint"],
        "allowed": result["allowed"],
        "errors": list(dict.fromkeys((form_errors or []) + result["errors"])),
        "status": config_status(c, result["allowed"]),
        "lan_nets": split.LAN_NETS,
    }


@app.get("/clients/{client_id}/routes", response_class=HTMLResponse)
def routes_page(request: Request, client_id: int):
    require_auth(request)
    c = get_client_or_404(client_id)
    return templates.TemplateResponse(request, "routes.html", routes_context(c))


@app.post("/clients/{client_id}/routes", response_class=HTMLResponse)
def save_routes(
    request: Request,
    client_id: int,
    exclusions: str = Form(""),
    exclude_lan: str | None = Form(None),
):
    require_auth(request)
    c = get_client_or_404(client_id)
    entries, errors = split.parse_text(exclusions)
    # домены проверяем сразу, чтобы опечатка не сохранилась молча
    for kind, value in entries:
        if kind == "domain":
            try:
                split.resolve(value)
            except split.EntryError as ex:
                errors.append(str(ex))
    if errors:
        draft = {**c, "exclusions": exclusions, "exclude_lan": int(bool(exclude_lan))}
        ctx = routes_context(draft, errors)
        ctx["draft_text"] = exclusions
        return templates.TemplateResponse(request, "routes.html", ctx, status_code=400)
    normalized = "\n".join(v for _, v in entries)
    db.update_client(client_id, exclusions=normalized, exclude_lan=int(bool(exclude_lan)))
    return RedirectResponse(f"/clients/{client_id}/routes?saved=1", status_code=303)
