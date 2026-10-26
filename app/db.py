import sqlite3
from contextlib import contextmanager

from .config import DATA_DIR, DB_FILE

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    private_key   TEXT NOT NULL,
    public_key    TEXT NOT NULL UNIQUE,
    preshared_key TEXT NOT NULL,
    address       TEXT NOT NULL UNIQUE,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    last_seen     INTEGER NOT NULL DEFAULT 0
);
"""

# Колонки, добавленные позже: (имя, определение). Старые базы догоняются через ALTER TABLE.
MIGRATIONS = [
    # исключения из туннеля: IP, подсети или домены, по одному на строку
    ("exclusions", "TEXT NOT NULL DEFAULT ''"),
    ("exclude_lan", "INTEGER NOT NULL DEFAULT 0"),
    # AllowedIPs из последнего выданного конфига; NULL — конфиг ещё не выдавался.
    # Для клиентов, созданных до появления исключений, это 0.0.0.0/0.
    ("issued_allowed_ips", "TEXT DEFAULT '0.0.0.0/0'"),
]


@contextmanager
def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        existing = {r["name"] for r in conn.execute("PRAGMA table_info(clients)")}
        for name, definition in MIGRATIONS:
            if name not in existing:
                conn.execute(f"ALTER TABLE clients ADD COLUMN {name} {definition}")


def list_clients() -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM clients ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def get_client(client_id: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    return dict(row) if row else None


def add_client(name, private_key, public_key, preshared_key, address) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO clients"
            " (name, private_key, public_key, preshared_key, address, issued_allowed_ips)"
            " VALUES (?, ?, ?, ?, ?, NULL)",
            (name, private_key, public_key, preshared_key, address),
        )
        return cur.lastrowid


def update_client(client_id: int, **fields) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k} = ?" for k in fields)
    with connect() as conn:
        conn.execute(f"UPDATE clients SET {cols} WHERE id = ?", (*fields.values(), client_id))


def delete_client(client_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
