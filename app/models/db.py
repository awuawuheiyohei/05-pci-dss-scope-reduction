"""数据库访问层"""
import sqlite3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "pci.db"
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema.sql"


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(verbose: bool = False) -> sqlite3.Connection:
    conn = get_conn()
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    conn.executescript(schema)
    conn.commit()
    if verbose:
        print(f"[+] DB initialized at {DB_PATH}")
    return conn


def row_to_dict(row) -> dict:
    return {k: row[k] for k in row.keys()} if row else {}


def rows_to_dicts(rows) -> list:
    return [row_to_dict(r) for r in rows]


def write_audit(conn, actor: str, action: str, entity_type: str = None,
                entity_id: str = None, details: dict = None) -> None:
    conn.execute(
        """INSERT INTO audit_trail (actor, action, entity_type, entity_id, details)
           VALUES (?, ?, ?, ?, ?)""",
        (actor, action, entity_type, entity_id, json.dumps(details or {}, ensure_ascii=False))
    )
    conn.commit()