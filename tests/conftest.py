"""Test fixtures"""
import os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest
from app.models.db import init_db
from app.models.seed import seed_all


@pytest.fixture(autouse=True)
def fresh_db(monkeypatch):
    import app.models.db as db_mod
    test_db = tempfile.mktemp(suffix=".db")
    monkeypatch.setattr(db_mod, "DB_PATH", Path(test_db))
    init_db()
    seed_all(verbose=False)
    yield
    try: Path(test_db).unlink()
    except FileNotFoundError: pass