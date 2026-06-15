"""
Optional SQLAlchemy persistence for the in-memory stores (Phase D / prod-scaling)
=================================================================================

A single generic document table — (namespace, key, JSON value) — that the canonical stores
load-on-start and write-through to **when ``CTPPO_DB_URL`` (or ``DATABASE_URL``) is set**.
Without it the stores run purely in memory (the default; dev + the whole test suite). Works on
SQLite and Postgres (psycopg2 is already a dependency).

Scope: single-process **write-through** persistence (survives restarts). Multi-process
read-through coherence is out of scope — for that, point all processes at Postgres and add a
read path, or use Redis (sessions already do, via REDIS_URL in session_store).
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Dict, Optional

_DB_URL = os.environ.get("CTPPO_DB_URL") or os.environ.get("DATABASE_URL")
_backend = None
_lock = threading.Lock()


class _Backend:
    """One document table shared by every namespace. Dialect-agnostic upsert (delete+insert)."""

    def __init__(self, url: str) -> None:
        from sqlalchemy import create_engine, Column, String, Text, MetaData, Table
        self._url = url
        self.engine = create_engine(url, future=True, pool_pre_ping=True)
        self.meta = MetaData()
        self.table = Table(
            "ctppo_store", self.meta,
            Column("namespace", String(64), primary_key=True),
            Column("key", String(255), primary_key=True),
            Column("value", Text, nullable=False),
            Column("updated_at", String(40)),
        )
        self.meta.create_all(self.engine)

    def upsert(self, ns: str, key: str, obj: dict) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.engine.begin() as conn:
            conn.execute(self.table.delete().where(
                (self.table.c.namespace == ns) & (self.table.c.key == str(key))))
            conn.execute(self.table.insert().values(
                namespace=ns, key=str(key), value=json.dumps(obj), updated_at=now))

    def delete(self, ns: str, key: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(self.table.delete().where(
                (self.table.c.namespace == ns) & (self.table.c.key == str(key))))

    def load(self, ns: str) -> Dict[str, dict]:
        from sqlalchemy import select
        with self.engine.connect() as conn:
            rows = conn.execute(select(self.table.c.key, self.table.c.value)
                                .where(self.table.c.namespace == ns)).all()
        return {k: json.loads(v) for k, v in rows}


class Namespaced:
    """A store's view of the backend, scoped to its namespace."""

    def __init__(self, backend: _Backend, namespace: str) -> None:
        self._b = backend
        self.ns = namespace

    def upsert(self, key: str, obj: dict) -> None:
        self._b.upsert(self.ns, key, obj)

    def delete(self, key: str) -> None:
        self._b.delete(self.ns, key)

    def load(self) -> Dict[str, dict]:
        return self._b.load(self.ns)


def _get_backend() -> Optional[_Backend]:
    global _backend
    if not _DB_URL:
        return None
    with _lock:
        if _backend is None:
            try:
                _backend = _Backend(_DB_URL)
                print(f"[persistence] store persistence enabled ({_DB_URL.split('://')[0]})")
            except Exception as e:  # bad URL / driver missing → fall back to memory
                print(f"[persistence] init failed ({e}); using in-memory stores.")
                return None
        return _backend


def default_persistence(namespace: str) -> Optional[Namespaced]:
    """Namespaced persistence if a DB is configured, else None (→ in-memory store)."""
    b = _get_backend()
    return Namespaced(b, namespace) if b is not None else None


def persistence_for(url: str, namespace: str) -> Namespaced:
    """Build an explicit-URL persistence facade (used by tests against a temp SQLite file)."""
    return Namespaced(_Backend(url), namespace)
