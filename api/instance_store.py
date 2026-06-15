"""
Instance (scan/analysis workspace) store for CTPPO (Phase B / B3)
=================================================================

An *instance* is a user-owned scan/analysis workspace. Its inputs are a prompt, a target
spec, and files (recorded with derived metadata — "metadata scans"). This is the canonical
in-memory store (run-anywhere, like the B1/B2 stores); a B-phase task can back it with
Postgres via api/database.py. Actual file-content handling / engine scanning is wired in
later (B5) — here a file is stored as its metadata record, not its bytes.

Every accessor is owner-scoped: a user only ever sees or mutates their own instances.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Dict, List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scan_files(files: Optional[List[dict]]) -> List[dict]:
    """Normalize provided file descriptors into metadata records (the 'metadata scan')."""
    scanned = []
    for f in files or []:
        name = (f.get("name") or "").strip()
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        scanned.append({
            "name": name,
            "size": int(f.get("size") or 0),
            "content_type": f.get("content_type") or "",
            "ext": ext,
            "scanned_at": _now(),
        })
    return scanned


class InstanceStore:
    """CRUD over user-owned instances, keyed by instance id."""

    _MUTABLE = ("name", "prompt", "target_spec", "files", "status")

    def __init__(self, persistence=None) -> None:
        self._by_id: Dict[str, dict] = {}
        self._p = persistence
        if self._p:
            self._by_id = dict(self._p.load())

    def create(self, owner: str, name: str, prompt: str = "",
               target_spec: Optional[dict] = None, files: Optional[List[dict]] = None) -> dict:
        instance_id = f"inst_{secrets.token_hex(6)}"
        now = _now()
        instance = {
            "id": instance_id,
            "owner": owner.lower(),
            "name": name,
            "prompt": prompt,
            "target_spec": target_spec or {},
            "files": _scan_files(files),
            "status": "draft",
            "created_at": now,
            "updated_at": now,
        }
        self._by_id[instance_id] = instance
        if self._p:
            self._p.upsert(instance_id, instance)
        return instance

    def get(self, instance_id: str, owner: str) -> Optional[dict]:
        instance = self._by_id.get(instance_id)
        if instance and instance["owner"] == owner.lower():
            return instance
        return None

    def list_for(self, owner: str) -> List[dict]:
        return [i for i in self._by_id.values() if i["owner"] == owner.lower()]

    def update(self, instance_id: str, owner: str, **fields) -> Optional[dict]:
        instance = self.get(instance_id, owner)
        if instance is None:
            return None
        if fields.get("files") is not None:
            fields["files"] = _scan_files(fields["files"])
        for key in self._MUTABLE:
            if fields.get(key) is not None:
                instance[key] = fields[key]
        instance["updated_at"] = _now()
        if self._p:
            self._p.upsert(instance_id, instance)
        return instance

    def delete(self, instance_id: str, owner: str) -> bool:
        if self.get(instance_id, owner) is None:
            return False
        del self._by_id[instance_id]
        if self._p:
            self._p.delete(instance_id)
        return True


# Default process-wide instance store shared by the API (persistent when CTPPO_DB_URL is set).
from persistence import default_persistence  # noqa: E402
instances = InstanceStore(persistence=default_persistence("instances"))
