"""
Organization / enterprise store for CTPPO (Phase B / B4)
========================================================

The enterprise tier: organizations with a seat allotment and role-based access control.
The creator becomes the org's first admin; admins manage membership and assign roles
(``admin`` / ``member``) up to the org's seat limit. Members can view the roster but not
mutate it. A user belongs to at most one org.

Canonical in-memory store (run-anywhere, like the B1–B3 stores); a B-phase task can back
it with Redis/Postgres. Mutating methods raise ``OrgError`` (carrying an HTTP status +
detail) so the router maps permission/seat/last-admin failures to the right response.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Dict, List, Optional

ROLES = ("admin", "member")


class OrgError(Exception):
    """Raised for org access/validation failures; carries an HTTP status + detail."""

    def __init__(self, status: int, detail: str) -> None:
        self.status = status
        self.detail = detail
        super().__init__(detail)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class OrgStore:
    def __init__(self) -> None:
        self._orgs: Dict[str, dict] = {}          # org_id -> org
        self._user_org: Dict[str, str] = {}        # email -> org_id (one org per user)

    # --- internals --------------------------------------------------------
    def _get(self, org_id: str) -> dict:
        org = self._orgs.get(org_id)
        if not org:
            raise OrgError(404, "Organization not found")
        return org

    def _require_member(self, org_id: str, actor: str) -> dict:
        org = self._get(org_id)
        if actor.lower() not in org["members"]:
            raise OrgError(404, "Organization not found")   # don't reveal orgs you're not in
        return org

    def _require_admin(self, org_id: str, actor: str) -> dict:
        org = self._require_member(org_id, actor)
        if org["members"][actor.lower()] != "admin":
            raise OrgError(403, "Organization admin role required")
        return org

    @staticmethod
    def _admin_count(org: dict) -> int:
        return sum(1 for r in org["members"].values() if r == "admin")

    # --- public API -------------------------------------------------------
    def create_org(self, name: str, admin_email: str, seats: int = 5) -> dict:
        admin = admin_email.lower()
        if admin in self._user_org:
            raise OrgError(400, "You already belong to an organization")
        if seats < 1:
            raise OrgError(400, "seats must be >= 1")
        org_id = f"org_{secrets.token_hex(6)}"
        org = {
            "id": org_id,
            "name": name,
            "seats": seats,
            "members": {admin: "admin"},
            "created_at": _now(),
        }
        self._orgs[org_id] = org
        self._user_org[admin] = org_id
        return org

    def org_for_user(self, email: str) -> Optional[dict]:
        org_id = self._user_org.get(email.lower())
        return self._orgs.get(org_id) if org_id else None

    def get_org(self, org_id: str, actor: str) -> dict:
        return self._require_member(org_id, actor)

    def list_members(self, org_id: str, actor: str) -> List[dict]:
        org = self._require_member(org_id, actor)
        return [{"email": e, "role": r} for e, r in org["members"].items()]

    def add_member(self, org_id: str, actor: str, member_email: str, role: str = "member") -> dict:
        org = self._require_admin(org_id, actor)
        member = member_email.lower()
        if role not in ROLES:
            raise OrgError(400, f"Invalid role (must be one of {ROLES})")
        if member in org["members"]:
            raise OrgError(400, "User is already a member of this organization")
        if member in self._user_org:
            raise OrgError(400, "User already belongs to an organization")
        if len(org["members"]) >= org["seats"]:
            raise OrgError(400, "Seat allotment exhausted")
        org["members"][member] = role
        self._user_org[member] = org_id
        return org

    def set_role(self, org_id: str, actor: str, member_email: str, role: str) -> dict:
        org = self._require_admin(org_id, actor)
        member = member_email.lower()
        if role not in ROLES:
            raise OrgError(400, f"Invalid role (must be one of {ROLES})")
        if member not in org["members"]:
            raise OrgError(404, "Member not found")
        if org["members"][member] == "admin" and role != "admin" and self._admin_count(org) == 1:
            raise OrgError(400, "Cannot demote the last admin")
        org["members"][member] = role
        return org

    def remove_member(self, org_id: str, actor: str, member_email: str) -> dict:
        org = self._require_admin(org_id, actor)
        member = member_email.lower()
        if member not in org["members"]:
            raise OrgError(404, "Member not found")
        if org["members"][member] == "admin" and self._admin_count(org) == 1:
            raise OrgError(400, "Cannot remove the last admin")
        del org["members"][member]
        self._user_org.pop(member, None)
        return org


# Default process-wide org store shared by the API.
orgs = OrgStore()
