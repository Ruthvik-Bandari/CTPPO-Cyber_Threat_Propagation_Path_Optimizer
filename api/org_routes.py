"""
Organization / enterprise routes for CTPPO (Phase B / B4)
=========================================================

CRUD over organizations and their membership, with RBAC enforced by ``org_store``. The
current user is supplied by an injected dependency (the app passes server_secure's
``get_current_user`` — auth + active subscription), so the enterprise endpoints are
subscription-gated; ``OrgStore`` then enforces per-org admin/member permissions.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr

from org_store import OrgStore, OrgError


class OrgCreate(BaseModel):
    name: str
    seats: int = 5


class MemberAdd(BaseModel):
    email: EmailStr
    role: str = "member"


class RoleUpdate(BaseModel):
    role: str


def _guard(call):
    """Run a store call, translating OrgError into the right HTTP response."""
    try:
        return call()
    except OrgError as e:
        raise HTTPException(status_code=e.status, detail=e.detail)


def create_org_router(store: OrgStore, current_user, create_user=None) -> APIRouter:
    """``create_user`` is the dependency gating org *creation* (e.g. an enterprise-tier check);
    it defaults to ``current_user`` when omitted, so isolated tests keep working unchanged."""
    router = APIRouter(prefix="/api/orgs", tags=["Organizations"])
    create_user = create_user or current_user

    @router.post("")
    async def create_org(body: OrgCreate, user: dict = Depends(create_user)):
        return _guard(lambda: store.create_org(body.name, user["email"], body.seats))

    @router.get("/me")
    async def my_org(user: dict = Depends(current_user)):
        org = store.org_for_user(user["email"])
        if org is None:
            return {"org": None, "role": None}
        return {"org": org, "role": org["members"][user["email"].lower()]}

    @router.get("/{org_id}/members")
    async def list_members(org_id: str, user: dict = Depends(current_user)):
        return {"members": _guard(lambda: store.list_members(org_id, user["email"]))}

    @router.post("/{org_id}/members")
    async def add_member(org_id: str, body: MemberAdd, user: dict = Depends(current_user)):
        return _guard(lambda: store.add_member(org_id, user["email"], body.email, body.role))

    @router.put("/{org_id}/members/{member_email}")
    async def set_role(org_id: str, member_email: str, body: RoleUpdate, user: dict = Depends(current_user)):
        return _guard(lambda: store.set_role(org_id, user["email"], member_email, body.role))

    @router.delete("/{org_id}/members/{member_email}")
    async def remove_member(org_id: str, member_email: str, user: dict = Depends(current_user)):
        _guard(lambda: store.remove_member(org_id, user["email"], member_email))
        return {"ok": True}

    return router
