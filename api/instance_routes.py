"""
Instance CRUD routes for CTPPO (Phase B / B3)
=============================================

REST CRUD over user-owned scan/analysis workspaces (``instance_store``). The current user
is supplied by an injected dependency — in the app that is server_secure's
``get_current_user`` (auth **and** active subscription, owners bypass), so instances are
both subscription-gated and owner-scoped. Injection also keeps the router testable in
isolation with a fake user dependency.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from instance_store import InstanceStore


class FileMeta(BaseModel):
    name: str
    size: int = 0
    content_type: str = ""


class InstanceCreate(BaseModel):
    name: str
    prompt: str = ""
    target_spec: dict = {}
    files: List[FileMeta] = []


class InstanceUpdate(BaseModel):
    name: Optional[str] = None
    prompt: Optional[str] = None
    target_spec: Optional[dict] = None
    files: Optional[List[FileMeta]] = None
    status: Optional[str] = None


def create_instance_router(store: InstanceStore, current_user) -> APIRouter:
    """Build the /api/instances router. ``current_user`` is a FastAPI dependency
    returning the authenticated, subscribed user dict."""
    router = APIRouter(prefix="/api/instances", tags=["Instances"])

    @router.post("")
    async def create_instance(body: InstanceCreate, user: dict = Depends(current_user)):
        return store.create(
            user["email"], body.name, body.prompt, body.target_spec,
            [f.model_dump() for f in body.files],
        )

    @router.get("")
    async def list_instances(user: dict = Depends(current_user)):
        return {"instances": store.list_for(user["email"])}

    @router.get("/{instance_id}")
    async def get_instance(instance_id: str, user: dict = Depends(current_user)):
        instance = store.get(instance_id, user["email"])
        if instance is None:
            raise HTTPException(status_code=404, detail="Instance not found")
        return instance

    @router.put("/{instance_id}")
    async def update_instance(instance_id: str, body: InstanceUpdate, user: dict = Depends(current_user)):
        # model_dump() recursively turns FileMeta into dicts; drop unset (None) fields.
        updates = {k: v for k, v in body.model_dump().items() if v is not None}
        instance = store.update(instance_id, user["email"], **updates)
        if instance is None:
            raise HTTPException(status_code=404, detail="Instance not found")
        return instance

    @router.delete("/{instance_id}")
    async def delete_instance(instance_id: str, user: dict = Depends(current_user)):
        if not store.delete(instance_id, user["email"]):
            raise HTTPException(status_code=404, detail="Instance not found")
        return {"ok": True}

    return router
