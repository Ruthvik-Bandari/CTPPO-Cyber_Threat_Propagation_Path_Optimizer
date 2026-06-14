"""
API-key management routes for CTPPO (Phase B / B5a)
===================================================

Issue / list / revoke API keys for the current user. Key management is itself
session-authenticated and subscription-gated (the app passes ``get_current_user``), since
keys are "issued from the subscription". The issued raw key is returned exactly once.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api_key_store import ApiKeyStore


class KeyCreate(BaseModel):
    name: str = "default"


def create_api_key_router(store: ApiKeyStore, current_user) -> APIRouter:
    router = APIRouter(prefix="/api/keys", tags=["API Keys"])

    @router.post("")
    async def issue_key(body: KeyCreate, user: dict = Depends(current_user)):
        raw, record = store.issue(user["email"], body.name)
        return {
            "api_key": raw,                    # shown once — clients must store it now
            "id": record["id"],
            "name": record["name"],
            "prefix": record["prefix"],
            "note": "Store this key now; it is not retrievable again.",
        }

    @router.get("")
    async def list_keys(user: dict = Depends(current_user)):
        return {"keys": store.list_for(user["email"])}

    @router.delete("/{key_id}")
    async def revoke_key(key_id: str, user: dict = Depends(current_user)):
        if not store.revoke(user["email"], key_id):
            raise HTTPException(status_code=404, detail="API key not found")
        return {"ok": True}

    return router
