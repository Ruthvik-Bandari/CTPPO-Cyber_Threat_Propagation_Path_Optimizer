"""HTTP route for the passive web exposure check."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from .models import Report
from .scan import scan

router = APIRouter(prefix="/api/webcheck", tags=["webcheck"])


class ScanBody(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    allow_private: bool = Field(
        default=False, description="Allow private/loopback targets such as a lab server you own."
    )


@router.post("", response_model=Report)
def webcheck(body: ScanBody) -> Report:
    return scan(body.url, allow_private=body.allow_private)
