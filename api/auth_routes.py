"""
Session-based auth routes for CTPPO (Phase B / B1)
==================================================

Signup / login / logout / forgot-password / reset-password backed by server-side
Redis sessions (``session_store``) and salted password hashing (``passwords``), against
the canonical ``user_store``. Sessions live server-side and the session id travels in an
HttpOnly cookie, so **logout is a real server-side revocation** (unlike the prior
stateless JWT). ``create_auth_router`` takes its stores by injection so it can be tested
in isolation and mounted onto the main app with the shared instances.

Email delivery for password reset is stubbed in dev: the reset token is returned in the
response (clearly labeled ``dev_reset_token``) and logged, instead of emailed. B6/prod
wires a real mailer; the token mechanism itself is production-real.
"""

from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field

from passwords import hash_password, verify_password
from session_store import SessionStore, SESSION_TTL_SECONDS
from user_store import UserStore, public_view

SESSION_COOKIE = "ctppo_session"
_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
# SameSite for the session cookie. Default "lax" (good for same-origin / Vite-proxy dev). A
# cross-origin prod frontend must set COOKIE_SAMESITE=none, which browsers only honour on a
# Secure cookie — so we force Secure on in that case.
_COOKIE_SAMESITE = os.environ.get("COOKIE_SAMESITE", "lax").lower()
if _COOKIE_SAMESITE not in ("lax", "strict", "none"):
    _COOKIE_SAMESITE = "lax"
if _COOKIE_SAMESITE == "none":
    _COOKIE_SECURE = True
# In dev (no mailer) we surface the reset token in the response so the flow is testable.
_EXPOSE_RESET_TOKEN = os.environ.get("EXPOSE_RESET_TOKEN", "true").lower() == "true"


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    name: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


def _set_session_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=session_id,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite=_COOKIE_SAMESITE,
        secure=_COOKIE_SECURE,
        path="/",
    )


def create_auth_router(users: UserStore, sessions: SessionStore) -> APIRouter:
    router = APIRouter(prefix="/api/auth", tags=["Auth"])

    def _current_user(request: Request) -> dict:
        sid = request.cookies.get(SESSION_COOKIE)
        session = sessions.get_session(sid) if sid else None
        if not session:
            raise HTTPException(status_code=401, detail="Not authenticated")
        user = users.get(session["email"])
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user

    @router.post("/signup")
    async def signup(req: SignupRequest, response: Response):
        if req.email in users:
            raise HTTPException(status_code=400, detail="Email already registered")
        user = users.create_user(req.email, req.name, hash_password(req.password))
        session_id = sessions.create_session(user["email"])
        _set_session_cookie(response, session_id)
        return {"user": public_view(user)}

    @router.post("/login")
    async def login(req: LoginRequest, response: Response):
        user = users.get(req.email)
        if not user or not verify_password(req.password, user.get("password_hash", "")):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        session_id = sessions.create_session(user["email"])
        _set_session_cookie(response, session_id)
        return {"user": public_view(user)}

    @router.post("/logout")
    async def logout(request: Request, response: Response):
        sid = request.cookies.get(SESSION_COOKIE)
        revoked = sessions.delete_session(sid) if sid else False
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"ok": True, "revoked": revoked}

    @router.get("/me")
    async def me(request: Request):
        return {"user": public_view(_current_user(request))}

    @router.post("/forgot-password")
    async def forgot_password(req: ForgotPasswordRequest):
        # Always return the same generic message so we don't leak which emails exist.
        generic = {"message": "If an account exists for that email, a reset link has been sent."}
        if req.email in users:
            token = sessions.create_reset_token(req.email)
            print(f"[auth] password reset requested for {req.email.lower()} "
                  f"(email delivery stubbed; token issued)")
            if _EXPOSE_RESET_TOKEN:
                # Dev only — no mailer configured. Clearly labeled, never use in prod.
                return {**generic, "dev_reset_token": token}
        return generic

    @router.post("/reset-password")
    async def reset_password(req: ResetPasswordRequest, response: Response):
        email = sessions.consume_reset_token(req.token)
        if not email:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")
        if not users.set_password(email, hash_password(req.new_password)):
            raise HTTPException(status_code=404, detail="User not found")
        return {"ok": True}

    return router
