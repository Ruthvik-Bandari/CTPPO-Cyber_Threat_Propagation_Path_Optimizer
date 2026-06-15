"""
Minimal transactional mailer for CTPPO (password reset)
=======================================================

Real SMTP send path when configured via env; a labeled no-op otherwise so dev/tests keep
working (the reset token is still surfaced via EXPOSE_RESET_TOKEN in dev). No new
dependencies — stdlib ``smtplib`` + ``email``.

Env:
  SMTP_HOST      enable sending (presence = configured)
  SMTP_PORT      default 587
  SMTP_USER      / SMTP_PASSWORD  optional auth
  SMTP_FROM      default = SMTP_USER or no-reply@ctppo.local
  SMTP_STARTTLS  default "true"
"""

from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage


def mailer_configured() -> bool:
    """True when an SMTP host is configured (so the app can prefer email over the dev token)."""
    return bool(os.environ.get("SMTP_HOST"))


def send_email(to: str, subject: str, body: str) -> bool:
    """Send a plain-text email. Returns True on success, False if unconfigured or it fails."""
    host = os.environ.get("SMTP_HOST")
    if not host:
        return False
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    sender = os.environ.get("SMTP_FROM", user or "no-reply@ctppo.local")
    use_tls = os.environ.get("SMTP_STARTTLS", "true").lower() == "true"

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(host, port, timeout=15) as server:
            if use_tls:
                server.starttls(context=ssl.create_default_context())
            if user and password:
                server.login(user, password)
            server.send_message(msg)
        return True
    except Exception as e:  # network/auth failure — never raise into the request path
        print(f"[mailer] send failed: {e}")
        return False
