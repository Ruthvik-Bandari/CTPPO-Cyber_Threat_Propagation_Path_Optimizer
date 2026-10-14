"""Pure evaluators for response headers, cookies and TLS results (no network access)."""

from __future__ import annotations

import re

from .models import Finding, TlsInfo

Headers = dict[str, list[str]]  # lower-cased name -> every value received

HSTS_MIN_AGE = 15_552_000  # 180 days
CERT_EXPIRY_WARN_DAYS = 14
_EVIDENCE_CHARS = 200
_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.I)
_VERSION = re.compile(r"\d+\.\d+")


def _ev(text: str) -> str:
    return text if len(text) <= _EVIDENCE_CHARS else text[: _EVIDENCE_CHARS - 1] + "…"


def _one(headers: Headers, name: str) -> str | None:
    values = headers.get(name)
    return values[0] if values else None


def check_https(final_scheme: str) -> list[Finding]:
    if final_scheme == "https":
        return []
    return [
        Finding(
            id="https.not_used",
            severity="high",
            title="Site is served over plain HTTP",
            explanation="Traffic can be read or changed by anyone on the network path, including passwords and session cookies.",
            recommendation="Serve the site over HTTPS (free certificates are available from Let's Encrypt) and redirect HTTP to HTTPS.",
        )
    ]


def check_hsts(headers: Headers, https: bool) -> list[Finding]:
    if not https:
        return []
    value = _one(headers, "strict-transport-security")
    if value is None:
        return [
            Finding(
                id="hsts.missing",
                severity="medium",
                title="HSTS header missing",
                explanation="Without Strict-Transport-Security, a browser's first visit can be downgraded to HTTP by an attacker.",
                recommendation="Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            )
        ]
    out = []
    match = _MAX_AGE.search(value)
    if match is None or int(match.group(1)) < HSTS_MIN_AGE:
        out.append(
            Finding(
                id="hsts.short_max_age",
                severity="low",
                title="HSTS max-age is short",
                explanation="A short max-age lets the browser forget the HTTPS-only rule quickly.",
                recommendation="Use a max-age of at least 15552000 (180 days); 31536000 is common.",
                evidence=_ev(value),
            )
        )
    if "includesubdomains" not in value.lower():
        out.append(
            Finding(
                id="hsts.no_subdomains",
                severity="info",
                title="HSTS does not cover subdomains",
                explanation="Subdomains can still be reached over HTTP and used to attack cookies of the main site.",
                recommendation="Add includeSubDomains once every subdomain supports HTTPS.",
                evidence=_ev(value),
            )
        )
    return out


def _csp_directives(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            out.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return out


def check_csp(headers: Headers) -> list[Finding]:
    value = _one(headers, "content-security-policy")
    if value is None:
        return [
            Finding(
                id="csp.missing",
                severity="medium",
                title="Content-Security-Policy missing",
                explanation="A CSP limits which scripts may run, which greatly reduces the impact of cross-site scripting (XSS).",
                recommendation="Start with \"default-src 'self'; object-src 'none'; base-uri 'none'\" and tighten from there.",
            )
        ]
    directives = _csp_directives(value)
    scripts = directives.get("script-src", directives.get("default-src", []))
    out = []
    if "'unsafe-inline'" in scripts:
        out.append(
            Finding(
                id="csp.unsafe_inline",
                severity="low",
                title="CSP allows inline scripts",
                explanation="'unsafe-inline' lets injected <script> tags run, which removes most of CSP's XSS protection.",
                recommendation="Use nonces or hashes for the inline scripts you need and drop 'unsafe-inline'.",
                evidence=_ev(value),
            )
        )
    if "'unsafe-eval'" in scripts:
        out.append(
            Finding(
                id="csp.unsafe_eval",
                severity="low",
                title="CSP allows eval()",
                explanation="'unsafe-eval' lets strings be executed as code, a common XSS escalation path.",
                recommendation="Remove 'unsafe-eval' and replace eval-style code.",
                evidence=_ev(value),
            )
        )
    if any(src in {"*", "http:", "https:", "data:"} for src in scripts):
        out.append(
            Finding(
                id="csp.wildcard_source",
                severity="low",
                title="CSP allows scripts from any host",
                explanation="A wildcard or bare scheme source lets scripts load from attacker-controlled servers.",
                recommendation="List the exact hosts that serve your scripts.",
                evidence=_ev(value),
            )
        )
    return out


def check_framing(headers: Headers) -> list[Finding]:
    xfo = (_one(headers, "x-frame-options") or "").strip().upper()
    csp = _csp_directives(_one(headers, "content-security-policy") or "")
    if xfo in {"DENY", "SAMEORIGIN"} or "frame-ancestors" in csp:
        return []
    return [
        Finding(
            id="framing.unprotected",
            severity="medium",
            title="Page can be embedded by other sites",
            explanation="Without X-Frame-Options or CSP frame-ancestors, attackers can overlay your page to trick clicks (clickjacking).",
            recommendation="Send \"Content-Security-Policy: frame-ancestors 'self'\" (or X-Frame-Options: DENY).",
        )
    ]


def check_simple_headers(headers: Headers) -> list[Finding]:
    out = []
    if (_one(headers, "x-content-type-options") or "").strip().lower() != "nosniff":
        out.append(
            Finding(
                id="xcto.missing",
                severity="low",
                title="X-Content-Type-Options missing",
                explanation="Browsers may guess content types and run an uploaded file as script.",
                recommendation="Send 'X-Content-Type-Options: nosniff'.",
            )
        )
    referrer = _one(headers, "referrer-policy")
    if referrer is None or referrer.strip().lower() in {"unsafe-url", "no-referrer-when-downgrade"}:
        out.append(
            Finding(
                id="referrer.weak",
                severity="low",
                title="Referrer-Policy missing or permissive",
                explanation="Full URLs, which can contain tokens or personal data, may leak to other sites.",
                recommendation="Send 'Referrer-Policy: strict-origin-when-cross-origin' (or no-referrer).",
                evidence=_ev(referrer) if referrer else None,
            )
        )
    if _one(headers, "permissions-policy") is None:
        out.append(
            Finding(
                id="permissions_policy.missing",
                severity="info",
                title="Permissions-Policy missing",
                explanation="Embedded content may request powerful browser features such as camera or geolocation.",
                recommendation="Disable features you do not use, e.g. 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
            )
        )
    if _one(headers, "cross-origin-opener-policy") is None:
        out.append(
            Finding(
                id="coop.missing",
                severity="info",
                title="Cross-Origin-Opener-Policy missing",
                explanation="Other windows you open can keep a reference to your page, enabling some cross-site leaks.",
                recommendation="Send 'Cross-Origin-Opener-Policy: same-origin' if the site does not rely on cross-origin popups.",
            )
        )
    return out


def check_disclosure(headers: Headers) -> list[Finding]:
    out = []
    server = _one(headers, "server")
    if server and _VERSION.search(server):
        out.append(
            Finding(
                id="disclosure.server_version",
                severity="low",
                title="Server header reveals software version",
                explanation="Exact versions help attackers pick known exploits.",
                recommendation="Remove the version from the Server header (e.g. nginx 'server_tokens off').",
                evidence=_ev(server),
            )
        )
    powered = _one(headers, "x-powered-by")
    if powered:
        out.append(
            Finding(
                id="disclosure.powered_by",
                severity="low",
                title="X-Powered-By header present",
                explanation="It advertises the framework and often its version.",
                recommendation="Remove the X-Powered-By header.",
                evidence=_ev(powered),
            )
        )
    return out


def _cookie_attrs(raw: str) -> tuple[str, dict[str, str]]:
    name = raw.split("=", 1)[0].strip()
    attrs = {}
    for part in raw.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        attrs[key.lower()] = value.strip().lower()
    return name, attrs


def check_cookies(headers: Headers, https: bool) -> list[Finding]:
    out = []
    for raw in headers.get("set-cookie", []):
        name, attrs = _cookie_attrs(raw)
        evidence = f"cookie {name!r}"  # never echo cookie values
        if https and "secure" not in attrs:
            out.append(
                Finding(
                    id="cookie.no_secure",
                    severity="medium",
                    title=f"Cookie {name} lacks Secure",
                    explanation="The cookie can be sent over plain HTTP and intercepted.",
                    recommendation="Add the Secure attribute.",
                    evidence=evidence,
                )
            )
        if "httponly" not in attrs:
            out.append(
                Finding(
                    id="cookie.no_httponly",
                    severity="low",
                    title=f"Cookie {name} lacks HttpOnly",
                    explanation="Scripts can read the cookie, so an XSS bug could steal it. Fine only if JavaScript must read it.",
                    recommendation="Add HttpOnly to session and authentication cookies.",
                    evidence=evidence,
                )
            )
        samesite = attrs.get("samesite")
        if samesite is None:
            out.append(
                Finding(
                    id="cookie.no_samesite",
                    severity="low",
                    title=f"Cookie {name} has no SameSite",
                    explanation="Browsers apply defaults that vary; explicit SameSite limits cross-site request forgery.",
                    recommendation="Add SameSite=Lax (or Strict).",
                    evidence=evidence,
                )
            )
        elif samesite == "none" and "secure" not in attrs:
            out.append(
                Finding(
                    id="cookie.samesite_none_insecure",
                    severity="medium",
                    title=f"Cookie {name} is SameSite=None without Secure",
                    explanation="Browsers reject or downgrade such cookies, and they travel with every cross-site request.",
                    recommendation="Add Secure, or use SameSite=Lax.",
                    evidence=evidence,
                )
            )
    return out


_TLS_TEXT = {
    "expired": ("The certificate has expired", "Renew the certificate; enable automatic renewal."),
    "not_yet_valid": ("The certificate is not valid yet", "Check the server clock and the certificate's start date."),
    "hostname_mismatch": (
        "The certificate does not match this hostname",
        "Issue a certificate that lists this exact hostname.",
    ),
    "untrusted": ("The certificate is not trusted", "Use a certificate from a public CA and serve the full chain."),
    "outdated_protocol": ("The server only offers TLS older than 1.2", "Enable TLS 1.2 and 1.3; disable TLS 1.0/1.1."),
    "handshake_failed": ("The TLS handshake failed", "Check the server's TLS configuration."),
}


def check_tls(tls: TlsInfo) -> list[Finding]:
    if tls.status == "not_https":
        return []
    if tls.status != "ok":
        title, fix = _TLS_TEXT[tls.status]
        return [
            Finding(
                id=f"tls.{tls.status}",
                severity="high",
                title=title,
                explanation="Browsers show a security warning, and users who click through can be intercepted.",
                recommendation=fix,
                evidence=_ev(tls.detail) if tls.detail else None,
            )
        ]
    if tls.days_remaining is not None and tls.days_remaining < CERT_EXPIRY_WARN_DAYS:
        return [
            Finding(
                id="tls.expiring_soon",
                severity="medium",
                title=f"Certificate expires in {tls.days_remaining} days",
                explanation="An expired certificate makes the site unreachable for most users.",
                recommendation="Renew now and automate renewal.",
                evidence=tls.not_after,
            )
        ]
    return []


def evaluate(headers: Headers, final_scheme: str, tls: TlsInfo) -> list[Finding]:
    https = final_scheme == "https"
    return (
        check_https(final_scheme)
        + check_tls(tls)
        + check_hsts(headers, https)
        + check_cookies(headers, https)
        + check_csp(headers)
        + check_framing(headers)
        + check_simple_headers(headers)
        + check_disclosure(headers)
    )
