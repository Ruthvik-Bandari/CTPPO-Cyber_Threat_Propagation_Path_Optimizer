import socket

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from aegissec.core.errors import Reason, Rejected
from aegissec.core.netguard import check_url
from aegissec.webcheck import checks
from aegissec.webcheck.cli import app as cli_app
from aegissec.webcheck.grade import grade
from aegissec.webcheck.models import Finding, TlsInfo
from aegissec.webcheck.scan import scan

OK_TLS = TlsInfo(host="site.test", status="ok", protocol="TLSv1.3", days_remaining=90)
GOOD = {
    "strict-transport-security": ["max-age=31536000; includeSubDomains"],
    "content-security-policy": ["default-src 'self'; frame-ancestors 'none'"],
    "x-content-type-options": ["nosniff"],
    "referrer-policy": ["strict-origin-when-cross-origin"],
    "permissions-policy": ["camera=()"],
    "cross-origin-opener-policy": ["same-origin"],
    "set-cookie": ["sid=SECRETVALUE; Secure; HttpOnly; SameSite=Lax"],
}
DNS = {"site.test": ["93.184.216.34"], "evil.test": ["10.0.0.5"], "rebind.test": ["127.0.0.1"]}


def ids(findings):
    return {f.id for f in findings}


def test_hardened_site_has_no_findings_and_grades_a():
    findings = checks.evaluate(GOOD, "https", OK_TLS)
    assert findings == []
    assert grade(findings, "https", OK_TLS) == ("A", 100)


def test_missing_headers_are_reported():
    found = ids(checks.evaluate({}, "https", OK_TLS))
    assert {"hsts.missing", "csp.missing", "framing.unprotected", "xcto.missing", "referrer.weak"} <= found


@pytest.mark.parametrize(
    ("csp", "expected"),
    [
        ("script-src 'self' 'unsafe-inline'", "csp.unsafe_inline"),
        ("default-src 'self' 'unsafe-eval'", "csp.unsafe_eval"),
        ("script-src *", "csp.wildcard_source"),
        ("default-src https:", "csp.wildcard_source"),
    ],
)
def test_weak_csp(csp, expected):
    assert expected in ids(checks.check_csp({"content-security-policy": [csp]}))


def test_hsts_edge_cases():
    assert ids(checks.check_hsts({"strict-transport-security": ["max-age=300"]}, True)) == {
        "hsts.short_max_age",
        "hsts.no_subdomains",
    }
    assert checks.check_hsts({}, https=False) == []


def test_cookie_checks_never_echo_values():
    findings = checks.check_cookies({"set-cookie": ["sid=SECRETVALUE", "pref=1; SameSite=None"]}, https=True)
    assert {"cookie.no_secure", "cookie.no_httponly", "cookie.no_samesite", "cookie.samesite_none_insecure"} <= ids(
        findings
    )
    assert all("SECRETVALUE" not in (f.evidence or "") for f in findings)


def test_disclosure_and_framing():
    found = ids(checks.check_disclosure({"server": ["nginx/1.18.0"], "x-powered-by": ["PHP/8.1"]}))
    assert found == {"disclosure.server_version", "disclosure.powered_by"}
    assert checks.check_disclosure({"server": ["cloudflare"]}) == []
    assert checks.check_framing({"x-frame-options": ["DENY"]}) == []


def test_grade_rubric_and_forced_f():
    lows = [Finding(id=f"x{i}", severity="low", title="", explanation="", recommendation="") for i in range(3)]
    assert grade(lows, "https", OK_TLS) == ("B", 88)
    assert grade([], "http", TlsInfo(host="h", status="not_https"))[0] == "F"
    assert grade([], "https", TlsInfo(host="h", status="expired"))[0] == "F"


def test_tls_findings():
    assert ids(checks.check_tls(TlsInfo(host="h", status="hostname_mismatch"))) == {"tls.hostname_mismatch"}
    assert ids(checks.check_tls(TlsInfo(host="h", status="ok", days_remaining=3))) == {"tls.expiring_soon"}


# ---------------------------------------------------------------- network layer (mocked)
@pytest.fixture
def fake_dns(monkeypatch):
    real = socket.getaddrinfo

    def fake(host, port, *args, **kwargs):
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host.strip("[]"))
            return real(host.strip("[]"), port, *args, **kwargs)
        except OSError:
            pass
        if host not in DNS:
            raise socket.gaierror(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in DNS[host]]

    monkeypatch.setattr(socket, "getaddrinfo", fake)


def ok_probe(host, ip, port, timeout):
    return TlsInfo(host=host, status="ok", protocol="TLSv1.3", days_remaining=60)


def transport(routes):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        key = (request.headers["host"], request.url.path)
        status, headers = routes[key]
        return httpx.Response(status, headers=headers, stream=httpx.ByteStream(b"x" * 10))

    return httpx.MockTransport(handler), seen


def test_scan_follows_redirect_and_pins_ip(fake_dns):
    tx, seen = transport(
        {
            ("site.test", "/"): (301, {"location": "https://site.test/home"}),
            ("site.test", "/home"): (200, {k: v[0] for k, v in GOOD.items()}),
        }
    )
    report = scan("http://site.test/", transport=tx, probe=ok_probe)
    assert report.final_url == "https://site.test/home"
    assert [h.status_code for h in report.redirect_chain] == [301, 200]
    assert all(r.url.host == "93.184.216.34" for r in seen)  # connected to the validated IP
    assert seen[1].extensions["sni_hostname"] == "site.test"
    assert report.grade == "A"


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data",
        "http://10.1.2.3/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://evil.test/",
        "http://rebind.test/",
    ],
)
def test_ssrf_targets_blocked(fake_dns, url):
    with pytest.raises(Rejected) as exc:
        scan(url, transport=transport({})[0], probe=ok_probe)
    assert exc.value.reason is Reason.TARGET_NOT_ALLOWED


def test_redirect_into_private_network_blocked(fake_dns):
    tx, _ = transport({("site.test", "/"): (302, {"location": "http://evil.test/admin"})})
    with pytest.raises(Rejected) as exc:
        scan("http://site.test/", transport=tx, probe=ok_probe)
    assert exc.value.reason is Reason.TARGET_NOT_ALLOWED


def test_redirect_loop_capped(fake_dns):
    tx, seen = transport({("site.test", "/"): (302, {"location": "/"})})
    with pytest.raises(Rejected, match="redirects"):
        scan("http://site.test/", transport=tx, probe=ok_probe)
    assert len(seen) == 6


def test_url_validation():
    for bad in ["ftp://site.test/", "http://user:pw@site.test/", "javascript:alert(1)", "http://"]:
        with pytest.raises(Rejected) as exc:
            check_url(bad)
        assert exc.value.reason is Reason.INVALID_URL


def test_private_targets_allowed_on_request(fake_dns):
    tx, _ = transport({("127.0.0.1:8080", "/"): (200, {})})
    report = scan("http://127.0.0.1:8080/", allow_private=True, transport=tx, probe=ok_probe)
    assert report.grade == "F"
    assert "https.not_used" in ids(report.findings)


def test_api_and_cli(monkeypatch):
    from aegissec.webcheck import api, cli

    monkeypatch.setattr(api, "scan", lambda url, allow_private: _fake_report())
    monkeypatch.setattr(cli, "scan", lambda url, allow_private: _fake_report())
    app = FastAPI()
    app.include_router(api.router)
    body = TestClient(app).post("/api/webcheck", json={"url": "https://site.test"}).json()
    assert body["grade"] == "A"
    assert "authorized" in body["notice"]
    result = CliRunner().invoke(cli_app, ["scan", "https://site.test"])
    assert result.exit_code == 0 and "grade A" in result.output


def _fake_report():
    from aegissec.webcheck.models import Report, Timings

    return Report(
        requested_url="https://site.test",
        final_url="https://site.test",
        status_code=200,
        headers_checked=True,
        redirect_chain=[],
        tls=OK_TLS,
        grade="A",
        score=100,
        findings=[],
        timings=Timings(total_ms=1, http_ms=1, tls_ms=0),
    )


def test_cli_rejected_exit_code(monkeypatch):
    from aegissec.webcheck import cli

    def boom(url, allow_private):
        raise Rejected(Reason.TARGET_NOT_ALLOWED, "private")

    monkeypatch.setattr(cli, "scan", boom)
    assert CliRunner().invoke(cli_app, ["scan", "http://10.0.0.1"]).exit_code == 2
