# Website check

The website check grades how well a site protects its visitors at the connection and browser level: HTTPS, the TLS certificate, security headers and cookie flags. Use it on a site you own or are authorized to assess, after a deploy or a hosting change, or to get a concrete fix list for a small site. It sends one GET request (following up to five redirects) and makes one TLS handshake. It does not crawl, fuzz, log in or scan ports, so it cannot find application bugs such as SQL injection.

Each problem comes with a recommendation, and the result is an A to F grade from a fixed rubric. Source files are under [`src/aegissec/webcheck/`](../../src/aegissec/webcheck/).

## Command

```bash
aegis-sec webcheck scan https://your-site.example
aegis-sec webcheck scan http://192.168.1.20:8080 --allow-private   # a lab host you own
aegis-sec webcheck scan https://your-site.example --json
```

| Option | Effect |
| --- | --- |
| `--allow-private` | Allows targets that resolve to private, loopback, link-local or other non-public addresses. Off by default. |
| `--json` | Prints the full report as JSON and skips the notice line. |

| Exit code | Meaning ([`cli.py`](../../src/aegissec/webcheck/cli.py)) |
| --- | --- |
| 0 | The check completed. A poor grade still exits 0. |
| 2 | The URL or target was rejected: `invalid_url` or `target_not_allowed`. |
| 3 | The target could not be reached: `target_unreachable` or `upstream_error`. |

The text output starts with the notice "Only check websites you own or are authorized to assess", then prints the final URL, grade, score, TLS status and each finding with its fix.

## What the check sends

The fetch logic is in [`fetch.py`](../../src/aegissec/webcheck/fetch.py).

- **Target validation.** Every hop, including each redirect, passes [`core/netguard.py`](../../src/aegissec/core/netguard.py):
  - only `http` and `https` URLs with a host, at most 2,048 characters, with no credentials in the URL;
  - every resolved address must be public unless `--allow-private` is set. This refuses private, loopback, link-local (which includes cloud metadata at 169.254.169.254), multicast and reserved ranges, including IPv4 addresses embedded in IPv6 forms.
- **Connect to the validated IP.** The request goes to the first validated address in sorted order. The `Host` header and TLS SNI carry the real hostname, so a DNS answer that changes between the check and the connection cannot redirect the request.
- **One GET per hop.** The request has `User-Agent: aegis-sec-webcheck/<version>`, no proxy settings from the environment, and certificate verification on. At most 1 MiB of each response body is read, and the body is discarded.
- **Redirects.** Up to 5 redirects (301, 302, 303, 307, 308) are followed. More than that fails with `upstream_error`.
- **Time limit.** 10 seconds for the whole redirect chain, and 10 seconds for the TLS probe.
- **TLS probe.** When the final URL is `https`, one more verified handshake is made against the same validated IP. It records the protocol version, issuer, expiry date and days remaining.

If the HTTPS connection fails during the TLS handshake, the report still comes back with `status_code: null` and `headers_checked: false`, and only the HTTPS and TLS checks are applied.

## Grading rubric

The rubric is in [`grade.py`](../../src/aegissec/webcheck/grade.py):

1. Start at 100.
2. Subtract 25 per `high`, 10 per `medium` and 4 per `low` finding. `info` findings cost nothing. The score does not go below 0.
3. Map the score to a letter: A at 90 or above, B at 80, C at 70, D at 60, otherwise F.
4. Force the grade to F when the final URL is not HTTPS or the TLS status is not `ok`, whatever the score. Every other protection depends on an intact connection.

The rubric is a summary for prioritizing fixes. It is not a compliance rating.

## Findings

Every finding has `id`, `severity`, `title`, `explanation`, `recommendation` and, where useful, `evidence` (header values cut to 200 characters). Cookie findings name the cookie but never echo its value. The checks are in [`checks.py`](../../src/aegissec/webcheck/checks.py).

### HTTPS and TLS

| `id` | Severity | Raised when |
| --- | --- | --- |
| `https.not_used` | high | The final URL is plain HTTP. |
| `tls.expired` | high | The certificate has expired. |
| `tls.not_yet_valid` | high | The certificate's start date is in the future. |
| `tls.hostname_mismatch` | high | The certificate does not list this hostname. |
| `tls.untrusted` | high | The certificate chain is not trusted, for example self-signed or incomplete. |
| `tls.outdated_protocol` | high | The server offers only TLS older than 1.2. |
| `tls.handshake_failed` | high | The TLS handshake failed for another reason. |
| `tls.expiring_soon` | medium | The certificate expires in fewer than 14 days. |

### Headers

| `id` | Severity | Raised when |
| --- | --- | --- |
| `hsts.missing` | medium | HTTPS response without `Strict-Transport-Security`. |
| `hsts.short_max_age` | low | HSTS `max-age` is missing or under 15,552,000 seconds (180 days). |
| `hsts.no_subdomains` | info | HSTS lacks `includeSubDomains`. |
| `csp.missing` | medium | No `Content-Security-Policy`. |
| `csp.unsafe_inline` | low | `script-src` (or `default-src` when there is no `script-src`) allows `'unsafe-inline'`. |
| `csp.unsafe_eval` | low | The same directive allows `'unsafe-eval'`. |
| `csp.wildcard_source` | low | The same directive allows `*`, `http:`, `https:` or `data:`. |
| `framing.unprotected` | medium | Neither `X-Frame-Options: DENY` or `SAMEORIGIN`, nor a CSP `frame-ancestors` directive. |
| `xcto.missing` | low | `X-Content-Type-Options` is not `nosniff`. |
| `referrer.weak` | low | `Referrer-Policy` is missing, `unsafe-url` or `no-referrer-when-downgrade`. |
| `permissions_policy.missing` | info | No `Permissions-Policy`. |
| `coop.missing` | info | No `Cross-Origin-Opener-Policy`. |

The HSTS checks run only for HTTPS responses.

### Information disclosure

| `id` | Severity | Raised when |
| --- | --- | --- |
| `disclosure.server_version` | low | The `Server` header contains a version number such as `nginx/1.25.3`. |
| `disclosure.powered_by` | low | An `X-Powered-By` header is present. |

### Cookies

These checks run on every `Set-Cookie` header of the final response.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `cookie.no_secure` | medium | HTTPS site and the cookie lacks `Secure`. |
| `cookie.no_httponly` | low | The cookie lacks `HttpOnly`. This is acceptable only when JavaScript must read the cookie. |
| `cookie.no_samesite` | low | The cookie has no `SameSite` attribute. |
| `cookie.samesite_none_insecure` | medium | `SameSite=None` without `Secure`. |

## Report fields

| Field | Content |
| --- | --- |
| `notice` | The authorization notice. |
| `requested_url`, `final_url` | The URL you gave, and the URL after redirects. |
| `status_code` | HTTP status of the final response, or `null` when the handshake failed. |
| `headers_checked` | Whether header and cookie checks ran. |
| `redirect_chain` | One entry per hop: `url`, `address` (the IP connected to), `status_code`, `elapsed_ms`. |
| `tls` | `host`, `status`, `detail`, `protocol`, `issuer`, `not_after`, `days_remaining`. `status` is `ok`, `not_https`, `expired`, `not_yet_valid`, `hostname_mismatch`, `untrusted`, `outdated_protocol` or `handshake_failed`. |
| `grade`, `score` | The letter and the 0 to 100 score. |
| `findings` | Sorted high, medium, low, info. |
| `timings` | `total_ms`, `http_ms`, `tls_ms`. |

## Limits

- One response is checked. Headers set only on other pages, or only for logged-in users, are not seen.
- TLS is checked once, with httpx's default verified client context. The check does not enumerate cipher suites or every protocol version the server accepts.
- Only the first resolved address is contacted. Sites behind several addresses or a CDN may answer differently elsewhere.
- `--allow-private` removes the address protections for that run. Use it only for hosts you control.
