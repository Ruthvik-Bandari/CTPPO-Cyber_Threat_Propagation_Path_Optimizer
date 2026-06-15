# 3c — LIVE container/VM testbed (the centerpiece)

**Phase 3 (Realtime ingestion), source 3 of 3 — the centerpiece.** Roadmap:
`05_OSS_REALTIME_PLAN.md` §Phase-3c. **Status: DONE (2026-06-15).** Run on a **real, running**
Docker testbed — not a synthetic graph.

## What this delivers

The full realtime loop end-to-end on live services, closing it against ground truth:

```
docker-compose vulnerable services → LIVE nmap -sV scan → 3b import + version→CVE
  → canonical AttackGraph (data-grounded EPSS/KEV) → NAMOA* → predicted Pareto path
  → compare vs the GROUND-TRUTH exploitable path  (recall + soundness)
```

This is the critique's **A1** "live testbed as centerpiece, not a footnote." It exercises the
3a feeds (EPSS/KEV grounding) and the 3b scanner-import path on a target whose true attack path
is **known and live-verified**.

## The testbed (`evaluation/live_testbed/docker-compose.yml`)

Two official, version-pinned Apache images with real, **KEV-listed** CVEs, on a segmented
Docker network:

| Host | Image | CVE | CVSS | Role | Port |
|---|---|---|---:|---|---|
| `web` | `httpd:2.4.49` | **CVE-2021-41773** | 7.5 | internet-facing entry (`edge` zone) | 18080 |
| `app` | `httpd:2.4.50` | **CVE-2021-42013** | 9.8 | goal / crown jewel (`internal` zone) | 18081 |

Ground-truth attack path: **Internet → web → app(goal)**. The container `command` flips the
stock `Require all denied` on the filesystem root to `Require all granted`, the documented
misconfiguration that makes the path-traversal CVEs live-exploitable.

## Ground truth, anchored two ways (honesty)

1. **By construction** — pinned versions ⇒ known CVEs; the segmentation is what we built, so the
   true path is known. (Unlike 3b, the topology here is *known*, not an inferred heuristic.)
2. **By live exploitation** — each CVE is *actually exploited* with a safe, non-destructive
   path-traversal PoC that reads `/etc/passwd`. The vulns are verified poppable, not merely
   version-fingerprinted.

## Measured — a real live run (2026-06-15)

`python evaluation/live_testbed.py` (Docker daemon up, `nmap` 7.94):

| Step | Result (real) |
|---|---|
| **Live nmap -sV** | `Apache httpd 2.4.49` (:18080), `Apache httpd 2.4.50` (:18081) — genuine fingerprints |
| **version → CVE** | 2.4.49 → CVE-2021-41773 · 2.4.50 → CVE-2021-42013 |
| **EPSS grounding** (3a feed) | CVE-2021-41773 = **0.99992** · CVE-2021-42013 = **0.99964** |
| **KEV** | both **True** |
| **Live exploit PoC** | **both CVEs exploited** — HTTP 200 leaking `root:x:0:0:root:/root:/bin/bash` |
| **Graph** | 8 nodes / 7 edges, 1 Pareto path |
| **Predicted Pareto path** | Internet → web → app(goal) |
| **Recall** | **1.00** — the predicted path == the ground-truth exploitable path |
| **Soundness** | **1.00** — the returned path reaches the goal using only real, scanned hosts |

**The engine's predicted optimal path is exactly the path that is actually exploitable on the
live testbed**, and both hops are verified poppable. That is the 3c exit criterion met on real
infrastructure: each source yields a valid end-to-end graph; the testbed path is recovered
(recall) and sound.

## How to run

```bash
# live (needs Docker + nmap): bring up, scan, exploit-verify, build, search, evaluate, tear down
python evaluation/live_testbed.py
python evaluation/live_testbed.py --keep-up      # leave containers running
python evaluation/live_testbed.py --no-exploit   # skip the PoC (scan + recovery only)

# offline pipeline on the captured scan (no Docker, used by the test suite)
python evaluation/live_testbed.py --offline
```

The live run refreshes `evaluation/live_testbed/sample_scan.xml` from the real scan; the offline
mode and `tests/scanners/test_live_testbed.py` replay it so the pipeline is validated in CI
without Docker.

## Honest scope / limits

- **2 hosts, 2 CVEs.** The testbed proves the loop end-to-end on real, live-exploited services;
  it is small by design (fast, reproducible, bounded image pulls). Scaling to more hosts/CVEs is
  the same compose + version→CVE pattern.
- **version→CVE is an explicit table**, not a CVE-emitting scan. `nmap -sV` reports the service
  *version*; we map that pinned version to its known CVE (documented in `live_testbed.py`).
  vulners-style scans (3b) or a CVE-aware scanner would supply CVEs directly.
- **Lateral exploitation is by-construction, entry is live-verified.** Both CVEs are individually
  exploited (LFI); the *pivot* web→app is the known segmentation, not a popped reverse shell.
  Full red-team chaining (e.g. Metasploit pivoting) is the further gold standard, noted not run.
- **Published ports** let the host scanner fingerprint the internal host (an authenticated/internal
  scan); the topology fed to the graph is the true segmentation.
- This validates path **recovery + soundness on live infra**; it is not a base-rate study (that is
  Phase-4 / A2).

## Files

`evaluation/live_testbed/docker-compose.yml`, `evaluation/live_testbed/sample_scan.xml` (captured
real scan), `evaluation/live_testbed.py` (driver: `run_live`, `run_offline`, `verify_exploit`,
`enrich_findings`, `build_testbed_graph`, `evaluate`), `tests/scanners/test_live_testbed.py`
(5 offline tests). Reuses the 3b `parse_nmap` parser (extended to capture service product/version)
and 3a EPSS/KEV grounding. **This completes Phase 3 (realtime ingestion: 3a feeds · 3b scanner
import · 3c live testbed).**
