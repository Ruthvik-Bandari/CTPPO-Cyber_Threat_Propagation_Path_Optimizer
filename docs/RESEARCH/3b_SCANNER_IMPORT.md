# 3b — Scanner import: Nessus / Qualys / OpenVAS / nmap → attack graph

**Phase 3 (Realtime ingestion), source 2 of 3.** Roadmap: `05_OSS_REALTIME_PLAN.md` §Phase-3b.
**Status: DONE (2026-06-15).** Measured end-to-end on schema-accurate fixtures with real CVEs.

## What this delivers

An adapter that imports the **output files** of the vulnerability scanners orgs already run
and turns them into the canonical `core.network_builder` `NetworkSpec` → `build_network` →
`AttackGraph` → NAMOA\*. This is the realistic enterprise / CI-CD ingestion path — you don't
re-run a scan, you import the artifact — and it closes the critique's **G1** repo-scan→graph gap.

| Format | File | Source of CVEs |
|---|---|---|
| **nmap** | `-oX` XML | NSE `vulners`/`vuln` script output (recon alone has no CVEs) |
| **Nessus** | `.nessus` (NessusClientData_v2) | `<ReportItem>/<cve>` + `cvss3_vector`/`cvss3_base_score` |
| **Qualys** | VM scan `<SCAN>` XML | `<VULN>/<CVE_ID_LIST>` + `CVSS3_BASE`; port from `<CAT>` |
| **OpenVAS/GVM** | report XML | `<result>/<nvt>/<refs>/<ref type="cve">` + `cvss_base` |

Pure stdlib XML parsing (namespace-tolerant), no scanner binary, no network → fully
reproducible and offline-testable. Format is auto-detected (`detect_format`); each parser
returns a common `ScanFinding` IR `(host_ip, hostname, cve_ids, cvss_score, cvss_vector,
port, service, severity)`.

## Data-grounded vs inferred (the honest core)

Scanners report **per-host findings, not network structure.** So:

- **Data-grounded (from the scan):** which hosts exist, and which CVEs each host has. CVSS
  comes from the scan when present (else enriched from the local NVD cache, 3a); **EPSS/KEV are
  looked up by CVE id** at `build_network` time via the real cost model.
- **INFERRED & flagged (NOT in any scan file):** host-to-host **reachability/topology**, network
  **zones** (per /24 subnet), which host is **internet-facing** (heuristic: open 80/443/8080/8443/22),
  and which host is the **goal** (heuristic: highest CVSS). These are documented heuristics, can be
  overridden with ground truth (`reachability_edges=`, `internet_facing=`, `goal=`), and are exactly
  the same bounded-heuristic situation as the lateral-movement prior (B3): the data-grounded vuln
  edges dominate the ranking; the inferred topology moves magnitude, not usually the decision.

Reachability policies: **`subnet`** (default — same-/24 mesh + internet-facing hosts bridge
across subnets), **`full_mesh`**, or an explicit ground-truth edge list. The API response and CLI
both flag `topology_inferred`.

## Measured — all four formats, end-to-end (2026-06-15)

Each fixture is a 2-host network (web entry → higher-CVSS goal on another subnet) using **real,
well-known KEV CVEs** so the grounding is real. Built with the 3a-refreshed EPSS/KEV cache:

| Format | detect | hosts | vulns | EPSS-grounded | KEV | CVSS vector | nodes/edges | Pareto path |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|---|
| nmap | ✅ | 2 | 2 | **2/2** | 2/2 | 0/2 | 8 / 7 | web01 → app01 (Log4Shell goal) |
| Nessus | ✅ | 2 | 2 | **2/2** | 2/2 | **2/2** | 8 / 7 | web01 → files01 (SMBGhost goal) |
| Qualys | ✅ | 2 | 2 | **2/2** | 2/2 | 0/2 | 8 / 7 | web01 → db01 (Log4Shell goal) |
| OpenVAS | ✅ | 2 | 2 | **2/2** | 2/2 | 0/2 | 8 / 7 | web01 → dc01 (BlueKeep goal) |

Every format yields a **valid end-to-end graph with a real attacker→goal Pareto path** — the
3b exit criterion. NAMOA\* returns 1 Pareto path per fixture (e.g. Nessus: `time=10.87
success=0.240 impact=5.00`).

**Key honest finding — what gets grounded:**

- **Success objective is grounded everywhere** (8/8 CVEs have real EPSS ≈ 0.99 and KEV = True),
  *even for Qualys/OpenVAS/nmap which emit no CVSS vector* — because EPSS/KEV are keyed by CVE id,
  not the vector.
- **Time/impact are fully grounded only where the scan carries a CVSS vector** (Nessus here, 2/2);
  without it the model falls back to the CVSS base score (impact) and a neutral exploitability
  (time), and records the fallback in edge metadata. Nessus also exercises **vector
  normalization** (a `AV:N/AC:L/…` vector without the `CVSS:3.1/` prefix is repaired).
- **NVD-cache enrichment (3a)** supplies a missing vector *for CVEs in the recent-changes window*.
  The famous CVEs here predate the 1-day window, so enrichment didn't fire — widen `NVD_DAYS`
  (3a) or use a fuller NVD mirror to enrich older CVEs. Demonstrated working against a controlled
  cache in the test suite.

## How to use

```bash
ctppo import-scan scan.nessus                       # auto-detect, subnet topology
ctppo import-scan report.xml --format openvas       # force a format
ctppo import-scan scan.xml --reachability full_mesh # change the inferred topology
ctppo import-scan scan.xml --no-threat-data         # CVSS-only (skip EPSS/KEV)
```

Library: `scanners.scan_import.import_scan_file(path, provider=…) -> (graph, spec, findings, fmt)`;
`parse_scan(xml)`, `findings_to_network_spec(findings, …)`. API: **`POST /api/scan/import`**
`{xml, format, reachability}` → Pareto paths + a `scan` block (`format`, `hosts`,
`vulnerabilities`, `topology_inferred`).

## Honest scope / limits

- **Topology is inferred, not scanned** (see above) — the single biggest caveat; supply ground
  truth for production. The graph is only as good as the reachability you give it.
- **nmap recon-only finds no CVEs** — needs the `vulners`/`vuln` NSE scripts; a bare port scan
  yields hosts with no exploit nodes (and therefore no attack path), which the adapter handles
  honestly (host present, 0 vulns).
- **Format coverage is the common shapes**, parsed defensively (namespace-agnostic, CVE-regex
  fallbacks); exotic vendor variants may need a tweak. CVSS vector availability varies by scanner.
- This is **ingestion**, not a new soundness claim — the engine and Phase-1/2 results are unchanged.

## Files

`scanners/scan_import.py` (parsers + `detect_format` + `findings_to_network_spec` +
`import_scan_file`), `ctppo import-scan`, `POST /api/scan/import`,
fixtures `tests/scanners/fixtures/{nmap,nessus,qualys,openvas}_*`, tests
`tests/scanners/test_scan_import.py` (+ API test) — 24 tests, offline. Next: 3c live testbed.
