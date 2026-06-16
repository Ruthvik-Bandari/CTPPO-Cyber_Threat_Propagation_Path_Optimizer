# Phase 6 — SIEM / EDR / ticketing hooks (G2)

**Phase 6 (realtime product UX), deliverable 3.** Roadmap: `05_OSS_REALTIME_PLAN.md` §Phase-6.
**Status: DONE (2026-06-15).** Sources: `integrations/exporters.py`, `api/server_secure.py`
(`/api/integrations/export`).

## What this delivers

CTPPO produces a recommended choke-point fix and the Pareto attack-path front. G2 formats those
findings into the **standard schemas a SOC already ingests**, so a CTPPO run can feed an existing
pipeline:

- **SIEM** — Elastic Common Schema (ECS) JSON events (one per Pareto path; `event.module=ctppo`,
  `event.dataset=ctppo.attack_path`, severity derived from reachability, full path + objectives +
  reachability band + recommended fix under `ctppo.*`) and a **CEF** line for legacy collectors.
- **Ticketing** — a generic remediation ticket (`summary` / `description` / `priority` / `labels` /
  `fields`) that maps onto Jira or ServiceNow issue fields; the description lists each Pareto path
  with its reachability range and names the recommended choke-point fix + the reachability it removes.
- **Delivery** — `dispatch_webhook(payload, url)` POSTs the payload to a configured endpoint.
- **API** — `POST /api/integrations/export` (`format = ecs | cef | ticket`, optional `webhook_url`)
  analyzes the network, computes the choke-point fix (`pareto_critical_vulns`) and its reachability
  reduction (via the D4 `whatif_front`), formats it, and optionally dispatches.

## Honest scope (important)

This **formats** findings and **optionally POSTs** them. It does **not** ship a real authenticated
Splunk / Elastic / Jira / CrowdStrike integration — that needs the operator's endpoint and
credentials, a genuine external dependency (the same discipline as the LLM reviewer needing an API
key). With no `webhook_url`, `dispatch_webhook` returns `delivered=False` with the payload rather
than pretending to deliver. EDR is **ingest-only**: an EDR/SIEM forwarder picks up the ECS event;
we do not call a vendor EDR API. The schemas are standards-compliant (ECS field names; CEF header
with literal structural pipes, only field *values* escaped) so a real connector is a config step,
not new code.

## Measured (tests)

- `tests/integrations/test_exporters.py` (6) — ECS event shape + severity mapping; **CEF header has
  the correct 6 literal structural pipes, unescaped** (a spec bug caught and fixed: the first
  rendering escaped the structural pipes); ticket fields; webhook honest no-op without a URL; webhook
  delivery with an injected client (status 202, exact payload).
- `tests/integrations/test_export_api.py` (3) — `/api/integrations/export` returns ECS events with
  `delivered=False` (no URL), a ticket payload for `format=ticket`, and HTTP 400 for a bad format.

## Files

`integrations/exporters.py` (`to_ecs_events`, `to_cef`, `to_ticket`, `dispatch_webhook`),
`api/server_secure.py` (`/api/integrations/export`, `IntegrationExportRequest`),
`tests/integrations/` (9 tests). **Completes the Phase-6 integration hooks** (G4 SOC2/compliance
remains retired by the OSS decision).
