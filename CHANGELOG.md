# Changelog

All notable changes to Aegis-Sec are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version may change commands, report fields or API routes; each such change is listed here.

## [Unreleased]

### Fixed

- Real SigmaHQ rules are accepted again. Their unquoted `date:` and `modified:` values resolve as YAML timestamps, which the strict loader refused, so every rule failed with `yaml_tag_not_allowed`. Timestamps now load as their literal text. Other non-plain tags, such as `!!binary`, are still refused.

### Added

- `aegisbench`, a research package that is not shipped in the wheel:
  - fetches SigmaHQ, OTRF Security-Datasets and Atomic Red Team at their pinned commits;
  - records license and per-file SHA-256 manifests;
  - writes aggregate-only QC reports.
- Slurm and transfer-node scripts for the Explorer cluster (`hpc/`), the HPC runbook (`docs/hpc.md`), and the data source license record, data and model guardrails policy, and compliance checklist (`docs/data/`).

## [0.1.0] - 2026-10-14

First release of Aegis-Sec as one installable package, `aegis-sec-ai`, with the `aegis-sec` CLI and a local dashboard. See [ADR 0001](docs/adr/0001-platform-direction.md) for the platform decision.

### Added

- **Detection repair** (`aegis-sec detect`), the deterministic B0 baseline from the [engineering plan](docs/CyberGuard_Engineering_Plan.md):
  - parser for a bounded single-event Sigma subset (Windows `process_creation`, exact/`contains`/`startswith`/`endswith`, value lists, `and`/`or`/`not`), with a reason code for every rejection;
  - environment field mappings and conversion with the pySigma Lucene backend;
  - replay on Elasticsearch 8.19.3 pinned by image digest, with a disposable index per run, count verification and full pagination;
  - diagnosis of mapping drift, missing telemetry, noise and logic faults;
  - bounded repair candidates (at most 3 AST edits and 4 candidates), development screening, frozen selection, and validation on independent held-out fixtures;
  - outcomes `repaired`, `unchanged`, `abstained`, `insufficient_evidence`, `unsupported` and `engine_unavailable`, with stable exit codes;
  - content-addressed JSON evidence (`--evidence-dir`);
  - 11 synthetic demonstration cases (`detect cases`, `detect demo`) and `engine-up` / `engine-status` helpers.
- **File and URL forensics** (`aegis-sec forensics`), adapted from CyberSafeX Detection Suite:
  - streaming MD5, SHA-1, SHA-256 and SHA-512;
  - whole-file and per-block entropy, and a byte histogram;
  - magic-byte format detection with extension-mismatch, double-extension and bidirectional-control findings;
  - EXIF and GPS privacy findings through the optional `[exif]` extra;
  - offline URL phishing heuristics.
- **Website check** (`aegis-sec webcheck scan`): one guarded GET plus one TLS handshake, checks for HTTPS, TLS, headers, information disclosure and cookies, and an A to F grade from a fixed rubric.
- **Bitcoin quantum risk** (`aegis-sec bitcoin`), adapted from BitShield (MIT Bitcoin Expo 2026, Team ACE):
  - Base58Check, Bech32 and Bech32m decoding;
  - key-exposure risk per address type;
  - migration plans;
  - optional mempool.space spend-history lookups;
  - an optional intent guardian that uses your own Anthropic key (`[ai]` extra, `AEGIS_SEC_AI_MODEL`).
- **Dashboard and API** (`aegis-sec dashboard`): a FastAPI server on `127.0.0.1:8765` serving the bundled React dashboard and a JSON API described at `/api/openapi.json`. Protections:
  - `Host` allowlist;
  - cross-site write refusal;
  - per-route body caps;
  - strict security headers.
- `aegis-sec config` commands to store, clear and inspect the local Anthropic key (`0600` file).
- Documentation: module guides under `docs/modules/`, `docs/api.md`, `docs/security-model.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and `CITATION.cff`.
- CI with these jobs:
  - lint and strict types;
  - unit tests on Python 3.12 and 3.13;
  - engine tests against the pinned Elasticsearch;
  - dashboard lint, test and build;
  - a wheel smoke test.

### Removed

- The CTPPO attack-path prototype that previously lived in this repository. It remains in git history.

[Unreleased]: https://github.com/Ruthvik-Bandari/CTPPO-Cyber_Threat_Propagation_Path_Optimizer/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Ruthvik-Bandari/CTPPO-Cyber_Threat_Propagation_Path_Optimizer/releases/tag/v0.1.0
