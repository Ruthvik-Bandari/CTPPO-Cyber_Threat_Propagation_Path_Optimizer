# LLM Code-Review Integration Spec

**Status:** Draft for review · **Date:** 2026-06-13

Adds a **Claude-based code security reviewer** to CTPPO, modeled on Claude Code's
`/security-review`. Implemented in [`scanners/llm_code_review.py`](../../scanners/llm_code_review.py).

> **Important framing correction.** "Claude Code security" is **Claude (a frozen LLM)
> prompted** to find vulnerabilities — *not* a model you train. So "train the model as if
> Claude Code security works" decomposes into two distinct, composable pieces below. We do
> both; neither one "trains Claude."

---

## 1. Two roles

### Role A — Scan-time reviewer (find vulns from code)
Claude reads source files and returns structured findings (injection, authz, secrets,
SSRF, path traversal, weak crypto, …) that signature scanners (nmap/ZAP/CVE matching)
cannot find. Each finding becomes a `VulnerabilityFinding` and flows into the attack graph
exactly like any other scanner's output → contributes nodes/edges → costed by the cost
model → considered by NAMOA*.

### Role B — Teacher for distillation (the honest version of "train the model")
Claude's findings are a **weak-supervision label source**: run the reviewer over many
repos to produce `(code → vulnerability)` labels, then train CTPPO's own cheaper model
(classifier / GNN feature) to approximate it (LLM-as-teacher → CTPPO student). This is the
only sense in which we "train as if Claude Code security works."

> **Honesty caveat (must hold in any paper):** LLM-generated labels are **noisy** — they
> hallucinate and miss. They are bootstrap/eval signal, **not** unquestioned ground truth.
> A distillation result must report agreement vs. a human-verified subset, never claim the
> LLM labels *are* truth.

---

## 2. Scan-time design (implemented)

- **SDK / model:** official `anthropic` SDK; default model `claude-opus-4-8` (strong at
  bug-finding). API key from `ANTHROPIC_API_KEY` (env) via bare `Anthropic()` — never hardcoded.
- **Structured output:** `output_config.format` with a strict JSON schema (`FINDINGS_SCHEMA`)
  — `{findings: [{title, severity, cwe, line, description, recommendation, confidence}]}`.
  (Prefill is removed on Opus 4.8, so structured outputs is the right mechanism.)
- **Thinking:** adaptive (`{"type": "adaptive"}`) — security review is non-trivial.
- **Mapping:** `findings_from_payload()` (pure, unit-tested) → `VulnerabilityFinding` with
  `scanner=ScannerType.LLM`, CWE ids, OWASP category, MITRE techniques, evidence
  `file:line`, and provenance in `metadata` (`source`, `model`, `llm_confidence`).
- **Graceful degradation:** if the SDK or key is absent, `review_*` returns `[]` and logs a
  warning. **It never fabricates findings** (honesty rule).
- **Prompt discipline:** the system prompt forbids invented issues, allows an empty list for
  clean code, and requires honest `confidence` — this is what keeps precision usable.

### Data flow
```
repo files ─► LLMCodeReviewer.review_paths() ─► [VulnerabilityFinding] ─┐
                                                                        ├─► AttackGraph
nmap / ZAP / CVE-match findings ────────────────────────────────────────┘   (cost_model → NAMOA*)
```

## 3. Distillation plan (Role B — later phase)
1. Run the reviewer across a corpus of repos → `(file, findings)` dataset.
2. Hold out a **human-verified** subset for evaluation (label-quality ceiling).
3. Train CTPPO's student model (e.g. a CWE/severity classifier, or a GNN node feature
   "is-this-code-likely-vulnerable") on the LLM labels.
4. **Report:** student-vs-teacher agreement, and student-vs-human on the verified subset.
   Distillation only "works" if the student approximates the teacher *and* the teacher is
   decent against humans — both measured, neither assumed.

## 4. Where it sits in the plan
- Role A (scan-time) — usable now; wire into `scanners/unified_scanner.py` and the repo-scan
  path of the product CLI (Part IV of the vision: SSH + Git + model-assisted repo scan).
- Role B (distillation) — a research sub-thread alongside Phase 3 (the GNN); gated on the
  same honesty/eval rigor as everything else.

## 5. Safety / authorization
Reviewing source code for vulnerabilities is **authorized defensive** use (your own /
permitted repos). The tool finds and explains weaknesses so they can be fixed — it does not
generate exploits.
