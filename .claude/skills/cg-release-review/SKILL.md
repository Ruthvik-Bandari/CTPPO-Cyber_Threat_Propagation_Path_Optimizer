---
name: cg-release-review
description: Assess release gates and reproducibility for a prototype, research release or pilot label - fresh setup, demo evidence, frozen benchmark report, model and dataset cards, security review, SBOM and contribution statement. Explicit invocation only. Do not use during normal development, and do not use it to raise a release label beyond what evidence supports.
disable-model-invocation: true
---

# Release gate review

Plan refs: sections 1 (release labels), 13 (research gates), 17 (CI, definition of done), 24 (release evidence, risks, claim discipline), 3 (attribution).

## Expected inputs

- Proposed release label: prototype, research release or pilot.
- Git tag or SHA, CI run results, evidence bundle IDs, report and card paths.

## Steps

1. Check the label definition: prototype = demonstrated on controlled fixtures; research release = frozen evaluation plus documented limitations; pilot = supervised use by named testers in an authorized environment.
2. Verify a fresh-environment setup guide exists and lists pinned versions and exact commands.
3. Verify the three demonstrations (mapping drift, noise, missing telemetry abstention) have healthy reference, impaired original, proposed change and unseen test fixtures.
4. For research release: frozen benchmark report with all baselines, denominators, grouped splits, intervals and failed runs.
5. Check model card, dataset card, licenses, security review, documented unsupported behavior, SBOM, lockfiles, image digests, secret scan, migration review.
6. Confirm the contribution statement credits upstream CyberGuard (commit 9d00c744...) and separates Ruthvik's work.
7. Scan README and release notes for prohibited claims: fixes all Sigma rules, eliminates false positives, detects unknown attacks, production certified.

## Output evidence

- Gate checklist with pass / fail / missing and the evidence path for each item; recommended label.

## Failure conditions (stop and report)

- Any gate lacks evidence: the label is not granted.
- Claims exceed measured results.
- Locked test data or credentials appear in the release bundle.
