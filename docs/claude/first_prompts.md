# First prompts

From plan section 23. Paste into Claude Code as written; adjust ticket IDs as the backlog moves.

## First prompt for Claude Code

> Read CLAUDE.md, docs/CyberGuard_Engineering_Plan.md and docs/handoff.md. Use /cg-repo-audit to inspect this checkout and confirm the upstream baseline. Inventory working commands, dependency locks, current authorization tests, evidence storage and migrations. Write findings and a plan for CG001 through CG003. Do not implement later tickets yet. Record facts separately from assumptions and do not access raw or private data.

## First implementation prompt

> Use /cg-plan-slice and /cg-sigma-adapter for CG005. Implement a safe parser for only the documented single event subset. Preserve rule and pipeline hashes, reject unsupported operators and expose explicit reason codes. Use synthetic fixtures including missing fields and hostile YAML. Run relevant tests and update the support matrix and handoff. Explain what is implemented and which commands actually passed.

## ML experiment prompt

> Use /cg-model-training for M1 after CG012. Audit grouped split hashes and licensing, then prepare a small SFT pilot with pinned model revision and measured memory. Read training and development data only. Do not launch a scheduled GPU job until this session explicitly requests submission. Compare the pilot to B2 using the same context and candidate budget; report failed runs and abstentions.

## Skill verification prompt

> Run /cg-skill-audit. Execute python3 scripts/check_claude_pack.py and python3 .claude/hooks/test_protect_paths.py and paste the real output. Walk the cases in docs/claude/skill_validation_cases.md for any skill changed in this diff and report which were checked in a live session and which were not.
