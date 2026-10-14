# Claude Code session workflow

Plan refs: sections 17 (definition of done), 19 (task sizing), 22.

## One slice per implementation session

A session implements one reviewable slice of one backlog ticket. It does not build the
platform, span tickets, or touch paths outside the slice plan.

Canonical sequence (example for CG005):

```text
/cg-repo-audit
/cg-plan-slice CG005 safe Sigma parser
/cg-sigma-adapter CG005 supported subset
/cg-security-review changed parser and upload paths
/cg-documentation CG005 support matrix
```

1. Start in plan mode (`claude --permission-mode plan`). Read `CLAUDE.md`, `docs/handoff.md`
   and the relevant plan sections.
2. Run `/cg-repo-audit` when the checkout is new or upstream changed; otherwise skim the handoff.
3. Run `/cg-plan-slice <ticket> <goal>`. Agree changed paths, contracts, failure states,
   tests and commands before editing.
4. Switch to the permission mode appropriate for normal development and implement only
   the agreed slice using the task skill (e.g. `/cg-sigma-adapter`).
5. Run the actual commands from real files. Do not assume a Makefile target exists.
6. Run `/cg-security-review` on changed input boundaries, routes or connectors.
   Optionally pass the gathered evidence to a read-only reviewer agent
   (`architecture-reviewer`, `detection-semantics-reviewer`, `ml-evaluation-reviewer`,
   `appsec-reviewer`). Reviewers cannot run code; the main session supplies output.
7. Run `/cg-documentation` to update the support matrix, docs and handoff.
8. Review the diff and command output yourself, then commit the verified change in the fork.

`/cg-model-training`, `/cg-evaluate` and `/cg-release-review` load only when invoked
explicitly by name.

Sequential development is the default. If parallel agents are used later, give each
separate files or a separate worktree and name one integration owner.

## Session handoff procedure

Before ending a session, update `docs/handoff.md`:

- Current git SHA (`git rev-parse HEAD`) and whether the tree is clean.
- Completed ticket or slice, and anything left partially done.
- Commands actually run, with pass/fail. Commands not run are listed as not run.
- Failed or skipped checks and why (e.g. Elasticsearch container unavailable).
- Artifact IDs and hashes produced (dataset versions, validation runs, evidence bundles).
- The single next action.

Keep detailed history in git; keep `CLAUDE.md` short. A new session begins by reading
the handoff and the current backlog.

## After editing the Claude setup

Run `/cg-skill-audit`, `python3 scripts/check_claude_pack.py` and
`python3 .claude/hooks/test_protect_paths.py`. Review permission changes like code.
