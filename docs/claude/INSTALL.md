# Installing the CyberGuard Claude Code starter pack

Plan refs: section 20 (installation sequence, configuration roles), 22 (hooks and MCP), 23.

**Provenance note:** the plan describes a companion ZIP containing this pack. That ZIP was
not available, so this pack was generated directly in this repository from the plan's
sections 16 and 20-23. It is original project content, not a copy of the ZIP. Review it
as you would any other code change.

## Steps

1. Install Claude Code from the current official setup page and verify with
   `claude --version` and `claude doctor`. Authenticate with the account or provider
   permitted for this project. Record the CLI version in `docs/handoff.md`.
2. Work in a fork or branch of the CyberGuard repository (upstream
   `tanishka-bandari/cyberguard`, baseline `9d00c744420d4681fc199f053f29b0863e31a910`).
   Because the pack was generated in-repo, there is no separate unpack step; review the
   diff for `CLAUDE.md`, `.claude/`, `docs/claude/`, `docs/handoff.md`,
   `scripts/check_claude_pack.py` and `.gitignore` before committing.
3. Existing instructions are preserved: `frontend/AGENTS.md` is untouched and referenced
   from `CLAUDE.md`. The `.gitignore` additions were appended under
   `# --- CyberGuard detection repair ---` without removing upstream lines (the same lines
   are in `docs/claude/gitignore_additions.txt`).
4. Run the structural checks:
   ```bash
   python3 scripts/check_claude_pack.py
   python3 .claude/hooks/test_protect_paths.py
   ```
   The validator checks local structure and template invariants only; it does not
   emulate Claude's runtime.
5. Start `claude --permission-mode plan`, run `/status` to confirm the project
   `settings.json` is a loaded settings source, and invoke `/cg-repo-audit`. Verify the
   `cg-*` skills appear in the slash command menu. `/cg-model-training`, `/cg-evaluate`
   and `/cg-release-review` are explicit-invocation only.
6. Run a harmless hook probe: ask Claude to write a file at a synthetic protected path
   such as `data/locked/probe.txt` and confirm the hook blocks it. Do not place real
   data there.
7. Commit the reviewed configuration in the fork.

## What the pack contains

| Path | Purpose |
| --- | --- |
| `CLAUDE.md` | Short standing context, commands, invariants |
| `.claude/skills/cg-*/SKILL.md` | 16 task procedures (plan section 21) |
| `.claude/agents/*.md` | 4 read-only reviewers (Read, Glob, Grep) |
| `.claude/rules/*.md` | Path-scoped guidance for analysis, frontend, backend |
| `.claude/settings.json` | Deny rules for secrets/raw/locked paths, PreToolUse hook |
| `.claude/hooks/protect_paths.py` | Blocks Write/Edit to protected or out-of-project paths |
| `docs/claude/` | Workflow, first prompts, skill validation cases, this guide |

## Limits

- Deny rules and the hook reduce accidental access; they are not a shell sandbox. The
  hook does not intercept Bash. Operating system isolation, separate evaluation
  workspaces and restricted service accounts provide the stronger boundary.
- No model is pinned and no MCP server is enabled.
- Claude Code sends interaction data over the network. Keep credentials, raw
  institutional telemetry and locked evaluation inputs outside this working tree.
