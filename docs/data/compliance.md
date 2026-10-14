# Research compliance checklist

Status of the documents and approvals the research track depends on. "Owner: Ruthvik" items
need a person; the tooling cannot satisfy them.

| Item | Status | Owner | Notes |
| --- | --- | --- | --- |
| License record for each data source | Done | repo | `sources.md`; license file hashes in each acquisition manifest |
| Data handling and model guardrails policy | Done (draft) | repo | `policy.md`; review and adopt |
| Explorer general and scratch policies read | Done | repo | [General policies](https://rc.northeastern.edu/research-computing-policies/general-policies/), [Scratch policy](https://rc.northeastern.edu/research-computing-policies/scratch-space-policy/): Slurm only, research or coursework use, no account sharing, monthly scratch purge |
| Faculty sponsor and allocation for this project | To confirm | Ruthvik | Explorer requires a faculty sponsor for students; confirm which Slurm account to charge (`sacctmgr` lists `aai6610.202610` and `j.liebowitz`) |
| Persistent `/work` storage | To request | Ruthvik and PI | Scratch is purged monthly; the frozen benchmark and checkpoints need `/work` (PI request) |
| Human-subjects review for practitioner trials | To confirm | Ruthvik | Timed practitioner trials (plan section 13) may need IRB review or an exemption determination before recruiting anyone |
| Written lab plan for Atomic Red Team runs | Not started | Ruthvik | Only needed before executing tests; reading definitions needs none |
| Base model license | Pending model choice | repo | Recorded when B2 selects a model (plan section 12) |
| Dataset card | After freeze | repo | Written when the split manifest is frozen |
| Model card and evaluation report | After M1 | repo | Required for any released model |
| Research Computing acknowledgement in publications | Ongoing | Ruthvik | [Acknowledgements](https://rc.northeastern.edu/research-computing-policies/acknowledgements/) |
