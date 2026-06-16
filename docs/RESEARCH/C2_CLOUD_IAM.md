# C2 — Cloud IAM / permission-lateral-movement modeling (+ ATT&CK on edges)

**Phase 5 (modeling scope), deliverable C2.** Roadmap: `05_OSS_REALTIME_PLAN.md` §Phase-5.
**Status: DONE (2026-06-15).** Source: `core/cloud_iam_graph.py`.

## The gap

C1 (`core/identity_graph`) added on-prem **identity/credential** movement (phish → Pass-the-Hash
→ DCSync). The matching gap for the **cloud control plane** is **IAM permission abuse**: in
AWS/Azure/GCP the lateral path is not a CVE and not a Windows hash — it is *"this principal can
`iam:PassRole`"*, *"this instance role can be stolen from the metadata service"*,
*"this role can `CreatePolicyVersion` to grant itself admin"*. **None of that is a CVE**, and EPSS
does not score it. C2 adds that modality.

## What this delivers

`core/cloud_iam_graph.py` builds the **same canonical** `AttackGraph` (so it plugs straight into
NAMOA\* and everything downstream), but the transitions are **cloud MITRE ATT&CK techniques**
between cloud principals/resources instead of CVE exploits:

- `Technique(...)` — reused from C1 (a cloud IAM step is the same kind of ATT&CK object as a
  credential step: id/name/tactic + heuristic success/time/detection priors).
- `CloudPrincipal` (`provider` aws|azure|gcp, `principal_type` iam_user|role|instance|resource) /
  `CloudMove` / `CloudScenario` — a spec for a cloud estate + the attacker's IAM moves;
  `build_cloud_iam_graph()` turns it into the canonical graph.
- Two new edge relations: `CLOUD_INITIAL_ACCESS`, `CLOUD_IAM_MOVE`. Every transition's **ATT&CK
  technique id + tactic** rides on both the `ExploitNode` and the edge metadata, and the cloud
  provider is recorded on each principal's asset metadata.

## Measured — the AWS IAM privesc chain recovered (2026-06-15)

`create_aws_privesc_scenario()` (4 principals: low-priv IAM user → EC2 instance → CI/CD role →
Account Admin, the goal) → 11 nodes / 11 edges → NAMOA\* returns **2 Pareto-optimal cloud-privesc
paths** to account administrator:

| # | Recovered kill chain (cloud ATT&CK) | time | success | impact |
|---|---|---:|---:|---:|
| 1 | **T1078.004** Valid Cloud Account → **T1651** Cloud Admin Command → **T1548.005** Temporary Elevated Cloud Access → Admin | 11.9 | 0.195 | 9.5 |
| 2 | **T1078.004** Valid Cloud Account → **T1651** Cloud Admin Command → **T1552.005** IMDS cred theft → **T1098.003** Additional Cloud Roles → Admin | 14.0 | **0.246** | 9.5 |

Both are valid **cloud IAM lateral paths** ending in account takeover — the same Phase-5 exit
criterion as C1 ("an identity/credential lateral path appears in a scenario"), now in the cloud
domain. The engine surfaces the real operator tradeoff: route 1 is **fewer hops / faster but
louder** (the EC2 instance role elevates straight to admin via a misconfigured elevation path,
which CloudTrail logs loudly); route 2 is the **slower, higher-success chain** (steal the instance
role from the metadata service, assume the broad CI/CD role, then attach `AdministratorAccess`).
Neither dominates the other on (time, success), so multi-objective Pareto keeps both — exactly the
value over single-objective ranking, now for cloud privesc.

## Cross-cloud (AWS / Azure / GCP)

The scenario is AWS-flavored, but the **structure and the ATT&CK technique IDs are
provider-agnostic** — only the API names differ:

| Step (ATT&CK) | AWS | Azure | GCP |
|---|---|---|---|
| T1078.004 Valid Cloud Account | leaked access key | leaked SP secret / token | leaked SA key |
| T1552.005 IMDS credential theft | `169.254.169.254` instance role | IMDS Managed Identity token | metadata server SA token |
| T1098.003 Additional Cloud Roles | `iam:CreatePolicyVersion` / `AttachRolePolicy` | `Microsoft.Authorization/roleAssignments` | `iam.serviceAccounts.actAs` / impersonation |
| T1548.005 Temp Elevated Cloud Access | `sts:AssumeRole` chain | PIM / eligible-role activation | `serviceAccounts.getAccessToken` |

`CloudPrincipal.provider` records which cloud; the same builder produces the graph for any of them.

## Honest caveat (important)

Exactly as in C1: **cloud IAM technique costs are heuristic** — there is no per-technique
exploit-probability feed (EPSS covers CVEs, not "can this principal `iam:PassRole`"). The
success/time priors are a documented calibration target, flagged `heuristic=True` and
`data_grounded=False` in **every** cloud edge's metadata (the same discipline as B3's lateral
prior and C1's credential prior). **The grounded part is the *structure*** (which principal can
reach which, by which technique — recoverable from an IAM-policy graph / a tool like
PMapper/Cartography); **the contribution is the modeling capability + ATT&CK provenance, not a
data-grounded probability for cloud privesc.** The B1–B8 sensitivity lesson applies — such priors
move reachability *magnitude*, while the prioritization *decision* is driven by graph structure
(here, the choke points — initial access and the EC2 pivot — that every cloud route crosses).
Grounding the priors from IAM-policy reachability analysis (a real IAM graph) or red-team
frequencies is future work.

## Files

`core/cloud_iam_graph.py` (`CloudPrincipal/Move/Scenario`, `build_cloud_iam_graph`,
`create_aws_privesc_scenario`, `_cloud_cost`; reuses `Technique` from `core/identity_graph`),
`tests/core/test_cloud_iam_graph.py` (7 tests, offline).
Next in Phase 5: C3 misconfiguration, C4 BAS-lite/scoping; E1/E2/E3 ML-role honesty.
