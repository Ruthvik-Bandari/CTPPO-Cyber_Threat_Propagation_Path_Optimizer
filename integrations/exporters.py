"""
SIEM / EDR / ticketing exporters (Phase 6, G2)
==============================================

CTPPO produces structured findings — a recommended choke-point fix and the Pareto attack-path
front. This module formats those findings into the **standard schemas** that downstream tools
ingest, so a CTPPO run can feed a SOC's existing pipeline:

- **SIEM** — Elastic Common Schema (ECS) JSON events (one per Pareto path) and a CEF line
  (Common Event Format) for collectors that prefer it.
- **Ticketing** — a generic remediation-ticket dict (summary / description / priority / labels)
  that maps cleanly onto Jira or ServiceNow issue fields.
- **Delivery** — a generic webhook dispatcher.

**Honesty (read this).** This formats and (optionally) POSTs payloads. It does **not** ship a real
authenticated Splunk/Elastic/Jira/CrowdStrike integration — that needs the operator's endpoint and
credentials, a genuine external dependency. With no webhook URL configured, ``dispatch_webhook``
returns the payload and says ``delivered=False`` rather than pretending to deliver (same discipline
as the LLM reviewer needing an API key). EDR is ingest-only here (EDRs *consume* detections); we
emit the ECS event an EDR/SIEM forwarder can pick up, we do not call a vendor EDR API.

Author: CTPPO
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_from_reachability(r: float) -> str:
    return "critical" if r >= 0.5 else "high" if r >= 0.2 else "medium" if r >= 0.05 else "low"


def to_ecs_events(pareto_out: Dict, source: str = "ctppo",
                  recommended_fix: Optional[str] = None, now: Optional[str] = None) -> List[Dict]:
    """One Elastic Common Schema (ECS) event per Pareto path. SIEM-ingestable JSON."""
    ts = now or _now_iso()
    events = []
    paths = pareto_out.get("paths", {}).get("pareto_optimal", [])
    for rank, p in enumerate(paths, 1):
        band = p.get("reachability_band") or {}
        reach = band.get("independence", 0.0)
        events.append({
            "@timestamp": ts,
            "event": {"kind": "alert", "category": ["intrusion_detection"], "type": ["info"],
                      "module": "ctppo", "dataset": "ctppo.attack_path",
                      "severity": _severity_from_reachability(reach)},
            "message": f"CTPPO Pareto attack path #{rank}: "
                       f"{' -> '.join(str(n) for n in p.get('path', []))}",
            "ctppo": {
                "pareto_rank": rank,
                "objectives": p.get("cost", {}),
                "reachability_independence": band.get("independence"),
                "reachability_comonotone": band.get("comonotone"),
                "path": p.get("path", []),
                "recommended_fix": recommended_fix,
                "num_pareto_paths": len(paths),
            },
        })
    return events


_CEF_ESCAPE = str.maketrans({"\\": "\\\\", "|": "\\|", "\n": " "})


def to_cef(event: Dict) -> str:
    """Render one ECS-style event as a CEF (Common Event Format) line for legacy SIEM collectors."""
    c = event.get("ctppo", {})
    sev_map = {"critical": 10, "high": 8, "medium": 5, "low": 2}
    sev = sev_map.get(event.get("event", {}).get("severity", "medium"), 5)
    # CEF header: structural pipes are field separators (literal); only the variable Name field
    # (the message) is escaped, per the CEF spec.
    name = str(event.get("message", "")).translate(_CEF_ESCAPE)
    header = f"CEF:0|CTPPO|attack-path-engine|1.0|pareto_path|{name}|{sev}"
    ext = {
        "cs1Label": "paretoRank", "cs1": str(c.get("pareto_rank", "")),
        "cs2Label": "recommendedFix", "cs2": str(c.get("recommended_fix") or ""),
        "cn1Label": "reachabilityLow", "cn1": str(c.get("reachability_independence") or 0),
        "cn2Label": "reachabilityHigh", "cn2": str(c.get("reachability_comonotone") or 0),
    }
    ext_str = " ".join(f"{k}={str(v).translate(_CEF_ESCAPE)}" for k, v in ext.items())
    return f"{header}|{ext_str}"


def to_ticket(pareto_out: Dict, recommended_fix: Optional[str] = None,
              reachability_reduction: Optional[float] = None) -> Dict:
    """A generic remediation ticket (Jira/ServiceNow-mappable) summarizing the front + the fix."""
    paths = pareto_out.get("paths", {}).get("pareto_optimal", [])
    best = max((p.get("reachability_band", {}).get("independence", 0.0) for p in paths), default=0.0)
    priority = {"critical": "Highest", "high": "High", "medium": "Medium",
                "low": "Low"}[_severity_from_reachability(best)]
    lines = [f"CTPPO found {len(paths)} Pareto-optimal attack path(s) to a crown jewel.", ""]
    if recommended_fix:
        red = f" (removes ~{reachability_reduction:.3f} reachability)" if reachability_reduction else ""
        lines.append(f"Recommended fix (choke point): {recommended_fix}{red}.")
        lines.append("")
    for rank, p in enumerate(paths, 1):
        band = p.get("reachability_band", {})
        lines.append(f"  Path {rank}: {' -> '.join(str(n) for n in p.get('path', []))}  "
                     f"[reachability {band.get('independence', 0):.4f}–{band.get('comonotone', 0):.4f}]")
    return {
        "summary": f"CTPPO: remediate {recommended_fix or 'top attack-path choke point'} "
                   f"({len(paths)} Pareto path(s))",
        "description": "\n".join(lines),
        "priority": priority,
        "labels": ["ctppo", "attack-path", "remediation"],
        "fields": {"recommended_fix": recommended_fix, "num_pareto_paths": len(paths),
                   "max_reachability": round(best, 6)},
    }


def dispatch_webhook(payload, url: Optional[str] = None, client=None, timeout: float = 10.0) -> Dict:
    """POST ``payload`` to ``url``. With no URL configured, returns the payload without delivering
    (honest no-op) — real delivery needs the operator's endpoint. ``client`` is injectable (httpx
    client or a TestClient-like) for tests."""
    body = payload if isinstance(payload, (dict, list)) else {"data": payload}
    if not url:
        return {"delivered": False, "reason": "no webhook URL configured", "payload": body}
    try:
        if client is None:
            import httpx
            client = httpx.Client(timeout=timeout)
            close = True
        else:
            close = False
        resp = client.post(url, json=body)
        if close:
            client.close()
        return {"delivered": True, "status_code": getattr(resp, "status_code", None),
                "url": url}
    except Exception as e:                       # network/dep failure is reported, not swallowed
        return {"delivered": False, "reason": f"{type(e).__name__}: {e}", "url": url,
                "payload": body}


if __name__ == "__main__":
    sample = {"paths": {"pareto_optimal": [
        {"path": ["internet", "web", "crown"], "cost": {"TIME_TO_EXPLOIT": 4.2, "SUCCESS_PROBABILITY": 0.46},
         "reachability_band": {"independence": 0.46, "comonotone": 0.8, "width_factor": 1.74, "n_edges": 4}},
    ]}, "risk_summary": {"num_pareto_paths": 1}}
    ev = to_ecs_events(sample, recommended_fix="CVE-2021-44228")
    print("ECS event:\n", json.dumps(ev[0], indent=2))
    print("\nCEF:\n", to_cef(ev[0]))
    print("\nTicket:\n", json.dumps(to_ticket(sample, "CVE-2021-44228", 0.31), indent=2))
    print("\nWebhook (no URL):\n", dispatch_webhook(ev, url=None)["delivered"])
