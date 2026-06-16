"""
B4 — external grounding of the time-to-exploit proxy vs KEV add-dates (Phase 1's lone open item)
================================================================================================

B4 originally PASSED construct validity (time monotone in CVSS AV/AC; KEV speed-up) but was
**externally INCONCLUSIVE** — the only sample then was 97 narrow, low-EPSS, **zero-KEV** NVD-cache
CVEs (Spearman +0.02, CI straddling 0). The deferred fix: validate against a real "time-to-exploit"
signal — Metasploit/ExploitDB availability or **CISA KEV add-dates**.

This does the KEV-add-date half, now that the KEV feed is cached with `dateAdded` (1,621 CVEs) and
the NVD cache carries `published_date` + CVSS vectors (3,200 CVEs). For each CVE in **both**:

    real exposure window  =  dateAdded(KEV)  -  published_date(NVD)     # days, disclosure → known-exploited
    proxy time            =  time_to_exploit_relative(expl, is_kev, ac) # lower = faster (the model)

If the proxy is externally valid, a *faster* proxy time should go with a *shorter* exposure window
→ a POSITIVE Spearman(proxy_time, exposure_window).

**Honest confound (decisive — read this).** `dateAdded` is when **CISA catalogued** the CVE as
known-exploited, NOT when it was first exploited. CISA's KEV program launched **2021-11-03** and
bulk-added many older CVEs, so for a CVE published years earlier the window is dominated by "when
CISA got to it," not exploitation speed. We therefore report BOTH the full sample and a
**post-launch subset** (published ≥ 2021-11-03), where `dateAdded` more plausibly tracks real
timing. This is a proxy-for-a-proxy; it is the best external signal available offline, not ground
truth from actual exploitation timestamps (that still needs Metasploit/ExploitDB modules).

Author: CTPPO
"""

from __future__ import annotations

import glob
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cost_model import time_to_exploit_relative
from evaluation.a5_statistical_rigor import bootstrap_ci

KEV_LAUNCH = datetime(2021, 11, 3)
_DATA = Path(__file__).resolve().parent.parent / "data"

# CVSS v3.1 exploitability-subscore coefficients.
_AV = {"NETWORK": 0.85, "ADJACENT": 0.62, "ADJACENT_NETWORK": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2}
_AC = {"LOW": 0.77, "HIGH": 0.44}
_PR = {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27}
_UI = {"NONE": 0.85, "REQUIRED": 0.62}


def _exploitability(vec: Dict) -> float:
    return round(8.22 * _AV.get(str(vec.get("attack_vector", "")).upper(), 0.85)
                 * _AC.get(str(vec.get("attack_complexity", "")).upper(), 0.77)
                 * _PR.get(str(vec.get("privileges_required", "")).upper(), 0.85)
                 * _UI.get(str(vec.get("user_interaction", "")).upper(), 0.85), 4)


def _ac(vec: Dict) -> str:
    return "H" if str(vec.get("attack_complexity", "")).upper() == "HIGH" else "L"


def _parse_date(s: str):
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(s.split("+")[0].rstrip("Z"), fmt)
        except (ValueError, AttributeError):
            continue
    return None


def load_pairs() -> List[Dict]:
    """Build the (proxy_time, exposure_window_days) sample over KEV ∩ NVD-cache CVEs."""
    kev = json.loads((_DATA / "threat_cache" / "known_exploited_vulnerabilities.json").read_text())
    kev_date = {v["cveID"]: v["dateAdded"] for v in kev.get("vulnerabilities", []) if v.get("dateAdded")}

    nvd: Dict[str, Dict] = {}
    for f in glob.glob(str(_DATA / "cve_cache" / "*.json")):
        try:
            arr = json.loads(Path(f).read_text())
        except Exception:
            continue
        if isinstance(arr, list):
            for r in arr:
                if isinstance(r, dict) and r.get("cve_id") and r.get("published_date") and isinstance(r.get("cvss_vector"), dict):
                    nvd[r["cve_id"]] = r

    rows = []
    for cve, added_s in kev_date.items():
        rec = nvd.get(cve)
        if not rec:
            continue
        added, pub = _parse_date(added_s), _parse_date(rec["published_date"])
        if not added or not pub:
            continue
        window = (added - pub).days
        if window < 0:
            continue                                  # data error (KEV before disclosure)
        vec = rec["cvss_vector"]
        rows.append({
            "cve": cve,
            "proxy_time": time_to_exploit_relative(_exploitability(vec), True, _ac(vec), []),
            "window_days": window,
            "published": pub,
        })
    return rows


def _spearman(xs: List[float], ys: List[float]) -> float:
    """Spearman rho via Pearson on ranks (no scipy dependency for the headline)."""
    n = len(xs)
    if n < 3:
        return 0.0

    def ranks(v):
        order = sorted(range(n), key=lambda i: v[i])
        r = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j + 1 < n and v[order[j + 1]] == v[order[i]]:
                j += 1
            avg = (i + j) / 2 + 1
            for k in range(i, j + 1):
                r[order[k]] = avg
            i = j + 1
        return r

    rx, ry = ranks(xs), ranks(ys)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    dx = sum((a - mx) ** 2 for a in rx) ** 0.5
    dy = sum((b - my) ** 2 for b in ry) ** 0.5
    return round(num / (dx * dy), 4) if dx and dy else 0.0


def _spearman_ci(xs: List[float], ys: List[float], n_boot: int = 2000, seed: int = 0) -> Dict:
    import random
    rng = random.Random(seed)
    n = len(xs)
    point = _spearman(xs, ys)
    boots = []
    for _ in range(n_boot):
        idx = [rng.randrange(n) for _ in range(n)]
        boots.append(_spearman([xs[i] for i in idx], [ys[i] for i in idx]))
    boots.sort()
    return {"point": point, "ci_lo": boots[int(0.025 * n_boot)], "ci_hi": boots[int(0.975 * n_boot)], "n": n}


def run() -> Dict:
    rows = load_pairs()
    full = _spearman_ci([r["proxy_time"] for r in rows], [r["window_days"] for r in rows]) if rows else {}
    post = [r for r in rows if r["published"] >= KEV_LAUNCH]
    post_ci = _spearman_ci([r["proxy_time"] for r in post], [r["window_days"] for r in post]) if len(post) >= 3 else {}
    med_window = sorted(r["window_days"] for r in rows)[len(rows) // 2] if rows else 0
    return {"n_pairs": len(rows), "n_post_launch": len(post),
            "median_window_days": med_window,
            "spearman_full": full, "spearman_post_launch": post_ci}


if __name__ == "__main__":
    res = run()
    print(f"B4 external grounding — KEV add-dates vs time-to-exploit proxy\n")
    print(f"  sample: {res['n_pairs']} CVEs in KEV ∩ NVD-cache (median exposure window "
          f"{res['median_window_days']} days)")
    f = res["spearman_full"]
    if f:
        sign = "POSITIVE (proxy valid)" if f["ci_lo"] > 0 else ("NEGATIVE" if f["ci_hi"] < 0 else "straddles 0 → INCONCLUSIVE")
        print(f"  full sample      Spearman(proxy_time, window) = {f['point']:+.3f} "
              f"[{f['ci_lo']:+.2f}, {f['ci_hi']:+.2f}] (n={f['n']}) → {sign}")
    p = res["spearman_post_launch"]
    if p:
        sign = "POSITIVE (proxy valid)" if p["ci_lo"] > 0 else ("NEGATIVE" if p["ci_hi"] < 0 else "straddles 0 → INCONCLUSIVE")
        print(f"  post-2021-11-03  Spearman(proxy_time, window) = {p['point']:+.3f} "
              f"[{p['ci_lo']:+.2f}, {p['ci_hi']:+.2f}] (n={p['n']}) → {sign}")
    else:
        print(f"  post-2021-11-03 subset too small (n={res['n_post_launch']}) for a CI")
