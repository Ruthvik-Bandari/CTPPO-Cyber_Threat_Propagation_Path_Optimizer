"""
Phase 1 / B4 + B5 — Time-to-exploit validation & asset-criticality sensitivity
==============================================================================

B4 — TIME-TO-EXPLOIT.  The TIME objective is a *relative* proxy: 10 / CVSS-exploitability-subscore,
times 0.5 if KEV (mature tooling) and 1.5 if Attack-Complexity is High. It does NOT use EPSS,
Metasploit/ExploitDB availability, or KEV add-dates. We validate it two ways with the data we have:
  (a) **Construct validity** — enumerate the CVSS exploitability space and confirm the proxy orders
      "easy/fast" (network · low-complexity · no-privs) below "hard/slow" as the spec claims.
  (b) **External validity** — on 97 REAL CVEs (CVSS vectors from the NVD cache, real EPSS + KEV from
      the threat provider), does the proxy agree with real exploit signals? EPSS is independent of
      the formula, so Spearman(time, EPSS) is a genuine external check: faster ⇒ higher real
      exploitation probability ⇒ expect a NEGATIVE correlation.

B5 — ASSET CRITICALITY.  Criticality is user-supplied and scales BUSINESS_IMPACT. We measure how
badly *mis-set* criticality distorts the remediation: re-run with criticality set uniform / shuffled
/ inverted and see how often the Pareto-critical top fix changes vs the correctly-set baseline.

Reproduce:  python3 evaluation/b4b5_time_criticality.py
"""

from __future__ import annotations

import glob
import json
import logging
import random
import re
import sys
from copy import deepcopy
from pathlib import Path
from statistics import mean
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cost_model import parse_cvss31_vector, exploitability_subscore, time_to_exploit_relative
from core.threat_data import ThreatDataProvider
from core.network_builder import build_network
from algorithms.namoa_star import run_namoa_star
from evaluation.b3_lateral_sensitivity import random_network, pareto_top_fix

logging.disable(logging.CRITICAL)

_CVE_RE = re.compile(r"CVE-\d{4}-\d+")
_VEC_RE = re.compile(r"CVSS:3\.[01]/[A-Z:/]+")


# ----------------------------- B4: time-to-exploit -----------------------------

def load_real_cves() -> List[Tuple[str, str]]:
    """Extract distinct (cve_id, cvss3_vector) pairs from the local NVD cache (data/cve_cache)."""
    root = Path(__file__).resolve().parent.parent
    seen = {}
    for f in sorted(glob.glob(str(root / "data" / "cve_cache" / "*.json"))):
        try:
            blob = json.dumps(json.loads(Path(f).read_text()))
        except Exception:
            continue
        # pair each CVE id with the nearest following vector within the same record blob
        for m in re.finditer(r"(CVE-\d{4}-\d+)(.*?)(CVSS:3\.[01]/[A-Z:/]+)", blob):
            cve, vec = m.group(1), m.group(3)
            seen.setdefault(cve, vec)
    return list(seen.items())


def _spearman(xs: List[float], ys: List[float]) -> Optional[float]:
    n = len(xs)
    if n < 3:
        return None

    def ranks(v):
        order = sorted(range(n), key=lambda i: v[i])
        r = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j + 1 < n and v[order[j + 1]] == v[order[i]]:
                j += 1
            avg = (i + j) / 2.0 + 1
            for k in range(i, j + 1):
                r[order[k]] = avg
            i = j + 1
        return r

    rx, ry = ranks(xs), ranks(ys)
    mx, my = sum(rx) / n, sum(ry) / n
    cov = sum((rx[i] - mx) * (ry[i] - my) for i in range(n))
    vx = sum((rx[i] - mx) ** 2 for i in range(n))
    vy = sum((ry[i] - my) ** 2 for i in range(n))
    if vx == 0 or vy == 0:
        return 0.0
    return cov / (vx ** 0.5 * vy ** 0.5)


def time_construct_validity() -> dict:
    """Enumerate the CVSS exploitability space; confirm the proxy's orderings match the spec."""
    rows = []
    for av in "NALP":
        for ac in "LH":
            for pr in "NLH":
                for ui in "NR":
                    for sc in "UC":
                        vec = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{sc}/C:H/I:H/A:H"
                        m = parse_cvss31_vector(vec)
                        t = time_to_exploit_relative(exploitability_subscore(m), False, ac, [])
                        rows.append((av, ac, pr, ui, sc, t))
    times = [r[5] for r in rows]
    av_mean = {a: mean([r[5] for r in rows if r[0] == a]) for a in "NALP"}
    ac_mean = {a: mean([r[5] for r in rows if r[1] == a]) for a in "LH"}
    # KEV factor effect on a representative vector
    m = parse_cvss31_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    expl = exploitability_subscore(m)
    return {
        "n_vectors": len(rows),
        "min_time": min(times), "max_time": max(times),
        "av_mean_time": av_mean,                    # expect N < A < L < P
        "ac_mean_time": ac_mean,                    # expect L < H
        "kev_speedup": time_to_exploit_relative(expl, False, "L", []) /
                       time_to_exploit_relative(expl, True, "L", []),   # expect ~2.0 (0.5x)
        "av_monotonic": av_mean["N"] < av_mean["A"] < av_mean["L"] < av_mean["P"],
        "ac_monotonic": ac_mean["L"] < ac_mean["H"],
    }


def time_external_validity(provider) -> dict:
    rows = []
    for cve, vec in load_real_cves():
        m = parse_cvss31_vector(vec)
        expl = exploitability_subscore(m)
        epss = provider.epss(cve)
        if expl is None or epss is None:
            continue
        kev = provider.is_kev(cve)
        t = time_to_exploit_relative(expl, kev, m.get("AC"), [])
        rows.append((cve, t, epss, kev))
    if len(rows) < 3:
        return {"n": len(rows)}
    from statistics import median
    times = [r[1] for r in rows]
    epsss = [r[2] for r in rows]
    non = [r for r in rows if not r[3]]
    kev = [r for r in rows if r[3]]
    return {
        "n": len(rows),
        "n_kev": len(kev),
        "epss_min": min(epsss), "epss_median": median(epsss), "epss_max": max(epsss),
        "spearman_time_epss_all": _spearman(times, epsss),                 # expect < 0
        "spearman_time_epss_nonkev": (_spearman([r[1] for r in non], [r[2] for r in non])
                                      if len(non) >= 3 else None),         # clean (no KEV coupling)
        "mean_time_kev": mean([r[1] for r in kev]) if kev else None,
        "mean_time_nonkev": mean([r[1] for r in non]) if non else None,
    }


# ----------------------------- B5: asset criticality -----------------------------

def _criticality_variant(spec, mode: str, rng: random.Random):
    s = deepcopy(spec)
    crits = [h.criticality for h in s.hosts]
    if mode == "uniform5":
        for h in s.hosts:
            h.criticality = 5.0
    elif mode == "shuffled":
        shuffled = crits[:]
        rng.shuffle(shuffled)
        for h, c in zip(s.hosts, shuffled):
            h.criticality = c
    elif mode == "inverted":
        for h in s.hosts:
            h.criticality = 10.0 - h.criticality
    return s


def criticality_sensitivity(n: int = 60) -> dict:
    provider = ThreatDataProvider(offline=True)
    modes = ["uniform5", "shuffled", "inverted"]
    stable = {m: 0 for m in modes}
    evaluated = 0
    for seed in range(n):
        spec = random_network(seed)
        base = build_network(spec, provider=provider)
        base_fix = pareto_top_fix(base, run_namoa_star(base))
        if base_fix is None:
            continue
        evaluated += 1
        rng = random.Random(seed + 9973)
        for m in modes:
            g = build_network(_criticality_variant(spec, m, rng), provider=provider)
            if pareto_top_fix(g, run_namoa_star(g)) == base_fix:
                stable[m] += 1
    return {
        "n_evaluated": evaluated,
        "top_fix_stable_frac": {m: (stable[m] / evaluated if evaluated else 1.0) for m in modes},
    }


def run() -> dict:
    provider = ThreatDataProvider(offline=True)
    return {
        "b4_construct": time_construct_validity(),
        "b4_external": time_external_validity(provider),
        "b5_criticality": criticality_sensitivity(),
    }


if __name__ == "__main__":
    res = run()
    c = res["b4_construct"]
    print("B4 — time-to-exploit construct validity (CVSS exploitability space):")
    print(f"  {c['n_vectors']} vectors · time range {c['min_time']:.2f}–{c['max_time']:.2f}")
    print(f"  mean time by Attack Vector (expect N<A<L<P): "
          f"{ {k: round(v,1) for k,v in c['av_mean_time'].items()} }  monotonic={c['av_monotonic']}")
    print(f"  mean time by Attack Complexity (expect L<H): "
          f"{ {k: round(v,1) for k,v in c['ac_mean_time'].items()} }  monotonic={c['ac_monotonic']}")
    print(f"  KEV speed-up factor: {c['kev_speedup']:.2f}x (spec 2.0x)")
    e = res["b4_external"]
    print(f"\nB4 — external validity on {e.get('n')} real CVEs (NVD cache ∩ EPSS; KEV={e.get('n_kev')}):")
    if e.get("n", 0) >= 3:
        print(f"  sample EPSS min/median/max   : {e['epss_min']:.4f} / {e['epss_median']:.4f} / {e['epss_max']:.4f}")
        print(f"  Spearman(time, EPSS) all     : {e['spearman_time_epss_all']:+.2f}  (expect <0 if proxy tracks real exploitability)")
        snk = e['spearman_time_epss_nonkev']
        print(f"  Spearman(time, EPSS) non-KEV : {snk:+.2f}" if snk is not None else "  non-KEV: n<3")
        if e.get("mean_time_kev") is not None and e.get("mean_time_nonkev") is not None:
            print(f"  mean time  KEV={e['mean_time_kev']:.2f}  non-KEV={e['mean_time_nonkev']:.2f} (KEV should be faster)")
        else:
            print("  (no KEV CVEs in this NVD-cache sample — KEV/non-KEV time comparison n/a)")
    b5 = res["b5_criticality"]
    print(f"\nB5 — asset-criticality sensitivity ({b5['n_evaluated']} networks): "
          "top fix UNCHANGED when criticality is mis-set —")
    for m, f in b5["top_fix_stable_frac"].items():
        print(f"  {m:<10}: {f:.1%}")
