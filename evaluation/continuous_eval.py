"""
Continuous-improvement loop (Phase 4)
=====================================

The repo half of the loop: on each run it pulls the **latest threat data**, rebuilds the
evaluation networks, re-runs NAMOA* + the A4 baselines, records the headline metrics to a
**timeseries**, and **flags regressions** against history + absolute floors. Designed to run
unattended (cron / the scheduled Claude agent), so a drop in the engine's value — or stale
data — is caught instead of silently rotting.

Loop closure (latest data → rebuild → metrics → flags):
- Default uses an **online** ``ThreatDataProvider`` so a stale EPSS/KEV cache auto-refreshes
  (the 3a feeds); each record stamps the feed provenance/staleness so the metric is tied to
  the data it was computed on.
- Metrics come from the A2/A4 study (``evaluation/baseline_study.py``) on the neutral
  generator — the honest base-rate of the Pareto-vs-baselines advantage.

Regression = a tracked metric below its absolute **floor**, or a **drop** beyond tolerance vs
the previous run. Exit code is non-zero when any regression fires (CI-friendly).

Run:   python3 evaluation/continuous_eval.py
Demo a caught regression:  python3 evaluation/continuous_eval.py --inject-regression --history /tmp/h.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.threat_data import ThreatDataProvider, utc_now_iso
from evaluation import baseline_study as bs

logging.disable(logging.CRITICAL)

DEFAULT_HISTORY = Path(__file__).resolve().parent / "history" / "continuous_eval_history.json"
DEFAULT_N = 60

# A tracked metric below its floor = regression (absolute health gate).
FLOORS = {"pareto_recovery": 0.60, "pareto_ge_cvss": 0.70}
# A tracked metric dropping by more than this vs the previous run = regression.
DROP_TOL = {"pareto_recovery": 0.10, "pareto_ge_cvss": 0.10, "pareto_gt_cvss": 0.15}


def measure(n: int, provider) -> Dict[str, float]:
    """Headline thesis metrics on the neutral generator (the honest base-rate)."""
    r = bs.run(n=n, mode="neutral", provider=provider)
    pt = lambda k: r[k]["point"]
    return {
        "n_evaluated": r["n_evaluated"],
        "pareto_recovery": pt("recovery_pareto"),
        "cvss_recovery": pt("recovery_cvss"),
        "epss_recovery": pt("recovery_epss"),
        "pareto_ge_cvss": pt("pareto_ge_cvss"),
        "pareto_gt_cvss": pt("pareto_gt_cvss"),
    }


def data_provenance(provider) -> Dict[str, dict]:
    """Feed freshness at eval time — ties the metric to the data it was computed on (3a)."""
    try:
        st = provider.staleness()
    except Exception:
        return {}
    return {src: {"source_as_of": v.get("source_as_of"), "status": v.get("status")}
            for src, v in st.items()}


def make_record(n: int, provider) -> dict:
    return {
        "timestamp": utc_now_iso(),
        "n": n,
        "metrics": measure(n, provider),
        "data": data_provenance(provider),
    }


def load_history(path: Path | str) -> List[dict]:
    path = Path(path)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_history(history: List[dict], path: Path | str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(history, indent=2), encoding="utf-8")


def detect_regressions(history: List[dict]) -> List[str]:
    """Flags vs absolute floors (always) and vs the previous run's metrics (if any)."""
    if not history:
        return []
    cur = history[-1].get("metrics", {})
    flags: List[str] = []
    for k, floor in FLOORS.items():
        v = cur.get(k)
        if v is not None and v < floor:
            flags.append(f"{k}={v:.3f} below floor {floor:.2f}")
    if len(history) >= 2:
        prev = history[-2].get("metrics", {})
        for k, tol in DROP_TOL.items():
            a, b = prev.get(k), cur.get(k)
            if a is not None and b is not None and a - b > tol:
                flags.append(f"{k} dropped {a:.3f}→{b:.3f} (>{tol:.2f})")
    return flags


def run(n: int = DEFAULT_N, history_path: Path | str = DEFAULT_HISTORY,
        provider=None, inject_regression: bool = False) -> dict:
    """Run one eval cycle: measure → append to history → detect regressions. Returns a report."""
    provider = provider or ThreatDataProvider()  # online by default = "latest data" (auto-refresh)
    record = make_record(n, provider)
    if inject_regression:  # exit-criterion demo: force a degraded metric so a regression is caught
        record["metrics"]["pareto_recovery"] = 0.0
        record["injected_regression"] = True
    history = load_history(history_path)
    history.append(record)
    flags = detect_regressions(history)
    record["regressions"] = flags
    save_history(history, history_path)
    return {"record": record, "regressions": flags, "history_len": len(history),
            "history_path": str(history_path)}


def main() -> int:
    ap = argparse.ArgumentParser(description="CTPPO continuous-eval regression harness")
    ap.add_argument("--n", type=int, default=DEFAULT_N, help="networks per eval (default 60)")
    ap.add_argument("--history", default=str(DEFAULT_HISTORY), help="timeseries JSON path")
    ap.add_argument("--offline", action="store_true", help="use the cached snapshot (no refresh)")
    ap.add_argument("--inject-regression", action="store_true",
                    help="force a degraded metric to demonstrate regression detection")
    args = ap.parse_args()
    provider = ThreatDataProvider(offline=True) if args.offline else ThreatDataProvider()
    rep = run(n=args.n, history_path=args.history, provider=provider,
              inject_regression=args.inject_regression)
    m = rep["record"]["metrics"]
    print(f"CTPPO continuous-eval — run #{rep['history_len']}  ({rep['record']['timestamp']})")
    print(f"  pareto_recovery={m['pareto_recovery']:.3f}  cvss={m['cvss_recovery']:.3f}  "
          f"epss={m['epss_recovery']:.3f}  pareto≥cvss={m['pareto_ge_cvss']:.3f}  (n={m['n_evaluated']})")
    for src, d in rep["record"].get("data", {}).items():
        print(f"  data[{src}]: as_of={d.get('source_as_of')} ({d.get('status')})")
    if rep["regressions"]:
        print("  ⚠ REGRESSIONS:")
        for f in rep["regressions"]:
            print(f"    - {f}")
        return 1
    print("  ✓ no regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
