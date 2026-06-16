# B4 — external grounding of the time-to-exploit proxy (the lone open Phase-1 item)

**Phase 1 follow-up, deliverable B4 (external half).** Roadmap: `05_OSS_REALTIME_PLAN.md` §Phase-1.
**Status: DONE via KEV add-dates (2026-06-16) — moves B4 from "externally inconclusive" to
"externally corroborated (modest, CI excludes 0)".** Source: `evaluation/b4_external_grounding.py`.

## The open item

B4 originally **passed construct validity** (proxy time monotone in CVSS Attack-Vector N<A<L<P and
Complexity L<H; KEV 2× speed-up) but was **externally INCONCLUSIVE**: the only sample then was 97
narrow, low-EPSS, **zero-KEV** NVD-cache CVEs → `Spearman = +0.02`, CI straddling 0
(`B4_B5_TIME_CRITICALITY.md`). The deferred fix needed a real "time-to-exploit" signal:
Metasploit/ExploitDB availability **or CISA KEV add-dates**. The KEV feed is now cached with
`dateAdded`, so the KEV-add-date half is doable offline.

## Method

For every CVE in **both** the KEV feed (`dateAdded`, 1,621 CVEs) and the NVD cache
(`published_date` + CVSS vector, 3,200 CVEs) — **155 CVEs** in the intersection:

```
real exposure window = dateAdded(KEV) − published_date(NVD)   # days: disclosure → known-exploited
proxy time           = time_to_exploit_relative(expl, is_kev=True, ac)   # the model; lower = faster
```

A valid proxy predicts a *faster* time for CVEs with a *shorter* window → a **positive**
Spearman(proxy_time, window). Spearman with a 2,000-sample bootstrap 95% CI (seed 0).

## Result — externally corroborated (modest, significant)

| Sample | n | Spearman(proxy_time, window) | 95% CI | Verdict |
|---|---:|---:|---|---|
| KEV ∩ NVD-cache (full) | **155** | **+0.263** | **[+0.11, +0.41]** | **POSITIVE — CI excludes 0** |
| post-2021-11-03 subset | 0 | — | — | n=0 (see confound) |

The CI **excludes zero**, so the time proxy is **positively and significantly correlated** with the
real disclosure→known-exploited window — a clear improvement on the original `+0.02` (CI straddling
0). The time-to-exploit proxy is now **externally corroborated**, not merely construct-valid.

## Honest confound (decisive — read before citing)

`dateAdded` is when **CISA catalogued** the CVE as known-exploited, **not** when it was first
exploited. CISA's KEV program launched **2021-11-03** and bulk-added many older CVEs, so the median
exposure window here is **~3,303 days (~9 years)** and **0 of the 155** were published after the KEV
launch. The window is therefore dominated by *cataloguing lag*, not exploitation speed, and the
+0.263 is measured against that noisy signal (plausible mechanism: CISA/attackers reached the
easily-exploitable, network/low-complexity CVEs sooner). So this is a **proxy-for-a-proxy**: real,
statistically significant, directionally correct, but **not** ground truth from actual exploitation
timestamps. The gold standard — Metasploit/ExploitDB module publication dates — remains future work
(needs fetching + parsing those datasets). B4's *construct* validity (B4_B5 doc) is unchanged; this
adds the external corroboration that was missing.

## Files

`evaluation/b4_external_grounding.py` (`load_pairs`, `_spearman`/`_spearman_ci`, `run`),
`tests/evaluation/test_b4_external_grounding.py` (2 tests). Updates METRICS §5 (B4 row) and the
A5 note. **This closes B4's external-grounding gap to the extent offline data allows.**
