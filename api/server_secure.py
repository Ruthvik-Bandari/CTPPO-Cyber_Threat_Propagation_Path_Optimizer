#!/usr/bin/env python3
"""
CTPPO — Cyber Threat Propagation Path Optimizer (open-source, local-first API)
====================================

Local-first: no authentication, accounts, or subscription — every request runs as a
single implicit local user. Serves the attack-path engine + scanning + reports.

Author: Ruthvik Bandari
Date: January 2026
"""

import os
import sys
import time
import urllib.parse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

import torch
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
# transformers is imported lazily inside the severity-classifier load path
# (ml/cve_classifier.py) so the API imports/runs even when transformers is absent.

# Instances (scan/analysis workspaces) — the one platform piece kept for local-first,
# open-source use (single local user, no auth / subscription).
from instance_store import instances as instance_store
from instance_routes import create_instance_router

# Add ml directory
sys.path.insert(0, str(Path(__file__).parent.parent / "ml"))
from core.attack_graph import AttackGraph, EdgeType, create_sample_enterprise_graph
from core.node_types import AssetNode, EntryPointNode, GoalNode, AssetType, PrivilegeLevel
from core.cost_model import build_edge_cost, EdgeCostInputs
from core.threat_data import ThreatDataProvider
from algorithms.namoa_star import run_namoa_star


# ============================================================================
# CONFIGURATION
# ============================================================================

# Local-first, open-source: no auth, accounts, or subscription. Every request runs as a
# single implicit local user (see get_current_user below).
LOCAL_USER = {
    "id": "local",
    "email": "local@ctppo",
    "name": "Local User",
    "role": "owner",
}

# ============================================================================
# MODEL CONFIG
# ============================================================================

# The severity classifier is text-only (DistilBERT on the CVE description) and lives in
# ml/cve_classifier.py. A4 replaced the earlier MultiModalCVEClassifier, which fed the CVSS
# score/vector as inputs — circular, since the severity label is a deterministic threshold
# on that score (it would yield a fake ~100% F1). Honest held-out macro-F1: see
# docs/RESEARCH/A4_SEVERITY_CLASSIFIER.md.
SEVERITY_CLASSES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
DEFAULT_MODEL_DIR = str(Path(__file__).resolve().parent.parent / "models" / "severity_text")


# ============================================================================
# ML MODEL
# ============================================================================

# ============================================================================
# GLOBAL STATE
# ============================================================================

class AppState:
    model = None                 # ml.cve_classifier.SeverityClassifier (loaded lazily)
    tokenizer = None
    device: torch.device = torch.device('cpu')
    loaded: bool = False
    val_f1: float = 0.0

state = AppState()


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class CVEClassifyRequest(BaseModel):
    description: str                       # the model predicts severity from this text
    cve_id: Optional[str] = None


class CVEClassifyResponse(BaseModel):
    cve_id: Optional[str]
    predicted_severity: str
    confidence: float
    probabilities: Dict[str, float]
    processing_time_ms: float


class BatchClassifyRequest(BaseModel):
    cves: List[CVEClassifyRequest]


class BatchClassifyResponse(BaseModel):
    results: List[CVEClassifyResponse]
    total_time_ms: float


class NetworkNode(BaseModel):
    id: str
    is_entry_point: bool = False
    is_critical_asset: bool = False


class NetworkVuln(BaseModel):
    cve_id: str
    source: str
    target: str
    severity: str = "HIGH"
    cvss_score: float = 7.0
    exploitability_score: float = 2.5
    impact_score: float = 4.0
    has_exploit: bool = False


class AttackPathRequest(BaseModel):
    nodes: List[NetworkNode]
    vulnerabilities: List[NetworkVuln]
    max_depth: int = 10


class AttackPathResponse(BaseModel):
    paths: Dict[str, List[Dict]]
    risk_summary: Dict[str, Any]
    processing_time_ms: float


# ============================================================================
# LOCAL USER (no auth — open-source local-first)
# ============================================================================

async def get_current_user() -> dict:
    """There is no authentication. Every request runs as the single local user. Kept as a
    FastAPI dependency so route signatures (and the instance router) are unchanged from
    when this was a multi-user app."""
    return LOCAL_USER


# ============================================================================
# MODEL LOADING
# ============================================================================

def load_model(model_dir: str = DEFAULT_MODEL_DIR) -> bool:
    """Load the text-only severity classifier from a local checkpoint dir.

    Returns True if a checkpoint was found and loaded, False otherwise (the API still
    runs — /api/classify returns 503 until a model is trained via ml/train_severity.py).
    transformers is imported here, not at module top, so the API loads without it.
    """
    if torch.cuda.is_available():
        state.device = torch.device('cuda')
    elif hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
        state.device = torch.device('mps')
    else:
        state.device = torch.device('cpu')
    try:
        from cve_classifier import load_classifier
        loaded = load_classifier(model_dir, device=state.device)
    except Exception as e:
        print(f"Severity classifier unavailable ({e}); /api/classify will return 503.")
        return False
    if loaded is None:
        print(f"Severity model not found at {model_dir} — train it with ml/train_severity.py.")
        return False
    state.model, state.tokenizer, state.val_f1 = loaded
    state.loaded = True
    print(f"✓ Severity classifier loaded (val_f1: {state.val_f1:.4f})")
    return True

# ============================================================================
# INFERENCE
# ============================================================================

def classify_cve(req: CVEClassifyRequest) -> CVEClassifyResponse:
    if not state.loaded:
        load_model(os.environ.get("MODEL_DIR", DEFAULT_MODEL_DIR))   # lazy load on first use
    if not state.loaded:
        raise HTTPException(503, "Severity model not trained. Run ml/train_severity.py.")

    start = time.time()
    from cve_classifier import predict_severity
    severity, confidence, probs = predict_severity(
        state.model, state.tokenizer, req.description, state.device)
    return CVEClassifyResponse(
        cve_id=req.cve_id,
        predicted_severity=severity,
        confidence=confidence,
        probabilities=probs,
        processing_time_ms=round((time.time() - start) * 1000, 2)
    )


async def lifespan(app: FastAPI):
    # The severity classifier loads lazily on first /api/classify call. Nothing to init.
    yield


app = FastAPI(title="CTPPO API", description="Cyber Threat Prioritization & Path Optimization", version="3.0.0", lifespan=lifespan)

# CORS: an explicit origin allowlist, not "*". Browsers reject `Access-Control-Allow-Origin: *`
# together with credentials, so the wildcard would silently break the session cookie on any
# cross-origin frontend. Configure prod origins via CORS_ORIGINS (comma-separated); the default
# covers local dev (the Vite dev server / common localhost ports).
_DEFAULT_CORS = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000"
CORS_ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", _DEFAULT_CORS).split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Defensive HTTP response headers on every response. (No restrictive CSP here: this app also
# serves FastAPI's interactive /docs, which a `default-src 'none'` policy would break; the SPA
# host applies its own CSP. These headers are safe for a JSON API + docs.)
_HSTS_ENABLED = os.environ.get("COOKIE_SECURE", "false").lower() == "true" or \
    os.environ.get("HSTS", "false").lower() == "true"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    if _HSTS_ENABLED:
        response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    return response

# Instance CRUD (local scan/analysis workspaces). The current-user dependency is the local
# no-auth stub, so all instances belong to the single local user.
app.include_router(create_instance_router(instance_store, get_current_user))




# ============================================================================
# PUBLIC ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    return {"name": "CTPPO API", "version": "3.0.0", "status": "running", "model_loaded": state.loaded}


@app.get("/api/health")
async def health():
    return {"status": "healthy", "model_loaded": state.loaded, "device": str(state.device), "timestamp": datetime.now().isoformat()}


# ============================================================================
# PROTECTED ENDPOINTS
# ============================================================================

@app.get("/api/model/info")
async def model_info(user: dict = Depends(get_current_user)):
    return {"loaded": state.loaded, "device": str(state.device), "classes": SEVERITY_CLASSES,
            "test_f1": round(state.val_f1, 4) if state.loaded else None}


@app.post("/api/classify", response_model=CVEClassifyResponse)
async def classify(req: CVEClassifyRequest, user: dict = Depends(get_current_user)):
    return classify_cve(req)


@app.post("/api/classify/batch", response_model=BatchClassifyResponse)
async def classify_batch(req: BatchClassifyRequest, user: dict = Depends(get_current_user)):
    start = time.time()
    results = [classify_cve(cve) for cve in req.cves]
    return BatchClassifyResponse(results=results, total_time_ms=round((time.time() - start) * 1000, 2))


# --- Canonical attack-path engine helpers (core/attack_graph + algorithms/namoa_star) ---
_threat_provider = None


def _get_threat_provider():
    """Module-level EPSS/KEV provider, loaded once and reused across requests."""
    global _threat_provider
    if _threat_provider is None:
        _threat_provider = ThreatDataProvider()
    return _threat_provider


@app.get("/api/threat-data/status")
async def threat_data_status(user: dict = Depends(get_current_user)):
    """Provenance + staleness of the cached threat feeds (EPSS / KEV / NVD) so a consumer
    can see how fresh the grounding behind an attack-path analysis is. Honest by design:
    a feed older than its TTL is reported ``stale`` (run the refresh job to update)."""
    provider = _get_threat_provider()
    staleness = provider.staleness()
    return {
        "provenance": provider.provenance(),
        "staleness": staleness,
        "any_stale": any(not s.get("fresh") for s in staleness.values()),
    }


def _format_pareto(graph, result):
    """Render a NAMOA* result into the API response shape."""
    from core.uncertainty import path_reachability_band
    paths = []
    for path_ids, cost in result.pareto_paths:
        names = [graph.get_node(nid).name if graph.get_node(nid) else nid for nid in path_ids]
        cost_d = {}
        if hasattr(cost, "values"):
            labels = getattr(cost, "labels", None) or [f"obj{i}" for i in range(len(cost.values))]
            cost_d = {str(l): round(float(x), 4) for l, x in zip(labels, cost.values)}
        # Reachability as a RANGE under unknown edge correlation (Phase 6 / B2): the cost's
        # SUCCESS_PROBABILITY is the independence lower bound; the band's upper bound is the
        # weakest-edge (comonotone) probability. Annotation only — no decision changes.
        band = path_reachability_band(graph, path_ids)
        paths.append({"path": names, "cost": cost_d, "reachability_band": band})
    return {
        "paths": {"pareto_optimal": paths},
        "risk_summary": {
            "num_pareto_paths": len(paths),
            "entry_points": len(graph.entry_points),
            "goal_nodes": len(graph.goal_nodes),
            "nodes": graph.num_nodes,
            "edges": graph.num_edges,
        },
    }


def _graph_and_edgemap_from_request(req: AttackPathRequest, exclude_cves=frozenset()):
    """Build a canonical AttackGraph from the request (typed nodes + data-grounded costs) and an
    edge_map {(src_node_id, tgt_node_id) -> NetworkVuln} for incremental what-if. CVEs in
    ``exclude_cves`` are treated as patched (their edges are omitted)."""
    graph = AttackGraph(name="api_attack_paths")
    id_map = {}
    for n in req.nodes:
        if n.is_entry_point:
            node = EntryPointNode(name=n.id, entry_type="network", access_level=PrivilegeLevel.NONE)
        elif n.is_critical_asset:
            node = GoalNode(name=n.id, goal_type="critical_asset_compromise",
                            required_privileges=PrivilegeLevel.USER, value_to_attacker=9.0)
        else:
            node = AssetNode(name=n.id, asset_type=AssetType.SERVER, hostname=n.id,
                             criticality=5.0, network_zone="internal")
        graph.add_node(node)
        id_map[n.id] = node.id

    provider = _get_threat_provider()
    edge_map = {}
    for v in req.vulnerabilities:
        if v.source not in id_map or v.target not in id_map or v.cve_id in exclude_cves:
            continue
        cost = build_edge_cost(EdgeCostInputs(
            cve_id=v.cve_id, cvss_score=v.cvss_score,
            is_kev=v.has_exploit,        # request's "public exploit exists" signal
            asset_criticality=8.0,
        ), provider=provider)
        s, t = id_map[v.source], id_map[v.target]
        graph.add_edge(s, t, EdgeType.ASSET_REACHES_ASSET, cost)
        edge_map[(s, t)] = v
    return graph, edge_map


def _graph_from_request(req: AttackPathRequest) -> AttackGraph:
    """Build a canonical AttackGraph from the request: typed nodes + data-grounded costs."""
    return _graph_and_edgemap_from_request(req)[0]


def _best_success(result) -> float:
    """Best (most-likely) success probability across a Pareto front — the reachability scalar."""
    best = 0.0
    for _ids, cost in result.pareto_paths:
        labels = list(getattr(cost, "labels", []))
        if "SUCCESS_PROBABILITY" in labels:
            best = max(best, float(cost.values[labels.index("SUCCESS_PROBABILITY")]))
    return round(best, 4)


@app.post("/api/attack-paths/analyze", response_model=AttackPathResponse)
async def analyze_attack_paths(req: AttackPathRequest, user: dict = Depends(get_current_user)):
    start = time.time()
    graph = _graph_from_request(req)
    if not graph.entry_points or not graph.goal_nodes:
        return AttackPathResponse(
            paths={"pareto_optimal": []},
            risk_summary={"num_pareto_paths": 0,
                          "note": "need >=1 entry point and >=1 critical asset"},
            processing_time_ms=round((time.time() - start) * 1000, 2),
        )
    result = run_namoa_star(graph)
    out = _format_pareto(graph, result)
    return AttackPathResponse(paths=out["paths"], risk_summary=out["risk_summary"],
                              processing_time_ms=round((time.time() - start) * 1000, 2))


@app.get("/api/attack-paths/sample")
async def sample_attack_paths(user: dict = Depends(get_current_user)):
    start = time.time()
    graph = create_sample_enterprise_graph()
    result = run_namoa_star(graph)
    out = _format_pareto(graph, result)
    return {"paths": out["paths"], "risk_summary": out["risk_summary"],
            "network": {"nodes": graph.num_nodes, "edges": graph.num_edges},
            "processing_time_ms": round((time.time() - start) * 1000, 2)}


class WhatIfRequest(AttackPathRequest):
    """An attack-path network + the CVE(s) an operator is considering patching (Phase 6 / D4)."""
    patch_cves: List[str] = Field(default_factory=list,
                                  description="CVE ids to simulate patching (remove from the graph)")


@app.post("/api/attack-paths/whatif")
async def whatif_attack_paths(req: WhatIfRequest, user: dict = Depends(get_current_user)):
    """Exact incremental "what if I patch these CVEs?" — surfaces the D4 engine.

    Returns the before/after Pareto fronts and the reachability reduction. If none of the patched
    CVEs lie on the baseline Pareto front, the front is **provably unchanged** and we say so without
    re-searching (`skipped_recompute=True`) — the D4 exact skip rule.
    """
    from evaluation.d4_incremental import whatif_front
    start = time.time()
    graph, edge_map = _graph_and_edgemap_from_request(req)
    if not graph.entry_points or not graph.goal_nodes:
        return {"paths": {"pareto_optimal": []},
                "risk_summary": {"num_pareto_paths": 0,
                                 "note": "need >=1 entry point and >=1 critical asset"},
                "processing_time_ms": round((time.time() - start) * 1000, 2)}

    def _recompute(patched):
        g2, _ = _graph_and_edgemap_from_request(req, exclude_cves=patched)
        return run_namoa_star(g2)

    before, after, skipped = whatif_front(graph, edge_map, req.patch_cves, _recompute)
    before_best, after_best = _best_success(before), _best_success(after)
    after_graph = graph if skipped else _graph_and_edgemap_from_request(
        req, exclude_cves=set(req.patch_cves))[0]
    out = _format_pareto(after_graph, after)
    out["whatif"] = {
        "patched_cves": req.patch_cves,
        "skipped_recompute": skipped,
        "skip_reason": ("patched CVEs are on no Pareto path — front provably unchanged (D4 skip)"
                        if skipped else None),
        "before_num_paths": len(before.pareto_paths),
        "after_num_paths": len(after.pareto_paths),
        "before_reachability": before_best,
        "after_reachability": after_best,
        "reachability_reduction": round(max(0.0, before_best - after_best), 4),
    }
    out["processing_time_ms"] = round((time.time() - start) * 1000, 2)
    return out


class IntegrationExportRequest(AttackPathRequest):
    """A network to analyze + export to a SIEM/ticketing schema (Phase 6 / G2)."""
    format: str = Field("ecs", description="ecs | cef | ticket")
    webhook_url: Optional[str] = Field(None, description="optional URL to POST the payload to")


@app.post("/api/integrations/export")
async def integrations_export(req: IntegrationExportRequest, user: dict = Depends(get_current_user)):
    """Analyze a network and export the findings to a SIEM/ticketing schema (ECS, CEF, or ticket).

    Formats only; with no `webhook_url` it returns the payload without delivering (honest no-op —
    real delivery needs the operator's endpoint/credentials). G2 integration hook.
    """
    from evaluation.baseline_comparison import pareto_critical_vulns
    from evaluation.d4_incremental import whatif_front
    from integrations.exporters import to_ecs_events, to_cef, to_ticket, dispatch_webhook
    start = time.time()
    fmt = (req.format or "ecs").lower()
    if fmt not in {"ecs", "cef", "ticket"}:
        raise HTTPException(status_code=400, detail="format must be ecs | cef | ticket")

    graph, edge_map = _graph_and_edgemap_from_request(req)
    if not graph.entry_points or not graph.goal_nodes:
        raise HTTPException(status_code=422, detail="need >=1 entry point and >=1 critical asset")
    result = run_namoa_star(graph)
    out = _format_pareto(graph, result)

    crit = pareto_critical_vulns(edge_map, result.pareto_paths)
    top_fix = crit.most_common(1)[0][0] if crit else None
    reduction = None
    if top_fix:
        before, after, _ = whatif_front(
            graph, edge_map, [top_fix],
            lambda patched: run_namoa_star(_graph_and_edgemap_from_request(req, exclude_cves=patched)[0]))
        reduction = round(max(0.0, _best_success(before) - _best_success(after)), 4)

    if fmt == "ecs":
        payload = to_ecs_events(out, recommended_fix=top_fix)
    elif fmt == "cef":
        payload = [to_cef(e) for e in to_ecs_events(out, recommended_fix=top_fix)]
    else:
        payload = to_ticket(out, recommended_fix=top_fix, reachability_reduction=reduction)

    dispatch = dispatch_webhook(payload, url=req.webhook_url)
    return {
        "format": fmt,
        "recommended_fix": top_fix,
        "reachability_reduction": reduction,
        "payload": payload,
        "dispatch": dispatch,
        "processing_time_ms": round((time.time() - start) * 1000, 2),
    }


class ScanImportRequest(BaseModel):
    """Raw scanner-output XML to import into an attack graph (Phase 3b)."""
    xml: str = Field(..., description="Nessus/Qualys/OpenVAS/nmap scan file contents")
    format: str = Field("auto", description="auto | nessus | qualys | openvas | nmap")
    reachability: str = Field("subnet", description="inferred topology policy: subnet | full_mesh")


@app.post("/api/scan/import")
async def import_scan(req: ScanImportRequest, user: dict = Depends(get_current_user)):
    """Import a vulnerability-scanner output file and return Pareto attack paths.

    Host vulnerabilities are data-grounded (from the scan + EPSS/KEV); the topology
    (reachability/zones/entry/goal) is inferred and flagged — see `scan.topology_inferred`.
    """
    from scanners.scan_import import parse_scan, findings_to_network_spec
    from core.network_builder import build_network
    start = time.time()
    try:
        fmt, findings = parse_scan(req.xml, fmt=req.format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    spec = findings_to_network_spec(findings, name="api_scan_import",
                                    reachability=req.reachability)
    if not spec.hosts:
        raise HTTPException(status_code=422, detail="no hosts/vulnerabilities found in scan")
    graph = build_network(spec, provider=_get_threat_provider())
    result = run_namoa_star(graph)
    out = _format_pareto(graph, result)
    vulns = [v for h in spec.hosts for v in h.vulnerabilities]
    out["scan"] = {
        "format": fmt,
        "hosts": len(spec.hosts),
        "vulnerabilities": len(vulns),
        "findings": len(findings),
        "topology_inferred": True,
        "note": "host vulnerabilities are from the scan; reachability/zones/entry/goal are "
                "inferred heuristics, not in the scan file",
    }
    out["processing_time_ms"] = round((time.time() - start) * 1000, 2)
    return out


# Store scan results for attack path generation
SCAN_RESULTS_CACHE: Dict[str, dict] = {}


@app.post("/api/attack-paths/from-scan")
async def attack_paths_from_scan(target: str, user: dict = Depends(get_current_user)):
    """
    Generate attack paths by scanning a target first.
    
    Creates multiple attack path scenarios:
    1. Individual vulnerability paths (each vuln = 1 attack vector)
    2. Severity-grouped paths (all HIGH vulns, all MEDIUM vulns)
    3. Multi-hop paths if backend services detected
    """
    start = time.time()
    
    # First, perform a scan
    simple = SimpleScanner()
    parsed = urllib.parse.urlparse(target if '://' in target else f'http://{target}')
    host = parsed.netloc or parsed.path
    host = host.split(':')[0]
    
    # Scan the host
    host_result = simple.scan_host(host)
    
    # Get web vulnerabilities
    url = target if '://' in target else f'http://{target}'
    web_vulns = simple.check_http_security_headers(url) or []
    
    # Check SSL if applicable
    if 'https' in url or ':443' in target:
        ssl_vulns = simple.check_ssl_vulnerabilities(host, 443) or []
        web_vulns.extend(ssl_vulns)
    
    # Ensure ports is a list
    ports = host_result.ports if host_result.ports else []
    
    # Create host ID
    host_id = f"host_{host.replace('.', '_').replace('-', '_')}"
    
    # Categorize vulnerabilities by severity
    critical_vulns = [v for v in web_vulns if v.get('severity', '').upper() == 'CRITICAL']
    high_vulns = [v for v in web_vulns if v.get('severity', '').upper() == 'HIGH']
    medium_vulns = [v for v in web_vulns if v.get('severity', '').upper() == 'MEDIUM']
    low_vulns = [v for v in web_vulns if v.get('severity', '').upper() == 'LOW']
    
    # Calculate counts
    critical_count = len(critical_vulns)
    high_count = len(high_vulns)
    medium_count = len(medium_vulns)
    low_count = len(low_vulns)
    
    # Determine overall risk
    if critical_count > 0:
        overall_risk = "CRITICAL"
    elif high_count > 0:
        overall_risk = "HIGH"
    elif medium_count > 0:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"
    
    # Check for backend services
    has_db = any(p.get('service', '') in ['mysql', 'postgresql', 'mongodb', 'redis'] for p in ports)
    has_ssh = any(p.get('service', '') == 'ssh' for p in ports)
    
    # Build network nodes
    nodes = ["internet", host_id]
    entry_points = ["internet"]
    critical_assets = [host_id]
    
    if has_db:
        nodes.append("database")
        critical_assets.append("database")
    
    # Build network edges
    network = {
        "nodes": nodes,
        "entry_points": entry_points,
        "critical_assets": critical_assets,
        "edges": {"internet": []}
    }
    
    # Add edges for all vulnerabilities
    for i, vuln in enumerate(web_vulns):
        severity = vuln.get('severity', 'LOW').upper()
        cvss = {'CRITICAL': 9.5, 'HIGH': 7.5, 'MEDIUM': 5.0, 'LOW': 2.5, 'INFO': 1.0}.get(severity, 2.5)
        network["edges"]["internet"].append({
            "target": host_id,
            "cve_id": vuln.get('id', f'VULN-{i}'),
            "severity": severity,
            "cvss_score": cvss
        })
    
    # =========================================================================
    # GENERATE MULTIPLE ATTACK PATHS
    # =========================================================================
    paths = {}
    path_counter = 1
    
    # INDIVIDUAL VULNERABILITY PATHS
    # Each vulnerability represents a distinct attack vector
    for vuln in web_vulns:
        severity = vuln.get('severity', 'LOW').upper()
        cvss = {'CRITICAL': 9.5, 'HIGH': 7.5, 'MEDIUM': 5.0, 'LOW': 2.5, 'INFO': 1.0}.get(severity, 2.5)
        vuln_name = vuln.get('name', 'Unknown')[:35]
        
        paths[f"Attack {path_counter}: {vuln_name}"] = [{
            "vulnerabilities": [{
                "cve_id": vuln.get('id', 'UNKNOWN'),
                "name": vuln.get('name', 'Unknown'),
                "source": "internet",
                "target": host_id,
                "severity": severity,
                "cvss_score": cvss,
                "description": vuln.get('description', '')
            }],
            "risk_score": cvss,
            "total_cvss": cvss,
            "hop_count": 1,
            "path_nodes": ["internet", host_id],
            "attack_type": "single_vector"
        }]
        path_counter += 1
    
    # COMBINED HIGH SEVERITY PATH
    if high_vulns or critical_vulns:
        high_severity_vulns = critical_vulns + high_vulns
        path_vulns = []
        for vuln in high_severity_vulns:
            severity = vuln.get('severity', 'HIGH').upper()
            cvss = {'CRITICAL': 9.5, 'HIGH': 7.5}.get(severity, 7.5)
            path_vulns.append({
                "cve_id": vuln.get('id', 'UNKNOWN'),
                "name": vuln.get('name', 'High Severity Vulnerability'),
                "source": "internet",
                "target": host_id,
                "severity": severity,
                "cvss_score": cvss
            })
        
        if path_vulns:
            max_cvss = max(v["cvss_score"] for v in path_vulns)
            paths["⚠️ Critical Path: All High Severity"] = [{
                "vulnerabilities": path_vulns,
                "risk_score": max_cvss,
                "total_cvss": sum(v["cvss_score"] for v in path_vulns),
                "hop_count": 1,
                "path_nodes": ["internet", host_id],
                "attack_type": "high_severity_combined",
                "description": f"Combined attack using {len(path_vulns)} high-severity vulnerabilities"
            }]
    
    # MULTI-HOP PATH TO DATABASE (if database detected)
    if has_db and web_vulns:
        network["edges"][host_id] = []
        # Add edge from host to database
        network["edges"][host_id].append({
            "target": "database",
            "cve_id": "DB-ACCESS",
            "severity": "CRITICAL",
            "cvss_score": 9.0
        })
        
        # Build multi-hop path
        top_vuln = max(web_vulns, key=lambda v: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(v.get('severity', '').upper(), 0))
        severity = top_vuln.get('severity', 'MEDIUM').upper()
        
        path_vulns = [
            {
                "cve_id": top_vuln.get('id', 'WEB-EXPLOIT'),
                "name": top_vuln.get('name', 'Web Application Compromise'),
                "source": "internet",
                "target": host_id,
                "severity": severity,
                "cvss_score": {'CRITICAL': 9.5, 'HIGH': 7.5, 'MEDIUM': 5.0, 'LOW': 2.5}.get(severity, 5.0)
            },
            {
                "cve_id": "DB-LATERAL-MOVE",
                "name": "Database Lateral Movement",
                "source": host_id,
                "target": "database",
                "severity": "CRITICAL",
                "cvss_score": 9.0
            }
        ]
        
        paths["🔴 Critical: Web → Database Attack Chain"] = [{
            "vulnerabilities": path_vulns,
            "risk_score": 9.0,
            "total_cvss": sum(v["cvss_score"] for v in path_vulns),
            "hop_count": 2,
            "path_nodes": ["internet", host_id, "database"],
            "attack_type": "multi_hop",
            "description": "Attacker compromises web server then pivots to database"
        }]
    
    # STEALTH PATH (Low severity chain)
    if len(low_vulns) >= 2:
        path_vulns = []
        for vuln in low_vulns[:3]:
            path_vulns.append({
                "cve_id": vuln.get('id', 'UNKNOWN'),
                "name": vuln.get('name', 'Information Disclosure'),
                "source": "internet",
                "target": host_id,
                "severity": "LOW",
                "cvss_score": 2.5
            })
        
        paths["🔵 Stealth: Low-Severity Recon Path"] = [{
            "vulnerabilities": path_vulns,
            "risk_score": 2.5,
            "total_cvss": sum(v["cvss_score"] for v in path_vulns),
            "hop_count": 1,
            "path_nodes": ["internet", host_id],
            "attack_type": "stealth",
            "description": "Information gathering using low-severity issues (harder to detect)"
        }]
    
    # Calculate summary
    total_paths = len(paths)
    critical_path_count = sum(1 for p in paths.values() if any(v.get('severity') == 'CRITICAL' for v in p[0]['vulnerabilities']))
    high_path_count = sum(1 for p in paths.values() if any(v.get('severity') == 'HIGH' for v in p[0]['vulnerabilities']))
    
    summary = {
        "total_paths": total_paths,
        "critical_paths": critical_path_count,
        "high_paths": high_path_count,
        "total_vulnerabilities": len(web_vulns),
        "overall_risk": overall_risk,
        "severity_breakdown": {
            "CRITICAL": critical_count,
            "HIGH": high_count,
            "MEDIUM": medium_count,
            "LOW": low_count
        },
        "namoa_analysis": {
            "individual_vectors": len(web_vulns),
            "combined_paths": total_paths - len(web_vulns),
            "multi_hop_paths": 1 if has_db else 0
        }
    }
    
    return {
        "scan_id": f"scan_{int(time.time())}",
        "target": target,
        "network": network,
        "paths": paths,
        "risk_summary": summary,
        "scan_summary": {
            "host": host,
            "open_ports": len(ports),
            "vulnerabilities_found": len(web_vulns),
            "has_database": has_db,
            "has_ssh": has_ssh
        },
        "processing_time_ms": round((time.time() - start) * 1000, 2)
    }


# ============================================================================
# REAL VULNERABILITY SCANNING ENDPOINTS
# ============================================================================

# Import real scanner
try:
    from real_scanner import VulnerabilityScanner
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False
    print("⚠️ Real scanner not available, using SimpleScanner")


class SimpleScanner:
    """Simple vulnerability scanner that works without external tools."""
    
    # Known cloud providers and their characteristics
    CLOUD_PROVIDERS = {
        'vercel': {
            'domains': ['vercel.app', 'vercel.com', 'now.sh'],
            'headers': ['x-vercel-id', 'x-vercel-cache'],
            'server_patterns': ['Vercel'],
            'expected_ports': [80, 443],  # Only these are actually open
            'note': 'Vercel is a serverless platform. Ports like SSH, MySQL are NOT actually exposed - they appear open due to CDN/edge network behavior.'
        },
        'netlify': {
            'domains': ['netlify.app', 'netlify.com'],
            'headers': ['x-nf-request-id'],
            'server_patterns': ['Netlify'],
            'expected_ports': [80, 443],
            'note': 'Netlify is a JAMstack platform. Only HTTP/HTTPS ports are actually exposed.'
        },
        'aws_cloudfront': {
            'domains': ['cloudfront.net', 'amazonaws.com'],
            'headers': ['x-amz-cf-id', 'x-amz-cf-pop'],
            'server_patterns': ['CloudFront', 'AmazonS3'],
            'expected_ports': [80, 443],
            'note': 'AWS CloudFront CDN. Backend ports are not directly exposed.'
        },
        'cloudflare': {
            'domains': ['cloudflare.com'],
            'headers': ['cf-ray', 'cf-cache-status'],
            'server_patterns': ['cloudflare'],
            'expected_ports': [80, 443],
            'note': 'Cloudflare CDN/WAF. Many ports may appear open due to proxy behavior.'
        },
        'github_pages': {
            'domains': ['github.io', 'githubusercontent.com'],
            'headers': [],
            'server_patterns': ['GitHub.com'],
            'expected_ports': [80, 443],
            'note': 'GitHub Pages serves static content only via HTTP/HTTPS.'
        },
        'heroku': {
            'domains': ['herokuapp.com'],
            'headers': ['via'],
            'server_patterns': ['heroku'],
            'expected_ports': [80, 443],
            'note': 'Heroku PaaS. Only web dynos are exposed via HTTP/HTTPS.'
        },
        'firebase': {
            'domains': ['web.app', 'firebaseapp.com'],
            'headers': [],
            'server_patterns': ['Google Frontend'],
            'expected_ports': [80, 443],
            'note': 'Firebase Hosting serves static content via Google\'s edge network.'
        }
    }
    
    def __init__(self):
        self.detected_provider = None
        self.provider_note = None
    
    def detect_cloud_provider(self, host: str, headers: dict = None) -> dict:
        """Detect if host is on a known cloud provider."""
        result = {
            'is_cloud': False,
            'provider': None,
            'note': None,
            'expected_ports': None
        }
        
        # Check domain patterns
        host_lower = host.lower()
        for provider, info in self.CLOUD_PROVIDERS.items():
            # Check domain
            for domain in info['domains']:
                if domain in host_lower:
                    result['is_cloud'] = True
                    result['provider'] = provider
                    result['note'] = info['note']
                    result['expected_ports'] = info['expected_ports']
                    return result
            
            # Check headers if provided
            if headers:
                for header in info['headers']:
                    if header.lower() in [h.lower() for h in headers.keys()]:
                        result['is_cloud'] = True
                        result['provider'] = provider
                        result['note'] = info['note']
                        result['expected_ports'] = info['expected_ports']
                        return result
                
                # Check server header pattern
                server = headers.get('Server', headers.get('server', ''))
                for pattern in info['server_patterns']:
                    if pattern.lower() in server.lower():
                        result['is_cloud'] = True
                        result['provider'] = provider
                        result['note'] = info['note']
                        result['expected_ports'] = info['expected_ports']
                        return result
        
        return result
    
    def scan_host(self, host: str, cloud_info: dict = None):
        """Scan a host for open ports using socket."""
        import socket
        from dataclasses import dataclass, field
        
        @dataclass
        class HostResult:
            host: str
            ports: list
            cloud_provider: str = None
            cloud_note: str = None
            is_cloud_hosted: bool = False
            
            def to_dict(self):
                return {
                    "host": self.host, 
                    "ports": self.ports,
                    "cloud_provider": self.cloud_provider,
                    "cloud_note": self.cloud_note,
                    "is_cloud_hosted": self.is_cloud_hosted
                }
        
        # First, detect cloud provider from domain
        if not cloud_info:
            cloud_info = self.detect_cloud_provider(host)
        
        # Define ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
        open_ports = []
        raw_open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((host, port))
                if result == 0:
                    raw_open_ports.append(port)
                sock.close()
            except:
                pass
        
        # Filter ports based on cloud provider knowledge
        if cloud_info and cloud_info['is_cloud']:
            expected = cloud_info.get('expected_ports', [])
            
            for port in raw_open_ports:
                service = self._get_service_name(port)
                is_expected = port in expected
                
                # For cloud providers, only report expected ports as truly open
                # Others are marked as "filtered/proxy"
                if is_expected:
                    open_ports.append({
                        "port": port,
                        "state": "open",
                        "service": service,
                        "version": "",
                        "note": ""
                    })
                else:
                    # These appear open but are likely CDN/proxy responses
                    open_ports.append({
                        "port": port,
                        "state": "open (proxy/CDN)",
                        "service": service,
                        "version": "",
                        "note": f"⚠️ Likely false positive - {cloud_info['provider']} CDN response"
                    })
            
            return HostResult(
                host=host, 
                ports=open_ports,
                cloud_provider=cloud_info['provider'],
                cloud_note=cloud_info['note'],
                is_cloud_hosted=True
            )
        else:
            # Non-cloud host - report all open ports
            for port in raw_open_ports:
                service = self._get_service_name(port)
                open_ports.append({
                    "port": port,
                    "state": "open",
                    "service": service,
                    "version": ""
                })
            
            return HostResult(host=host, ports=open_ports)
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for port."""
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
            993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 8080: "http-proxy", 8443: "https-alt"
        }
        return services.get(port, "unknown")
    
    def check_http_security_headers(self, url: str) -> list:
        """Check HTTP security headers."""
        import urllib.request
        import ssl
        
        vulns = []
        
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(url, headers={'User-Agent': 'CTPPO-Scanner/3.0'})
            response = urllib.request.urlopen(req, timeout=10, context=ctx)
            headers = dict(response.headers)
            
            # Detect cloud provider from response headers
            cloud_info = self.detect_cloud_provider(url, headers)
            self.detected_provider = cloud_info.get('provider')
            self.provider_note = cloud_info.get('note')
            
            # Check for missing security headers
            security_headers = {
                'Strict-Transport-Security': ('HIGH', 'Missing HSTS header - vulnerable to downgrade attacks'),
                'X-Content-Type-Options': ('MEDIUM', 'Missing X-Content-Type-Options - vulnerable to MIME sniffing'),
                'X-Frame-Options': ('MEDIUM', 'Missing X-Frame-Options - vulnerable to clickjacking'),
                'Content-Security-Policy': ('MEDIUM', 'Missing CSP header - vulnerable to XSS'),
                'X-XSS-Protection': ('LOW', 'Missing X-XSS-Protection header'),
                'Referrer-Policy': ('LOW', 'Missing Referrer-Policy header'),
            }
            
            for header, (severity, description) in security_headers.items():
                if header.lower() not in [h.lower() for h in headers.keys()]:
                    vulns.append({
                        'id': f'HEADER-{header.upper().replace("-", "_")}',
                        'name': f'Missing {header}',
                        'severity': severity,
                        'description': description,
                        'url': url,
                        'solution': f'Add the {header} header to your server configuration'
                    })
            
            # Check for information disclosure
            server_header = headers.get('Server', '')
            if server_header:
                vulns.append({
                    'id': 'INFO-SERVER-DISCLOSURE',
                    'name': 'Server Version Disclosure',
                    'severity': 'LOW',
                    'description': f'Server header reveals: {server_header}',
                    'url': url,
                    'solution': 'Remove or obfuscate the Server header'
                })
            
            x_powered = headers.get('X-Powered-By', '')
            if x_powered:
                vulns.append({
                    'id': 'INFO-POWERED-BY',
                    'name': 'Technology Disclosure',
                    'severity': 'LOW',
                    'description': f'X-Powered-By reveals: {x_powered}',
                    'url': url,
                    'solution': 'Remove the X-Powered-By header'
                })
                
        except Exception as e:
            vulns.append({
                'id': 'SCAN-ERROR',
                'name': 'Scan Error',
                'severity': 'INFO',
                'description': f'Could not complete scan: {str(e)}',
                'url': url,
                'solution': 'Check if the target is accessible'
            })
        
        return vulns
    
    def check_ssl_vulnerabilities(self, host: str, port: int = 443) -> list:
        """Check SSL/TLS vulnerabilities."""
        import ssl
        import socket
        
        vulns = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    
                    # Check TLS version
                    if version in ['TLSv1', 'TLSv1.0']:
                        vulns.append({
                            'id': 'SSL-WEAK-TLS10',
                            'name': 'Weak TLS Version',
                            'severity': 'HIGH',
                            'description': f'Server uses outdated {version}',
                            'url': f'https://{host}:{port}',
                            'solution': 'Upgrade to TLS 1.2 or higher'
                        })
                    elif version == 'TLSv1.1':
                        vulns.append({
                            'id': 'SSL-WEAK-TLS11',
                            'name': 'Deprecated TLS Version',
                            'severity': 'MEDIUM',
                            'description': f'Server uses deprecated {version}',
                            'url': f'https://{host}:{port}',
                            'solution': 'Upgrade to TLS 1.2 or higher'
                        })
                    
                    # Check certificate expiry
                    if cert:
                        from datetime import datetime
                        not_after = cert.get('notAfter', '')
                        if not_after:
                            try:
                                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                days_left = (expiry - datetime.now()).days
                                if days_left < 0:
                                    vulns.append({
                                        'id': 'SSL-CERT-EXPIRED',
                                        'name': 'Expired SSL Certificate',
                                        'severity': 'CRITICAL',
                                        'description': f'Certificate expired {abs(days_left)} days ago',
                                        'url': f'https://{host}:{port}',
                                        'solution': 'Renew the SSL certificate immediately'
                                    })
                                elif days_left < 30:
                                    vulns.append({
                                        'id': 'SSL-CERT-EXPIRING',
                                        'name': 'SSL Certificate Expiring Soon',
                                        'severity': 'MEDIUM',
                                        'description': f'Certificate expires in {days_left} days',
                                        'url': f'https://{host}:{port}',
                                        'solution': 'Renew the SSL certificate'
                                    })
                            except:
                                pass
                                
        except ssl.SSLCertVerificationError as e:
            vulns.append({
                'id': 'SSL-CERT-INVALID',
                'name': 'Invalid SSL Certificate',
                'severity': 'HIGH',
                'description': f'Certificate verification failed: {str(e)}',
                'url': f'https://{host}:{port}',
                'solution': 'Install a valid SSL certificate'
            })
        except Exception as e:
            pass
        
        return vulns

# Global scanner instance
_scanner = None

def get_scanner():
    global _scanner
    if _scanner is None and SCANNER_AVAILABLE:
        zap_url = os.environ.get("ZAP_URL")
        zap_key = os.environ.get("ZAP_API_KEY")
        _scanner = VulnerabilityScanner(zap_url, zap_key)
    return _scanner


class ScanRequest(BaseModel):
    """Request model for vulnerability scan."""
    target: str = Field(..., description="URL, IP, or hostname to scan")
    scan_type: str = Field(default="quick", description="Scan type: quick, full, or vuln")
    include_web_scan: bool = Field(default=True, description="Include web application scanning")


class ScanStatusResponse(BaseModel):
    """Response model for scan capabilities."""
    scanner_available: bool
    nmap_available: bool
    zap_available: bool
    simple_scanner: bool = True


@app.get("/api/scan/capabilities", response_model=ScanStatusResponse)
async def get_scan_capabilities(user: dict = Depends(get_current_user)):
    """Check what scanning capabilities are available."""
    import subprocess
    
    # Check if nmap is installed on the system
    nmap_available = False
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
        nmap_available = result.returncode == 0
    except:
        pass
    
    # Check if ZAP is running (default port 8080)
    zap_available = False
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('localhost', 8080))
        # Be careful - 8080 might be our own frontend proxy
        # ZAP usually runs on 8080, but we should verify it's actually ZAP
        zap_available = False  # Conservative: only mark true if we can verify ZAP API
        sock.close()
    except:
        pass
    
    # SimpleScanner is ALWAYS available (built-in)
    return ScanStatusResponse(
        scanner_available=True,  # SimpleScanner is always available!
        nmap_available=nmap_available,
        zap_available=zap_available,
        simple_scanner=True
    )


@app.post("/api/scan/target")
async def scan_target(req: ScanRequest, user: dict = Depends(get_current_user)):
    """
    Perform a real vulnerability scan on a target.
    
    Supports:
    - Network scanning (port discovery, service detection)
    - Web application scanning (security headers, SSL, common vulns)
    - CVE correlation
    - Cloud provider detection
    """
    scanner = get_scanner()
    
    if not scanner:
        # Fallback to simple scanner
        simple = SimpleScanner()
        start = time.time()
        
        try:
            # Parse target
            import urllib.parse
            parsed = urllib.parse.urlparse(req.target if '://' in req.target else f'http://{req.target}')
            host = parsed.netloc or parsed.path
            host = host.split(':')[0]
            
            # Check web vulnerabilities first to detect cloud provider
            web_vulns = []
            cloud_info = None
            
            if req.include_web_scan:
                url = req.target if '://' in req.target else f'http://{req.target}'
                web_vulns = simple.check_http_security_headers(url) or []
                
                # Get cloud provider info from the header check
                cloud_info = simple.detect_cloud_provider(host)
                if simple.detected_provider:
                    cloud_info['provider'] = simple.detected_provider
                    cloud_info['note'] = simple.provider_note
                    cloud_info['is_cloud'] = True
                
                # SSL checks
                if 'https' in url or ':443' in req.target:
                    ssl_vulns = simple.check_ssl_vulnerabilities(host, 443) or []
                    web_vulns.extend(ssl_vulns)
            
            # Scan host with cloud provider awareness
            host_result = simple.scan_host(host, cloud_info)
            
            # Ensure ports is a list
            ports = host_result.ports if host_result.ports else []
            
            # Calculate risk based on actual vulnerabilities
            critical_count = sum(1 for v in web_vulns if v.get('severity', '').upper() == 'CRITICAL')
            high_count = sum(1 for v in web_vulns if v.get('severity', '').upper() == 'HIGH')
            medium_count = sum(1 for v in web_vulns if v.get('severity', '').upper() == 'MEDIUM')
            low_count = sum(1 for v in web_vulns if v.get('severity', '').upper() == 'LOW')
            info_count = sum(1 for v in web_vulns if v.get('severity', '').upper() == 'INFO')
            
            # Determine risk level
            if critical_count > 0:
                risk_level = 'CRITICAL'
            elif high_count > 0:
                risk_level = 'HIGH'
            elif medium_count > 0:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'
            
            # Count actual open ports (not CDN false positives)
            actual_open_ports = len([p for p in ports if 'proxy' not in p.get('state', '')])
            
            # Build recommendation
            recommendations = []
            if critical_count > 0:
                recommendations.append(f"URGENT: Address {critical_count} critical vulnerabilities immediately")
            if high_count > 0:
                recommendations.append(f"Address {high_count} high severity issues soon")
            if medium_count > 0:
                recommendations.append(f"Review {medium_count} medium severity findings")
            if not recommendations:
                recommendations.append("No critical issues found. Continue monitoring.")
            
            # Build response
            response = {
                "target": req.target,
                "scan_type": req.scan_type,
                "started_at": datetime.now().isoformat(),
                "completed_at": datetime.now().isoformat(),
                "hosts": [host_result.to_dict()],
                "web_vulnerabilities": web_vulns,
                "vulnerabilities": web_vulns,  # Alias for PDF generator
                "cve_matches": [],
                "risk_summary": {
                    "risk_level": risk_level,
                    "total_hosts": 1,
                    "total_open_ports": actual_open_ports,
                    "total_vulnerabilities": len(web_vulns),
                    "vulnerabilities": {
                        "critical": critical_count,
                        "high": high_count,
                        "medium": medium_count,
                        "low": low_count,
                        "info": info_count,
                        "total": len(web_vulns)
                    },
                    "severity_breakdown": {
                        "CRITICAL": critical_count,
                        "HIGH": high_count,
                        "MEDIUM": medium_count,
                        "LOW": low_count,
                        "INFO": info_count
                    },
                    "recommendations": recommendations,
                    "recommendation": "; ".join(recommendations)
                },
                "processing_time_ms": round((time.time() - start) * 1000, 2),
                "scanner_used": "simple"
            }
            
            # Add cloud provider notice if detected
            if host_result.is_cloud_hosted:
                response["cloud_provider"] = {
                    "detected": True,
                    "name": host_result.cloud_provider,
                    "note": host_result.cloud_note,
                    "warning": "⚠️ Some port scan results may be affected by CDN/edge network behavior"
                }
                response["risk_summary"]["cloud_notice"] = host_result.cloud_note
            
            return response
            
        except Exception as e:
            raise HTTPException(500, f"Scan failed: {str(e)}")
    
    # Use full scanner
    try:
        import asyncio
        result = await scanner.scan(req.target, req.scan_type, req.include_web_scan)
        return {**result.to_dict(), "scanner_used": "full"}
    except Exception as e:
        raise HTTPException(500, f"Scan failed: {str(e)}")


@app.post("/api/scan/quick")
async def quick_scan(target: str, user: dict = Depends(get_current_user)):
    """Quick port scan of a target."""
    req = ScanRequest(target=target, scan_type="quick", include_web_scan=True)
    return await scan_target(req, user)


# ============================================================================
# PDF REPORT GENERATION
# ============================================================================

from fastapi.responses import Response

try:
    from pdf_generator import SecurityReportGenerator
    PDF_AVAILABLE = True
    pdf_generator = SecurityReportGenerator()
except ImportError:
    PDF_AVAILABLE = False
    pdf_generator = None
    print("⚠️ PDF generator not available")


@app.post("/api/reports/scan-pdf")
async def generate_scan_pdf(scan_data: dict, user: dict = Depends(get_current_user)):
    """Generate PDF report from scan results."""
    if not PDF_AVAILABLE:
        raise HTTPException(503, "PDF generation not available. Install reportlab: pip install reportlab")
    
    try:
        pdf_bytes = pdf_generator.generate_scan_report(scan_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=ctppo-scan-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(500, f"Failed to generate PDF: {str(e)}")


@app.post("/api/reports/attack-path-pdf")
async def generate_attack_path_pdf(path_data: dict, user: dict = Depends(get_current_user)):
    """Generate PDF report from attack path analysis."""
    if not PDF_AVAILABLE:
        raise HTTPException(503, "PDF generation not available")
    
    try:
        pdf_bytes = pdf_generator.generate_attack_path_report(path_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=ctppo-attack-path-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(500, f"Failed to generate PDF: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)




