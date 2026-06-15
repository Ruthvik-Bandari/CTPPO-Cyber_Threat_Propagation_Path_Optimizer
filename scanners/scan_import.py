"""
Scanner Import Adapter (Phase 3b)
=================================

Imports the **output files** of the vulnerability scanners orgs already run
(Nessus / Qualys / OpenVAS-GVM / nmap), and turns them into the canonical
``core.network_builder.NetworkSpec`` → ``build_network`` → ``AttackGraph``. This is the
realistic enterprise / CI-CD ingestion path (you don't re-run a scan, you import the
artifact it produced), and it closes the critique's **G1** repo-scan→graph gap.

What is data-grounded vs inferred (honesty — same discipline as the rest of CTPPO):

- **Data-grounded (from the scan):** which hosts exist, and which CVEs each host has.
  CVSS comes from the scan when present (else enriched from the local NVD cache, 3a);
  EPSS/KEV are looked up by CVE id at ``build_network`` time via the real cost model.
- **INFERRED (NOT in any scan file):** host-to-host **reachability/topology**, network
  **zones**, which host is **internet-facing**, and which host is the **goal**. Scanners
  report per-host findings, not network structure — so these come from documented
  heuristics (subnet grouping, well-known service ports) and are clearly flagged. They
  can (and for real use *should*) be overridden with ground truth. This is the same
  bounded-heuristic situation as the lateral-movement prior (B3): the data-grounded vuln
  edges dominate the ranking; the inferred topology moves magnitude, not usually the
  decision.

Pure stdlib XML parsing (no scanner binary, no network) → fully reproducible & testable
offline. Namespaces are handled by matching on local tag names.

Author: CTPPO
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.network_builder import NetworkSpec, HostSpec, VulnSpec, build_network
from core.node_types import AssetType
from core.threat_feeds import DEFAULT_NVD_CACHE_DIR, load_nvd_recent

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Well-known service ports → asset type (heuristic, lowest matching port wins).
_PORT_ASSET = {
    3306: AssetType.DATABASE, 5432: AssetType.DATABASE, 1433: AssetType.DATABASE,
    1521: AssetType.DATABASE, 27017: AssetType.DATABASE,
    445: AssetType.FILE_SERVER, 139: AssetType.FILE_SERVER,
    80: AssetType.WEB_APPLICATION, 443: AssetType.WEB_APPLICATION,
    8080: AssetType.WEB_APPLICATION, 8443: AssetType.WEB_APPLICATION,
    25: AssetType.EMAIL_SERVER, 587: AssetType.EMAIL_SERVER,
    110: AssetType.EMAIL_SERVER, 143: AssetType.EMAIL_SERVER, 993: AssetType.EMAIL_SERVER,
    389: AssetType.DOMAIN_CONTROLLER, 636: AssetType.DOMAIN_CONTROLLER, 88: AssetType.DOMAIN_CONTROLLER,
    3389: AssetType.WORKSTATION,
}
_INTERNET_FACING_PORTS = {80, 443, 8080, 8443, 22}


# --- intermediate representation -------------------------------------------------

@dataclass
class ScanFinding:
    """One (host, port, vulnerability) row distilled from a scanner file. ``cve_ids`` may
    be empty (a recon-only open port) — such findings still register the host/service.
    ``product``/``version`` are the service fingerprint (e.g. nmap -sV) for version→CVE
    mapping when the scan reports no CVE directly."""
    host_ip: str
    hostname: str = ""
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    name: str = ""
    port: Optional[int] = None
    service: str = ""
    severity: str = ""
    product: str = ""
    version: str = ""


# --- small XML helpers (namespace-tolerant) -------------------------------------

def _ln(tag: str) -> str:
    """Local name of a (possibly namespaced) tag, e.g. '{ns}result' → 'result'."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _findall(elem, name: str):
    """All descendants whose local tag name == ``name`` (namespace-agnostic)."""
    return [e for e in elem.iter() if _ln(e.tag) == name]


def _children(elem, name: str):
    return [e for e in list(elem) if _ln(e.tag) == name]


def _first_child_text(elem, name: str) -> str:
    for e in list(elem):
        if _ln(e.tag) == name and e.text:
            return e.text.strip()
    return ""


def _to_float(s) -> Optional[float]:
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def _root(xml: str):
    return ET.fromstring(xml.encode("utf-8") if isinstance(xml, str) else xml)


# --- format detection -----------------------------------------------------------

def detect_format(xml: str) -> str:
    """Return one of {'nessus','nmap','qualys','openvas','unknown'} from the document."""
    try:
        root = _root(xml)
    except ET.ParseError:
        return "unknown"
    tag = _ln(root.tag).lower()
    if tag == "nessusclientdata_v2" or _findall(root, "NessusClientData_v2"):
        return "nessus"
    if tag == "nmaprun":
        return "nmap"
    if tag in ("scan", "asset_data_report", "was_scan") or _findall(root, "CVE_ID_LIST"):
        return "qualys"
    if tag in ("report", "get_reports_response") or _findall(root, "nvt"):
        return "openvas"
    # last resort: peek at distinctive child tags
    names = {_ln(e.tag) for e in list(root)}
    if "Report" in names:
        return "nessus"
    return "unknown"


# --- per-format parsers ----------------------------------------------------------

def parse_nmap(xml: str) -> List[ScanFinding]:
    """nmap -oX. CVEs come from NSE vuln scripts (e.g. ``--script vulners``); bare recon
    yields open-port findings with no CVE."""
    root = _root(xml)
    findings: List[ScanFinding] = []
    for host in _findall(root, "host"):
        ip = ""
        for addr in _children(host, "address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
        if not ip:
            continue
        hostname = ""
        for hns in _children(host, "hostnames"):
            for hn in _children(hns, "hostname"):
                hostname = hn.get("name", "") or hostname
                break
        for ports in _children(host, "ports"):
            for port in _children(ports, "port"):
                state = next((s for s in _children(port, "state")), None)
                if state is None or state.get("state") != "open":
                    continue
                portid = int(port.get("portid")) if port.get("portid", "").isdigit() else None
                svc = next((s for s in _children(port, "service")), None)
                service = svc.get("name", "") if svc is not None else ""
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                cves: set = set()
                cvss: Optional[float] = None
                for script in _children(port, "script"):
                    cves.update(m.upper() for m in CVE_RE.findall(script.get("output", "") or ""))
                    for tbl in _findall(script, "table"):  # vulners table rows
                        row = {e.get("key"): (e.text or "").strip() for e in _children(tbl, "elem")}
                        if row.get("id") and CVE_RE.fullmatch(row["id"]):
                            cves.add(row["id"].upper())
                            cvss = cvss or _to_float(row.get("cvss"))
                findings.append(ScanFinding(
                    host_ip=ip, hostname=hostname, cve_ids=sorted(cves),
                    cvss_score=cvss, name=service, port=portid, service=service,
                    product=product, version=version))
        for script in _findall(host, "hostscript"):  # host-level scripts
            for s in _children(script, "script"):
                cves = {m.upper() for m in CVE_RE.findall(s.get("output", "") or "")}
                if cves:
                    findings.append(ScanFinding(host_ip=ip, hostname=hostname,
                                                cve_ids=sorted(cves), name=s.get("id", "")))
    return findings


def parse_nessus(xml: str) -> List[ScanFinding]:
    """Nessus .nessus (NessusClientData_v2)."""
    root = _root(xml)
    findings: List[ScanFinding] = []
    for rh in _findall(root, "ReportHost"):
        name_attr = rh.get("name", "")
        ip, fqdn = "", ""
        for hp in _findall(rh, "HostProperties"):
            for tag in _children(hp, "tag"):
                if tag.get("name") == "host-ip":
                    ip = (tag.text or "").strip()
                elif tag.get("name") in ("host-fqdn", "host-rdns"):
                    fqdn = fqdn or (tag.text or "").strip()
        ip = ip or name_attr
        for item in _children(rh, "ReportItem"):
            cves = [(_ln(c.tag), (c.text or "").strip()) for c in list(item)]
            cve_ids = sorted({v.upper() for t, v in cves if t == "cve" and CVE_RE.fullmatch(v)})
            vector = _first_child_text(item, "cvss3_vector") or _first_child_text(item, "cvss_vector")
            score = (_to_float(_first_child_text(item, "cvss3_base_score"))
                     or _to_float(_first_child_text(item, "cvss_base_score")))
            portid = int(item.get("port")) if (item.get("port") or "").isdigit() else None
            findings.append(ScanFinding(
                host_ip=ip, hostname=fqdn, cve_ids=cve_ids, cvss_score=score,
                cvss_vector=_normalize_vector(vector), name=item.get("pluginName", ""),
                port=portid, service=item.get("svc_name", ""), severity=item.get("severity", "")))
    return findings


def parse_qualys(xml: str) -> List[ScanFinding]:
    """Qualys VM scan results (<SCAN>/<IP>/<VULNS>/<CAT>/<VULN>). The port lives on the
    enclosing <CAT>; VULNs may also appear directly under <IP> (handled as a fallback)."""
    root = _root(xml)
    findings: List[ScanFinding] = []

    def _vuln_finding(vuln, ip, hostname, portid, proto):
        cve_ids = sorted({c.upper() for c in CVE_RE.findall(ET.tostring(vuln, encoding="unicode"))})
        score = (_to_float(_first_child_text(vuln, "CVSS3_BASE"))
                 or _to_float(_first_child_text(vuln, "CVSS_BASE")))
        return ScanFinding(host_ip=ip, hostname=hostname, cve_ids=cve_ids, cvss_score=score,
                           name=_first_child_text(vuln, "TITLE"), port=portid,
                           service=proto, severity=vuln.get("severity", ""))

    for ipnode in _findall(root, "IP"):
        ip = ipnode.get("value", "")
        hostname = ipnode.get("name", "")
        if not ip:
            continue
        seen = set()
        for cat in _findall(ipnode, "CAT"):
            port = cat.get("port", "")
            portid = int(port) if port.isdigit() else None
            for vuln in _children(cat, "VULN"):
                seen.add(id(vuln))
                findings.append(_vuln_finding(vuln, ip, hostname, portid, cat.get("protocol", "")))
        for vuln in _findall(ipnode, "VULN"):  # any VULN not under a CAT
            if id(vuln) not in seen:
                findings.append(_vuln_finding(vuln, ip, hostname, None, ""))
    return findings


def parse_openvas(xml: str) -> List[ScanFinding]:
    """OpenVAS / Greenbone GVM report XML (<report>/.../<result>)."""
    root = _root(xml)
    findings: List[ScanFinding] = []
    for result in _findall(root, "result"):
        host = ""
        for h in _children(result, "host"):
            host = (h.text or "").strip()
            break
        if not host:
            continue
        nvt = next((n for n in _children(result, "nvt")), None)
        cve_ids: set = set()
        score = None
        name = ""
        if nvt is not None:
            name = _first_child_text(nvt, "name")
            score = _to_float(_first_child_text(nvt, "cvss_base"))
            for refs in _findall(nvt, "refs"):
                for ref in _children(refs, "ref"):
                    if (ref.get("type") or "").lower() == "cve" and ref.get("id"):
                        cve_ids.add(ref.get("id").upper())
            cve_ids.update(m.upper() for m in CVE_RE.findall(_first_child_text(nvt, "cve")))
        sev = _first_child_text(result, "severity")
        port_text = _first_child_text(result, "port")          # e.g. "443/tcp" or "general/tcp"
        head = port_text.split("/", 1)[0]
        portid = int(head) if head.isdigit() else None
        findings.append(ScanFinding(
            host_ip=host, cve_ids=sorted(cve_ids), cvss_score=score,
            name=name, port=portid, service=port_text, severity=sev))
    return findings


_PARSERS = {"nmap": parse_nmap, "nessus": parse_nessus,
            "qualys": parse_qualys, "openvas": parse_openvas}


def parse_scan(xml: str, fmt: str = "auto") -> Tuple[str, List[ScanFinding]]:
    """Parse scanner XML into findings. Returns ``(detected_format, findings)``."""
    if fmt == "auto":
        fmt = detect_format(xml)
    parser = _PARSERS.get(fmt)
    if parser is None:
        raise ValueError(f"unsupported/unknown scan format: {fmt!r} "
                         f"(supported: {', '.join(sorted(_PARSERS))})")
    return fmt, parser(xml)


def _normalize_vector(v: str) -> str:
    """Nessus sometimes emits 'AV:N/AC:L/...' without the 'CVSS:3.x/' prefix the cost
    model expects. Add it when the metric letters are present but the prefix is not."""
    v = (v or "").strip()
    if v and not v.upper().startswith("CVSS:") and re.search(r"\bAV:[NALP]\b", v):
        return "CVSS:3.1/" + v
    return v


# --- findings → NetworkSpec ------------------------------------------------------

def _subnet(ip: str) -> str:
    parts = ip.split(".")
    return "_".join(parts[:3]) if len(parts) == 4 else ip


def findings_to_network_spec(
    findings: List[ScanFinding],
    name: str = "ImportedScan",
    *,
    nvd_cache_dir: Path | str = DEFAULT_NVD_CACHE_DIR,
    reachability: str = "subnet",
    reachability_edges: Optional[List[Tuple[str, str]]] = None,
    internet_facing: str = "web_ports",
    goal: str = "highest_cvss",
) -> NetworkSpec:
    """Group findings into a ``NetworkSpec``.

    Data-grounded: hosts and their CVEs (CVSS from the scan, else enriched from the local
    NVD cache). INFERRED & flagged: zones (per /24 subnet), ``internet_facing`` (hosts with
    a web/SSH port, policy ``web_ports``), ``goal`` (host with the highest CVSS, policy
    ``highest_cvss``), and ``reachability`` (``subnet``: same-/24 mesh + internet-facing
    hosts bridge across subnets; ``full_mesh``; or supply ``reachability_edges`` ground truth).
    """
    nvd = load_nvd_recent(nvd_cache_dir)

    # group by host
    hosts: Dict[str, dict] = {}
    for f in findings:
        h = hosts.setdefault(f.host_ip, {
            "hostname": "", "ports": set(), "vulns": {}, "max_cvss": 0.0})
        if f.hostname and not h["hostname"]:
            h["hostname"] = f.hostname
        if f.port:
            h["ports"].add(f.port)
        for cve in f.cve_ids:
            cve = cve.upper()
            vector = f.cvss_vector
            score = f.cvss_score
            if (not vector or score is None) and cve in nvd:  # 3a enrichment
                vector = vector or (nvd[cve].get("cvss_vector") or "")
                score = score if score is not None else nvd[cve].get("cvss_score")
            prev = h["vulns"].get(cve)
            # keep the richest record (prefer one that has a vector)
            if prev is None or (not prev.cvss_vector and vector):
                h["vulns"][cve] = VulnSpec(cve_id=cve, name=f.name or cve,
                                           cvss_vector=vector or "", cvss_score=score)
            if score:
                h["max_cvss"] = max(h["max_cvss"], score)

    if not hosts:
        return NetworkSpec(name=name)

    def _asset_type(ports: set) -> AssetType:
        for p in sorted(ports):
            if p in _PORT_ASSET:
                return _PORT_ASSET[p]
        return AssetType.SERVER

    host_specs: List[HostSpec] = []
    for ip, h in hosts.items():
        host_specs.append(HostSpec(
            host_id=ip, name=h["hostname"] or ip, ip_address=ip,
            asset_type=_asset_type(h["ports"]), network_zone="zone_" + _subnet(ip),
            criticality=min(10.0, max(1.0, h["max_cvss"] or 5.0)),
            vulnerabilities=list(h["vulns"].values()),
            internet_facing=(internet_facing == "web_ports" and bool(h["ports"] & _INTERNET_FACING_PORTS)),
        ))

    # ensure an attacker entry exists (a graph with no internet-facing host is unreachable)
    if not any(h.internet_facing for h in host_specs):
        entry = max(host_specs, key=lambda h: (len(h.vulnerabilities), h.host_id))
        entry.internet_facing = True
        logger.warning("scan_import: no host matched the internet-facing heuristic; "
                       "marking %s as the entry point", entry.host_id)

    # goal selection (inferred): the highest-CVSS host
    if goal == "highest_cvss":
        goal_host = max(host_specs, key=lambda h: (hosts[h.host_id]["max_cvss"], h.host_id))
        goal_host.is_goal = True

    spec = NetworkSpec(name=name, hosts=host_specs,
                       reachability=_build_reachability(host_specs, reachability, reachability_edges))
    return spec


def _build_reachability(host_specs, policy: str,
                        explicit: Optional[List[Tuple[str, str]]]) -> List[Tuple[str, str]]:
    ids = [h.host_id for h in host_specs]
    if explicit is not None:
        known = set(ids)
        return [(a, b) for a, b in explicit if a in known and b in known]
    edges: List[Tuple[str, str]] = []
    if policy == "full_mesh":
        edges = [(a, b) for a in ids for b in ids if a != b]
    else:  # "subnet": same-/24 mesh + internet-facing hosts bridge across subnets
        zone = {h.host_id: h.network_zone for h in host_specs}
        facing = [h.host_id for h in host_specs if h.internet_facing]
        for a in ids:
            for b in ids:
                if a == b:
                    continue
                if zone[a] == zone[b] or a in facing:
                    edges.append((a, b))
    return edges


# --- top-level convenience -------------------------------------------------------

def import_scan_file(
    path: Path | str,
    fmt: str = "auto",
    provider=None,
    *,
    name: Optional[str] = None,
    logger_=None,
    **spec_kwargs,
):
    """Parse a scanner file and build the canonical multi-host ``AttackGraph``.

    Returns ``(graph, spec, findings, detected_format)``. ``provider`` is a
    ``ThreatDataProvider`` for EPSS/KEV grounding (None → CVSS-only, recorded).
    """
    path = Path(path)
    xml = path.read_text(encoding="utf-8", errors="replace")
    detected, findings = parse_scan(xml, fmt=fmt)
    spec = findings_to_network_spec(findings, name=name or path.stem, **spec_kwargs)
    graph = build_network(spec, provider=provider, logger=logger_)
    return graph, spec, findings, detected
