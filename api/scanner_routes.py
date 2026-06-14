#!/usr/bin/env python3
"""
CTPPO Security Scanner API Endpoints
=====================================

REST API for real-time security scanning.

Author: Ruthvik Bandari
Date: January 2026
"""

import asyncio
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from fastapi.responses import StreamingResponse
import json

# Import our scanner
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "scanner"))

try:
    from security_scanner import SecurityScanner, ScanResult, NMAP_AVAILABLE, ZAP_AVAILABLE
except ImportError:
    NMAP_AVAILABLE = False
    ZAP_AVAILABLE = False
    SecurityScanner = None


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class ScanRequest(BaseModel):
    """Request to start a security scan."""
    target: str = Field(..., description="URL, IP address, or hostname to scan")
    scan_type: str = Field(default="quick", description="Scan type: quick, network, web, full")
    ports: str = Field(default="21,22,80,443,3306,5432,8080,8443", description="Ports to scan")
    max_duration: int = Field(default=300, ge=30, le=3600, description="Max scan duration in seconds")


class ScanStatusResponse(BaseModel):
    """Response for scan status."""
    scan_id: str
    status: str  # pending, running, completed, failed
    progress: int  # 0-100
    started_at: str
    completed_at: Optional[str] = None
    target: str
    scan_type: str


class VulnerabilityResponse(BaseModel):
    """Vulnerability in response."""
    id: str
    name: str
    description: str
    severity: str
    cvss_score: float
    host: str
    port: int
    url: str
    solution: str
    cwe_id: str


class AttackPathResponse(BaseModel):
    """Attack path in response."""
    entry_point: str
    target: str
    total_risk: float
    likelihood: float
    impact: float
    steps: List[dict]


class ScanResultResponse(BaseModel):
    """Complete scan result response."""
    scan_id: str
    target: str
    scan_type: str
    status: str
    started_at: str
    completed_at: Optional[str]
    duration_seconds: float
    hosts_discovered: List[str]
    services: List[dict]
    vulnerabilities: List[dict]
    attack_paths: List[dict]
    risk_summary: dict
    errors: List[str]


class ToolStatusResponse(BaseModel):
    """Scanner tool availability status."""
    nmap_available: bool
    nmap_installed: bool
    zap_available: bool
    zap_running: bool
    nvd_api_configured: bool
    recommendations: List[str]


# ============================================================================
# IN-MEMORY SCAN STORAGE (Use Redis in production)
# ============================================================================

ACTIVE_SCANS: dict = {}  # scan_id -> ScanResult
SCAN_STATUS: dict = {}   # scan_id -> status info


# ============================================================================
# ROUTER
# ============================================================================

router = APIRouter(prefix="/api/scanner", tags=["Security Scanner"])


# ============================================================================
# ENDPOINTS
# ============================================================================

@router.get("/status", response_model=ToolStatusResponse)
async def get_scanner_status():
    """Check availability of scanning tools."""
    recommendations = []
    
    nmap_installed = False
    if NMAP_AVAILABLE:
        try:
            import subprocess
            result = subprocess.run(["nmap", "--version"], capture_output=True)
            nmap_installed = result.returncode == 0
        except:
            pass
    
    if not NMAP_AVAILABLE:
        recommendations.append("Install python-nmap: pip install python-nmap")
    if not nmap_installed:
        recommendations.append("Install Nmap: brew install nmap (Mac) or apt install nmap (Linux)")
    
    zap_running = False
    if ZAP_AVAILABLE:
        try:
            from zapv2 import ZAPv2
            zap = ZAPv2(proxies={"http": "http://localhost:8080"})
            zap.core.version
            zap_running = True
        except:
            pass
    
    if not ZAP_AVAILABLE:
        recommendations.append("Install ZAP Python client: pip install python-owasp-zap-v2.4")
    if not zap_running:
        recommendations.append("Start OWASP ZAP: Download from https://www.zaproxy.org/ and run with API enabled")
    
    import os
    nvd_configured = bool(os.environ.get("NVD_API_KEY"))
    if not nvd_configured:
        recommendations.append("Set NVD_API_KEY environment variable for faster CVE lookups (get key from https://nvd.nist.gov/developers/request-an-api-key)")
    
    return ToolStatusResponse(
        nmap_available=NMAP_AVAILABLE,
        nmap_installed=nmap_installed,
        zap_available=ZAP_AVAILABLE,
        zap_running=zap_running,
        nvd_api_configured=nvd_configured,
        recommendations=recommendations
    )


@router.post("/scan", response_model=ScanStatusResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a new security scan.
    
    Scan types:
    - quick: Fast port scan with version detection
    - network: Full network scan with Nmap vulnerability scripts
    - web: Web application scan with OWASP ZAP
    - full: Combined network + web scan
    """
    if not SecurityScanner:
        raise HTTPException(
            status_code=503,
            detail="Scanner not available. Install required packages: pip install python-nmap python-owasp-zap-v2.4 httpx"
        )
    
    # Generate scan ID
    import uuid
    scan_id = str(uuid.uuid4())[:8]
    
    # Initialize status
    SCAN_STATUS[scan_id] = {
        "scan_id": scan_id,
        "status": "pending",
        "progress": 0,
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "target": request.target,
        "scan_type": request.scan_type
    }
    
    # Start scan in background
    background_tasks.add_task(
        run_scan_background,
        scan_id,
        request.target,
        request.scan_type,
        request.ports,
        request.max_duration
    )
    
    return ScanStatusResponse(**SCAN_STATUS[scan_id])


async def run_scan_background(
    scan_id: str,
    target: str,
    scan_type: str,
    ports: str,
    max_duration: int
):
    """Run scan in background."""
    try:
        SCAN_STATUS[scan_id]["status"] = "running"
        SCAN_STATUS[scan_id]["progress"] = 10
        
        scanner = SecurityScanner()
        
        # Run the scan
        result = await scanner.scan(
            target=target,
            scan_type=scan_type,
            ports=ports,
            max_duration=max_duration
        )
        
        # Store result
        ACTIVE_SCANS[scan_id] = result
        
        SCAN_STATUS[scan_id]["status"] = "completed"
        SCAN_STATUS[scan_id]["progress"] = 100
        SCAN_STATUS[scan_id]["completed_at"] = datetime.utcnow().isoformat()
        
    except Exception as e:
        SCAN_STATUS[scan_id]["status"] = "failed"
        SCAN_STATUS[scan_id]["error"] = str(e)


@router.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """Get the status of a running scan."""
    if scan_id not in SCAN_STATUS:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return ScanStatusResponse(**SCAN_STATUS[scan_id])


@router.get("/scan/{scan_id}/result", response_model=ScanResultResponse)
async def get_scan_result(scan_id: str):
    """Get the results of a completed scan."""
    if scan_id not in SCAN_STATUS:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    status = SCAN_STATUS[scan_id]
    
    if status["status"] == "pending":
        raise HTTPException(status_code=202, detail="Scan is pending")
    
    if status["status"] == "running":
        raise HTTPException(status_code=202, detail="Scan is still running")
    
    if status["status"] == "failed":
        raise HTTPException(status_code=500, detail=f"Scan failed: {status.get('error', 'Unknown error')}")
    
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Scan results not found")
    
    result = ACTIVE_SCANS[scan_id]
    
    return ScanResultResponse(
        scan_id=scan_id,
        **result.to_dict()
    )


@router.get("/scan/{scan_id}/stream")
async def stream_scan_results(scan_id: str):
    """
    Stream scan results in real-time using Server-Sent Events.
    
    Connect with EventSource in JavaScript:
    ```javascript
    const es = new EventSource('/api/scanner/scan/{scan_id}/stream');
    es.onmessage = (event) => console.log(JSON.parse(event.data));
    ```
    """
    if scan_id not in SCAN_STATUS:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    async def event_generator():
        while True:
            status = SCAN_STATUS.get(scan_id, {})
            
            yield f"data: {json.dumps(status)}\n\n"
            
            if status.get("status") in ["completed", "failed"]:
                # Send final result
                if scan_id in ACTIVE_SCANS:
                    result = ACTIVE_SCANS[scan_id].to_dict()
                    yield f"data: {json.dumps({'type': 'result', 'data': result})}\n\n"
                break
            
            await asyncio.sleep(2)
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


@router.delete("/scan/{scan_id}")
async def cancel_scan(scan_id: str):
    """Cancel a running scan."""
    if scan_id not in SCAN_STATUS:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    SCAN_STATUS[scan_id]["status"] = "cancelled"
    
    return {"message": "Scan cancelled", "scan_id": scan_id}


@router.get("/scans", response_model=List[ScanStatusResponse])
async def list_scans():
    """List all scans."""
    return [ScanStatusResponse(**status) for status in SCAN_STATUS.values()]


# ============================================================================
# QUICK SCAN ENDPOINT (Synchronous for simple use)
# ============================================================================

@router.post("/quick-scan")
async def quick_scan(request: ScanRequest):
    """
    Perform a quick synchronous scan and return results immediately.
    
    Best for simple scans that complete quickly (< 60 seconds).
    For longer scans, use /scan endpoint with background processing.
    """
    if not SecurityScanner:
        raise HTTPException(
            status_code=503,
            detail="Scanner not available. Install: pip install python-nmap httpx"
        )
    
    try:
        scanner = SecurityScanner()
        result = await scanner.scan(
            target=request.target,
            scan_type="quick",
            ports=request.ports,
            max_duration=60
        )
        
        return result.to_dict()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CVE LOOKUP ENDPOINT
# ============================================================================

@router.get("/cve/{cve_id}")
async def lookup_cve(cve_id: str):
    """Look up details for a specific CVE."""
    try:
        from security_scanner import NVDClient
        nvd = NVDClient()
        cves = await nvd.search_cves_by_keyword(cve_id, limit=1)
        
        if not cves:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        return cves[0]
        
    except ImportError:
        raise HTTPException(status_code=503, detail="NVD client not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cve/search/{keyword}")
async def search_cves(keyword: str, limit: int = 10):
    """Search CVEs by keyword."""
    try:
        from security_scanner import NVDClient
        nvd = NVDClient()
        cves = await nvd.search_cves_by_keyword(keyword, limit=limit)
        return {"results": cves, "count": len(cves)}
        
    except ImportError:
        raise HTTPException(status_code=503, detail="NVD client not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
