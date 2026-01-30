#!/usr/bin/env python3
"""
CTPPO v3.0 - FastAPI Backend
============================

REST API for CVE severity classification and NAMOA* attack path analysis.

Endpoints:
- POST /api/classify              - Classify a single CVE
- POST /api/classify/batch        - Classify multiple CVEs
- POST /api/attack-paths/analyze  - Analyze attack paths
- GET  /api/attack-paths/sample   - Get sample network analysis
- GET  /api/health                - Health check
- GET  /api/model/info            - Model information

Run:
    cd ~/Downloads/ctppo
    uvicorn api.server:app --reload --port 8000

Author: Ruthvik Bandari
Date: January 2026
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from contextlib import asynccontextmanager

import torch
import torch.nn as nn
import numpy as np
from pydantic import BaseModel, Field

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent / "ml"))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from transformers import DistilBertTokenizer, DistilBertModel

# Import NAMOA analyzer
from namoa_analyzer import (
    AttackGraph, NAMOAPathAnalyzer, Vulnerability, create_sample_network
)


# ============================================================================
# CONFIG (matches training)
# ============================================================================

class ModelConfig:
    model_name = "distilbert-base-uncased"
    text_hidden_dim = 512
    metadata_hidden_dim = 128
    fusion_hidden_dim = 256
    num_classes = 4
    cvss_vocab_sizes = {
        'attackVector': 5, 'attackComplexity': 3, 'privilegesRequired': 4,
        'userInteraction': 3, 'scope': 3, 'confidentialityImpact': 4,
        'integrityImpact': 4, 'availabilityImpact': 4,
    }
    cvss_embed_dim = 8
    cwe_embed_dim = 64
    max_length = 256
    dropout = 0.3
    class_names = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    label2id = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


# ============================================================================
# MODEL ARCHITECTURE (same as training)
# ============================================================================

class CVSSEmbedding(nn.Module):
    def __init__(self, config):
        super().__init__()
        self.embeddings = nn.ModuleDict({
            k: nn.Embedding(v, config.cvss_embed_dim, padding_idx=v-1)
            for k, v in config.cvss_vocab_sizes.items()
        })
        self.output_dim = config.cvss_embed_dim * 8
    
    def forward(self, x):
        keys = list(self.embeddings.keys())
        return torch.cat([self.embeddings[k](x[:, i]) for i, k in enumerate(keys)], dim=-1)


class MultiModalCVEClassifier(nn.Module):
    def __init__(self, config, cwe_vocab_size):
        super().__init__()
        self.bert = DistilBertModel.from_pretrained(config.model_name)
        
        self.text_projection = nn.Sequential(
            nn.Linear(768, config.text_hidden_dim),
            nn.LayerNorm(config.text_hidden_dim),
            nn.ReLU(),
            nn.Dropout(config.dropout)
        )
        
        self.cvss_embedding = CVSSEmbedding(config)
        self.cwe_embedding = nn.Embedding(cwe_vocab_size, config.cwe_embed_dim, padding_idx=1)
        
        self.numeric_projection = nn.Sequential(
            nn.Linear(8, 32), nn.ReLU(), nn.Dropout(config.dropout)
        )
        
        metadata_dim = self.cvss_embedding.output_dim + config.cwe_embed_dim + 32
        self.metadata_fusion = nn.Sequential(
            nn.Linear(metadata_dim, config.metadata_hidden_dim),
            nn.LayerNorm(config.metadata_hidden_dim),
            nn.ReLU(),
            nn.Dropout(config.dropout)
        )
        
        fusion_dim = config.text_hidden_dim + config.metadata_hidden_dim
        self.classifier = nn.Sequential(
            nn.Linear(fusion_dim, config.fusion_hidden_dim),
            nn.LayerNorm(config.fusion_hidden_dim),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.fusion_hidden_dim, config.fusion_hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.fusion_hidden_dim // 2, config.num_classes)
        )
    
    def forward(self, input_ids, attention_mask, cvss_features, numeric_features, cwe_id):
        bert_out = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        text = self.text_projection(bert_out.last_hidden_state[:, 0, :])
        
        cvss = self.cvss_embedding(cvss_features)
        cwe = self.cwe_embedding(cwe_id)
        numeric = self.numeric_projection(numeric_features)
        
        metadata = self.metadata_fusion(torch.cat([cvss, cwe, numeric], dim=-1))
        return self.classifier(torch.cat([text, metadata], dim=-1))


# ============================================================================
# GLOBAL STATE
# ============================================================================

class AppState:
    model: Optional[MultiModalCVEClassifier] = None
    tokenizer: Optional[DistilBertTokenizer] = None
    cwe_vocab: Dict[str, int] = {}
    device: torch.device = torch.device('cpu')
    config: ModelConfig = ModelConfig()
    loaded: bool = False

state = AppState()


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class CVSSVector(BaseModel):
    attackVector: str = "NETWORK"
    attackComplexity: str = "LOW"
    privilegesRequired: str = "NONE"
    userInteraction: str = "NONE"
    scope: str = "UNCHANGED"
    confidentialityImpact: str = "HIGH"
    integrityImpact: str = "HIGH"
    availabilityImpact: str = "HIGH"


class CVEClassifyRequest(BaseModel):
    description: str = Field(..., description="CVE description text")
    cve_id: Optional[str] = None
    cvss_vector: Optional[CVSSVector] = None
    cvss_score: float = Field(default=0.0, ge=0, le=10)
    exploitability_score: float = Field(default=0.0, ge=0, le=4)
    impact_score: float = Field(default=0.0, ge=0, le=6)
    cwe_id: Optional[str] = None
    has_exploit: bool = False
    has_patch: bool = False


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
    max_depth: int = Field(default=10, ge=1, le=20)


class AttackPathResponse(BaseModel):
    paths: Dict[str, List[Dict]]
    risk_summary: Dict[str, Any]
    processing_time_ms: float


# ============================================================================
# CVSS ENCODING
# ============================================================================

CVSS_MAP = {
    'attackVector': {'NETWORK': 0, 'ADJACENT_NETWORK': 1, 'LOCAL': 2, 'PHYSICAL': 3},
    'attackComplexity': {'LOW': 0, 'HIGH': 1},
    'privilegesRequired': {'NONE': 0, 'LOW': 1, 'HIGH': 2},
    'userInteraction': {'NONE': 0, 'REQUIRED': 1},
    'scope': {'UNCHANGED': 0, 'CHANGED': 1},
    'confidentialityImpact': {'NONE': 0, 'LOW': 1, 'HIGH': 2},
    'integrityImpact': {'NONE': 0, 'LOW': 1, 'HIGH': 2},
    'availabilityImpact': {'NONE': 0, 'LOW': 1, 'HIGH': 2},
}


def encode_cvss(cvss: Optional[CVSSVector]) -> List[int]:
    """Encode CVSS vector to integers."""
    if cvss is None:
        return [state.config.cvss_vocab_sizes[k] - 1 for k in CVSS_MAP.keys()]
    
    result = []
    for key in CVSS_MAP.keys():
        val = getattr(cvss, key, None)
        if val and val in CVSS_MAP[key]:
            result.append(CVSS_MAP[key][val])
        else:
            result.append(state.config.cvss_vocab_sizes[key] - 1)
    return result


# ============================================================================
# MODEL LOADING
# ============================================================================

def load_model(model_dir: str = "./models/severity_v3"):
    """Load the trained model."""
    model_path = Path(model_dir)
    
    if not (model_path / "checkpoint_best.pt").exists():
        print(f"Warning: Model not found at {model_path}")
        return False
    
    # Device
    if torch.cuda.is_available():
        state.device = torch.device('cuda')
    elif hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
        state.device = torch.device('mps')
    else:
        state.device = torch.device('cpu')
    
    print(f"Using device: {state.device}")
    
    # Load vocab
    with open(model_path / "cwe_vocab.json") as f:
        state.cwe_vocab = json.load(f)
    
    # Load tokenizer
    tok_path = model_path / "tokenizer"
    if tok_path.exists():
        state.tokenizer = DistilBertTokenizer.from_pretrained(tok_path)
    else:
        state.tokenizer = DistilBertTokenizer.from_pretrained(state.config.model_name)
    
    # Load model
    state.model = MultiModalCVEClassifier(state.config, len(state.cwe_vocab))
    checkpoint = torch.load(model_path / "checkpoint_best.pt", map_location=state.device, weights_only=False)
    state.model.load_state_dict(checkpoint['model_state_dict'])
    state.model = state.model.to(state.device)
    state.model.eval()
    
    state.loaded = True
    print(f"✓ Model loaded (val_f1: {checkpoint.get('val_f1', 0):.4f})")
    return True


# ============================================================================
# INFERENCE
# ============================================================================

def classify_cve(req: CVEClassifyRequest) -> CVEClassifyResponse:
    """Classify a single CVE."""
    if not state.loaded:
        raise HTTPException(503, "Model not loaded")
    
    start = time.time()
    
    # Tokenize
    enc = state.tokenizer(
        req.description,
        max_length=state.config.max_length,
        padding='max_length',
        truncation=True,
        return_tensors='pt'
    )
    
    # Encode features
    cvss = encode_cvss(req.cvss_vector)
    cwe_idx = state.cwe_vocab.get(req.cwe_id or '<UNK>', state.cwe_vocab.get('<UNK>', 0))
    
    numeric = torch.tensor([[
        req.cvss_score / 10.0,
        req.exploitability_score / 4.0,
        req.impact_score / 6.0,
        float(req.has_exploit),
        float(req.has_patch),
        0.0, 0.0, 0.0
    ]], dtype=torch.float32)
    
    # Move to device
    input_ids = enc['input_ids'].to(state.device)
    attention_mask = enc['attention_mask'].to(state.device)
    cvss_tensor = torch.tensor([cvss], dtype=torch.long).to(state.device)
    numeric = numeric.to(state.device)
    cwe_tensor = torch.tensor([cwe_idx], dtype=torch.long).to(state.device)
    
    # Inference
    with torch.no_grad():
        logits = state.model(input_ids, attention_mask, cvss_tensor, numeric, cwe_tensor)
        probs = torch.softmax(logits, dim=-1)
        pred = torch.argmax(logits, dim=-1)
    
    pred_idx = pred.item()
    
    return CVEClassifyResponse(
        cve_id=req.cve_id,
        predicted_severity=state.config.class_names[pred_idx],
        confidence=round(probs[0, pred_idx].item(), 4),
        probabilities={
            state.config.class_names[i]: round(probs[0, i].item(), 4)
            for i in range(state.config.num_classes)
        },
        processing_time_ms=round((time.time() - start) * 1000, 2)
    )


# ============================================================================
# FASTAPI APP
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model on startup."""
    model_dir = os.environ.get("MODEL_DIR", "./models/severity_v3")
    load_model(model_dir)
    yield

app = FastAPI(
    title="CTPPO API",
    description="Cyber Threat Prioritization & Path Optimization",
    version="3.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    return {
        "name": "CTPPO API",
        "version": "3.0.0",
        "status": "running",
        "model_loaded": state.loaded,
        "endpoints": [
            "POST /api/classify",
            "POST /api/classify/batch",
            "POST /api/attack-paths/analyze",
            "GET /api/attack-paths/sample",
            "GET /api/health",
            "GET /api/model/info"
        ]
    }


@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "model_loaded": state.loaded,
        "device": str(state.device),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/model/info")
async def model_info():
    return {
        "loaded": state.loaded,
        "device": str(state.device),
        "classes": state.config.class_names,
        "test_f1": "97.50%",
        "cwe_vocab_size": len(state.cwe_vocab)
    }


@app.post("/api/classify", response_model=CVEClassifyResponse)
async def classify(req: CVEClassifyRequest):
    """Classify a single CVE."""
    return classify_cve(req)


@app.post("/api/classify/batch", response_model=BatchClassifyResponse)
async def classify_batch(req: BatchClassifyRequest):
    """Classify multiple CVEs."""
    start = time.time()
    results = [classify_cve(cve) for cve in req.cves]
    return BatchClassifyResponse(
        results=results,
        total_time_ms=round((time.time() - start) * 1000, 2)
    )


@app.post("/api/attack-paths/analyze", response_model=AttackPathResponse)
async def analyze_attack_paths(req: AttackPathRequest):
    """Analyze attack paths in a network."""
    start = time.time()
    
    # Build graph
    graph = AttackGraph()
    for node in req.nodes:
        graph.add_node(node.id, node.is_entry_point, node.is_critical_asset)
    
    for v in req.vulnerabilities:
        graph.add_edge(Vulnerability(
            cve_id=v.cve_id,
            source=v.source,
            target=v.target,
            severity=v.severity,
            cvss_score=v.cvss_score,
            exploitability_score=v.exploitability_score,
            impact_score=v.impact_score,
            has_exploit=v.has_exploit
        ))
    
    # Analyze
    analyzer = NAMOAPathAnalyzer(graph)
    all_paths = analyzer.find_all_critical_paths(req.max_depth)
    summary = analyzer.get_risk_summary()
    
    # Convert paths to dict
    paths_dict = {
        k: [p.to_dict() for p in v]
        for k, v in all_paths.items()
    }
    
    return AttackPathResponse(
        paths=paths_dict,
        risk_summary=summary,
        processing_time_ms=round((time.time() - start) * 1000, 2)
    )


@app.get("/api/attack-paths/sample")
async def sample_attack_paths():
    """Get sample network analysis."""
    start = time.time()
    
    graph = create_sample_network()
    analyzer = NAMOAPathAnalyzer(graph)
    all_paths = analyzer.find_all_critical_paths()
    summary = analyzer.get_risk_summary()
    
    return {
        "network": graph.to_dict(),
        "paths": {k: [p.to_dict() for p in v] for k, v in all_paths.items()},
        "risk_summary": summary,
        "processing_time_ms": round((time.time() - start) * 1000, 2)
    }


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
