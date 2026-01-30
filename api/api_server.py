#!/usr/bin/env python3
"""
CTPPO v3.0 - FastAPI Backend
============================

REST API for CVE severity classification and attack path analysis.

Endpoints:
- POST /classify          - Classify a single CVE
- POST /classify/batch    - Classify multiple CVEs
- POST /attack-paths      - Analyze attack paths in a network
- GET  /health            - Health check
- GET  /model/info        - Model information

Usage:
    uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload

Author: Ruthvik Bandari
Date: January 2026
"""

import os
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from contextlib import asynccontextmanager

import torch
import torch.nn as nn
import numpy as np
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from transformers import DistilBertTokenizer, DistilBertModel

# Import attack path analyzer
from attack_path_analyzer import (
    AttackGraph, NAMOAStar, Vulnerability, 
    create_sample_network
)


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    model_name = "distilbert-base-uncased"
    text_hidden_dim = 512
    metadata_hidden_dim = 128
    fusion_hidden_dim = 256
    num_classes = 4
    
    cvss_vocab_sizes = {
        'attackVector': 5,
        'attackComplexity': 3,
        'privilegesRequired': 4,
        'userInteraction': 3,
        'scope': 3,
        'confidentialityImpact': 4,
        'integrityImpact': 4,
        'availabilityImpact': 4,
    }
    cvss_embed_dim = 8
    cwe_embed_dim = 64
    max_length = 256
    dropout = 0.3
    
    class_names = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    label2id = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    id2label = {0: 'CRITICAL', 1: 'HIGH', 2: 'MEDIUM', 3: 'LOW'}


# ============================================================================
# MODEL DEFINITION (same as training)
# ============================================================================

class CVSSEmbedding(nn.Module):
    def __init__(self, config: Config):
        super().__init__()
        self.embeddings = nn.ModuleDict({
            'attackVector': nn.Embedding(config.cvss_vocab_sizes['attackVector'], config.cvss_embed_dim, padding_idx=config.cvss_vocab_sizes['attackVector']-1),
            'attackComplexity': nn.Embedding(config.cvss_vocab_sizes['attackComplexity'], config.cvss_embed_dim, padding_idx=config.cvss_vocab_sizes['attackComplexity']-1),
            'privilegesRequired': nn.Embedding(config.cvss_vocab_sizes['privilegesRequired'], config.cvss_embed_dim, padding_idx=config.cvss_vocab_sizes['privilegesRequired']-1),
            'userInteraction': nn.Embedding(config.cvss_vocab_sizes['userInteraction'], config.cvss_embed_dim, padding_idx=config.cvss_vocab_sizes['userInteraction']-1),
            'scope': nn.Embedding(config.cvss_vocab_sizes['scope'], config.cvss_embed_dim, padding_idx=config.cvss_vocab_sizes['scope']-1),
            'confidentialityImpact': nn.Embedding(config.cvss_vocab_sizes['confidentialityImpact'], config.cvss_embed_dim, padding_idx=config.cvss_vocab_sizes['confidentialityImpact']-1),
            'integrityImpact': nn.Embedding(config.cvss_vocab_sizes['integrityImpact'], config.cvss_embed_dim, padding_idx=config.cvss_vocab_sizes['integrityImpact']-1),
            'availabilityImpact': nn.Embedding(config.cvss_vocab_sizes['availabilityImpact'], config.cvss_embed_dim, padding_idx=config.cvss_vocab_sizes['availabilityImpact']-1),
        })
        self.output_dim = config.cvss_embed_dim * 8
    
    def forward(self, cvss_features: torch.Tensor) -> torch.Tensor:
        embeddings = []
        keys = ['attackVector', 'attackComplexity', 'privilegesRequired',
                'userInteraction', 'scope', 'confidentialityImpact',
                'integrityImpact', 'availabilityImpact']
        for i, key in enumerate(keys):
            emb = self.embeddings[key](cvss_features[:, i])
            embeddings.append(emb)
        return torch.cat(embeddings, dim=-1)


class MultiModalCVEClassifier(nn.Module):
    def __init__(self, config: Config, cwe_vocab_size: int):
        super().__init__()
        self.config = config
        
        self.bert = DistilBertModel.from_pretrained(config.model_name)
        bert_hidden = self.bert.config.hidden_size
        
        self.text_projection = nn.Sequential(
            nn.Linear(bert_hidden, config.text_hidden_dim),
            nn.LayerNorm(config.text_hidden_dim),
            nn.ReLU(),
            nn.Dropout(config.dropout)
        )
        
        self.cvss_embedding = CVSSEmbedding(config)
        cvss_dim = self.cvss_embedding.output_dim
        
        self.cwe_embedding = nn.Embedding(cwe_vocab_size, config.cwe_embed_dim, padding_idx=1)
        
        self.numeric_projection = nn.Sequential(
            nn.Linear(8, 32),
            nn.ReLU(),
            nn.Dropout(config.dropout)
        )
        
        metadata_dim = cvss_dim + config.cwe_embed_dim + 32
        self.metadata_fusion = nn.Sequential(
            nn.Linear(metadata_dim, config.metadata_hidden_dim),
            nn.LayerNorm(config.metadata_hidden_dim),
            nn.ReLU(),
            nn.Dropout(config.dropout)
        )
        
        fusion_input_dim = config.text_hidden_dim + config.metadata_hidden_dim
        self.classifier = nn.Sequential(
            nn.Linear(fusion_input_dim, config.fusion_hidden_dim),
            nn.LayerNorm(config.fusion_hidden_dim),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.fusion_hidden_dim, config.fusion_hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.fusion_hidden_dim // 2, config.num_classes)
        )
    
    def forward(self, input_ids, attention_mask, cvss_features, numeric_features, cwe_id):
        bert_output = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        text_features = bert_output.last_hidden_state[:, 0, :]
        text_features = self.text_projection(text_features)
        
        cvss_features_encoded = self.cvss_embedding(cvss_features)
        cwe_features = self.cwe_embedding(cwe_id)
        numeric_features_encoded = self.numeric_projection(numeric_features)
        
        metadata = torch.cat([cvss_features_encoded, cwe_features, numeric_features_encoded], dim=-1)
        metadata_fused = self.metadata_fusion(metadata)
        
        combined = torch.cat([text_features, metadata_fused], dim=-1)
        logits = self.classifier(combined)
        
        return logits


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class CVSSVector(BaseModel):
    """CVSS v3 vector components."""
    attackVector: str = Field(..., description="NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL")
    attackComplexity: str = Field(..., description="LOW, HIGH")
    privilegesRequired: str = Field(..., description="NONE, LOW, HIGH")
    userInteraction: str = Field(..., description="NONE, REQUIRED")
    scope: str = Field(..., description="UNCHANGED, CHANGED")
    confidentialityImpact: str = Field(..., description="NONE, LOW, HIGH")
    integrityImpact: str = Field(..., description="NONE, LOW, HIGH")
    availabilityImpact: str = Field(..., description="NONE, LOW, HIGH")


class CVEInput(BaseModel):
    """Input for CVE classification."""
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    description: str = Field(..., description="CVE description text")
    cvss_vector: Optional[CVSSVector] = Field(None, description="CVSS v3 vector")
    cvss_score: Optional[float] = Field(None, description="CVSS base score (0-10)")
    exploitability_score: Optional[float] = Field(None, description="Exploitability score")
    impact_score: Optional[float] = Field(None, description="Impact score")
    cwe_id: Optional[str] = Field(None, description="CWE identifier (e.g., CWE-79)")
    has_exploit: bool = Field(False, description="Known exploit exists")
    has_patch: bool = Field(False, description="Patch available")


class ClassificationResult(BaseModel):
    """Classification result for a single CVE."""
    cve_id: Optional[str]
    predicted_severity: str
    confidence: float
    probabilities: Dict[str, float]
    processing_time_ms: float


class BatchClassificationRequest(BaseModel):
    """Batch classification request."""
    cves: List[CVEInput]


class BatchClassificationResponse(BaseModel):
    """Batch classification response."""
    results: List[ClassificationResult]
    total_processing_time_ms: float


class NetworkNode(BaseModel):
    """Node in network graph."""
    id: str
    name: str
    type: str
    is_entry_point: bool = False
    is_critical_asset: bool = False


class NetworkVulnerability(BaseModel):
    """Vulnerability connecting nodes."""
    cve_id: str
    source: str
    target: str
    severity: str
    cvss_score: float
    exploitability_score: float = 2.5
    impact_score: float = 4.0
    has_exploit: bool = False
    description: str = ""


class AttackPathRequest(BaseModel):
    """Request for attack path analysis."""
    nodes: List[NetworkNode]
    vulnerabilities: List[NetworkVulnerability]
    max_paths: int = Field(10, ge=1, le=50)


class AttackPathResponse(BaseModel):
    """Response with attack path analysis."""
    paths: List[Dict[str, Any]]
    statistics: Dict[str, Any]
    processing_time_ms: float


# ============================================================================
# GLOBAL STATE
# ============================================================================

class ModelState:
    model: Optional[MultiModalCVEClassifier] = None
    tokenizer: Optional[DistilBertTokenizer] = None
    cwe_vocab: Optional[Dict[str, int]] = None
    device: torch.device = torch.device('cpu')
    config: Config = Config()
    loaded: bool = False
    model_info: Dict = {}


state = ModelState()


# ============================================================================
# CVSS ENCODING HELPERS
# ============================================================================

CVSS_ENCODINGS = {
    'attackVector': {'NETWORK': 0, 'ADJACENT_NETWORK': 1, 'LOCAL': 2, 'PHYSICAL': 3},
    'attackComplexity': {'LOW': 0, 'HIGH': 1},
    'privilegesRequired': {'NONE': 0, 'LOW': 1, 'HIGH': 2},
    'userInteraction': {'NONE': 0, 'REQUIRED': 1},
    'scope': {'UNCHANGED': 0, 'CHANGED': 1},
    'confidentialityImpact': {'NONE': 0, 'LOW': 1, 'HIGH': 2},
    'integrityImpact': {'NONE': 0, 'LOW': 1, 'HIGH': 2},
    'availabilityImpact': {'NONE': 0, 'LOW': 1, 'HIGH': 2},
}


def encode_cvss_vector(cvss: Optional[CVSSVector], config: Config) -> List[int]:
    """Encode CVSS vector to integers."""
    if cvss is None:
        # Return padding values
        return [config.cvss_vocab_sizes[k] - 1 for k in CVSS_ENCODINGS.keys()]
    
    encoded = []
    for key in CVSS_ENCODINGS.keys():
        value = getattr(cvss, key, None)
        if value and value in CVSS_ENCODINGS[key]:
            encoded.append(CVSS_ENCODINGS[key][value])
        else:
            encoded.append(config.cvss_vocab_sizes[key] - 1)  # Padding
    return encoded


# ============================================================================
# MODEL LOADING
# ============================================================================

def load_model(model_dir: str = "./models/severity_v3"):
    """Load the trained model."""
    model_path = Path(model_dir)
    
    # Check if model exists
    if not (model_path / "checkpoint_best.pt").exists():
        raise FileNotFoundError(f"Model not found at {model_path}")
    
    # Determine device
    if torch.cuda.is_available():
        state.device = torch.device('cuda')
    elif hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
        state.device = torch.device('mps')
    else:
        state.device = torch.device('cpu')
    
    print(f"Using device: {state.device}")
    
    # Load CWE vocabulary
    with open(model_path / "cwe_vocab.json", 'r') as f:
        state.cwe_vocab = json.load(f)
    
    # Load tokenizer
    tokenizer_path = model_path / "tokenizer"
    if tokenizer_path.exists():
        state.tokenizer = DistilBertTokenizer.from_pretrained(tokenizer_path)
    else:
        state.tokenizer = DistilBertTokenizer.from_pretrained(state.config.model_name)
    
    # Create and load model
    state.model = MultiModalCVEClassifier(state.config, len(state.cwe_vocab))
    checkpoint = torch.load(model_path / "checkpoint_best.pt", map_location=state.device, weights_only=False)
    state.model.load_state_dict(checkpoint['model_state_dict'])
    state.model = state.model.to(state.device)
    state.model.eval()
    
    # Store model info
    state.model_info = {
        'epoch': checkpoint.get('epoch', 'unknown'),
        'validation_f1': checkpoint.get('val_f1', 0),
        'cwe_vocab_size': len(state.cwe_vocab),
        'device': str(state.device),
        'model_path': str(model_path)
    }
    
    state.loaded = True
    print(f"Model loaded from {model_path} (epoch {state.model_info['epoch']}, val_f1: {state.model_info['validation_f1']:.4f})")


# ============================================================================
# INFERENCE
# ============================================================================

def classify_cve(cve: CVEInput) -> ClassificationResult:
    """Classify a single CVE."""
    if not state.loaded:
        raise RuntimeError("Model not loaded")
    
    start_time = time.time()
    
    # Tokenize text
    encoding = state.tokenizer(
        cve.description,
        max_length=state.config.max_length,
        padding='max_length',
        truncation=True,
        return_tensors='pt'
    )
    
    # Encode CVSS
    cvss_encoded = encode_cvss_vector(cve.cvss_vector, state.config)
    
    # Encode CWE
    cwe = cve.cwe_id or '<UNK>'
    cwe_id = state.cwe_vocab.get(cwe, state.cwe_vocab.get('<UNK>', 0))
    
    # Numeric features
    numeric_features = torch.tensor([[
        (cve.cvss_score or 0.0) / 10.0,
        (cve.exploitability_score or 0.0) / 4.0,
        (cve.impact_score or 0.0) / 6.0,
        float(cve.has_exploit),
        float(cve.has_patch),
        0.0,  # has_vendor_advisory
        0.0,  # reference_count
        0.0,  # product_count
    ]], dtype=torch.float32)
    
    # Move to device
    input_ids = encoding['input_ids'].to(state.device)
    attention_mask = encoding['attention_mask'].to(state.device)
    cvss_features = torch.tensor([cvss_encoded], dtype=torch.long).to(state.device)
    numeric_features = numeric_features.to(state.device)
    cwe_tensor = torch.tensor([cwe_id], dtype=torch.long).to(state.device)
    
    # Inference
    with torch.no_grad():
        logits = state.model(input_ids, attention_mask, cvss_features, numeric_features, cwe_tensor)
        probs = torch.softmax(logits, dim=-1)
        pred = torch.argmax(logits, dim=-1)
    
    # Convert to result
    pred_idx = pred.item()
    confidence = probs[0, pred_idx].item()
    
    probabilities = {
        state.config.class_names[i]: round(probs[0, i].item(), 4)
        for i in range(state.config.num_classes)
    }
    
    processing_time = (time.time() - start_time) * 1000
    
    return ClassificationResult(
        cve_id=cve.cve_id,
        predicted_severity=state.config.class_names[pred_idx],
        confidence=round(confidence, 4),
        probabilities=probabilities,
        processing_time_ms=round(processing_time, 2)
    )


# ============================================================================
# FASTAPI APP
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model on startup."""
    model_dir = os.environ.get("MODEL_DIR", "./models/severity_v3")
    try:
        load_model(model_dir)
    except Exception as e:
        print(f"Warning: Could not load model: {e}")
        print("API will start but classification endpoints will fail.")
    yield


app = FastAPI(
    title="CTPPO API",
    description="Cyber Threat Prioritization & Path Optimization - CVE Severity Classification and Attack Path Analysis",
    version="3.0.0",
    lifespan=lifespan
)

# CORS middleware
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
    """Root endpoint."""
    return {
        "name": "CTPPO API",
        "version": "3.0.0",
        "description": "CVE Severity Classification & Attack Path Analysis",
        "endpoints": {
            "classify": "POST /classify",
            "batch_classify": "POST /classify/batch",
            "attack_paths": "POST /attack-paths",
            "health": "GET /health",
            "model_info": "GET /model/info"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "model_loaded": state.loaded,
        "device": str(state.device),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/model/info")
async def model_info():
    """Get model information."""
    if not state.loaded:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    return {
        "model_loaded": True,
        "info": state.model_info,
        "classes": state.config.class_names,
        "test_f1": "97.50%"  # From our evaluation
    }


@app.post("/classify", response_model=ClassificationResult)
async def classify(cve: CVEInput):
    """Classify a single CVE."""
    if not state.loaded:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        result = classify_cve(cve)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/classify/batch", response_model=BatchClassificationResponse)
async def classify_batch(request: BatchClassificationRequest):
    """Classify multiple CVEs."""
    if not state.loaded:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    start_time = time.time()
    results = []
    
    for cve in request.cves:
        try:
            result = classify_cve(cve)
            results.append(result)
        except Exception as e:
            results.append(ClassificationResult(
                cve_id=cve.cve_id,
                predicted_severity="ERROR",
                confidence=0.0,
                probabilities={},
                processing_time_ms=0.0
            ))
    
    total_time = (time.time() - start_time) * 1000
    
    return BatchClassificationResponse(
        results=results,
        total_processing_time_ms=round(total_time, 2)
    )


@app.post("/attack-paths", response_model=AttackPathResponse)
async def analyze_attack_paths(request: AttackPathRequest):
    """Analyze attack paths in a network."""
    start_time = time.time()
    
    # Build graph
    graph = AttackGraph()
    
    for node in request.nodes:
        graph.add_node(
            node.id,
            {"name": node.name, "type": node.type},
            is_entry=node.is_entry_point,
            is_critical=node.is_critical_asset
        )
    
    for vuln in request.vulnerabilities:
        graph.add_vulnerability(Vulnerability(
            cve_id=vuln.cve_id,
            source=vuln.source,
            target=vuln.target,
            severity=vuln.severity,
            cvss_score=vuln.cvss_score,
            exploitability_score=vuln.exploitability_score,
            impact_score=vuln.impact_score,
            has_exploit=vuln.has_exploit,
            description=vuln.description
        ))
    
    # Run NAMOA*
    analyzer = NAMOAStar(graph)
    results = analyzer.analyze_all_paths(max_paths_per_pair=request.max_paths)
    
    processing_time = (time.time() - start_time) * 1000
    
    return AttackPathResponse(
        paths=results['paths'],
        statistics=results['statistics'],
        processing_time_ms=round(processing_time, 2)
    )


@app.get("/attack-paths/sample")
async def get_sample_network():
    """Get a sample network for testing attack path analysis."""
    graph = create_sample_network()
    
    analyzer = NAMOAStar(graph)
    results = analyzer.analyze_all_paths(max_paths_per_pair=5)
    
    return {
        "network": graph.to_dict(),
        "analysis": results
    }


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
