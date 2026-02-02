#!/usr/bin/env python3
"""
CTPPO v3.0 - Secure FastAPI Backend
====================================

Production-ready API with:
- JWT Authentication
- 2FA (TOTP) Support  
- Secure Password Hashing

Author: Ruthvik Bandari
Date: January 2026
"""

import os
import sys
import asyncio
import json
import time
import secrets
import hashlib
import urllib.parse
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

import torch
import torch.nn as nn
from pydantic import BaseModel, Field, EmailStr
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from transformers import DistilBertTokenizer, DistilBertModel

# JWT and 2FA

# Database
from database import (
    init_db, is_db_available, db_create_user, db_get_user, db_update_user, db_user_exists,
    db_create_product_key, db_get_product_key, db_get_all_product_keys, db_mark_key_used, db_delete_product_key,
    db_create_subscription, db_get_subscription, db_get_all_subscriptions, db_delete_subscription
)
import jwt
import pyotp
import qrcode
from io import BytesIO
import base64

# Add ml directory
sys.path.insert(0, str(Path(__file__).parent.parent / "ml"))
from namoa_analyzer import AttackGraph, NAMOAPathAnalyzer, Vulnerability, create_sample_network


# ============================================================================
# CONFIGURATION
# ============================================================================

SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
TOTP_ISSUER = "CTPPO Security"


# ============================================================================
# IN-MEMORY USER STORE (Replace with PostgreSQL in production)
# ============================================================================

# Admin Configuration
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "ctppo-admin-2026")

def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

USERS_DB: Dict[str, Dict] = {
    "admin@ctppo.io": {
        "id": "usr_001",
        "email": "admin@ctppo.io",
        "name": "Admin User",
        "password_hash": _hash("admin123"),
        "totp_secret": None,
        "is_2fa_enabled": False,
        "role": "admin",
        "created_at": "2026-01-01T00:00:00Z"
    }
}


# ============================================================================
# SUBSCRIPTION SYSTEM (Early declaration for get_current_user)
# ============================================================================

OWNER_EMAILS = [
    "bandari.ru@northeastern.edu",
    "ruthvik299@gmail.com"
]

PRODUCT_KEYS_DB = {}
ACTIVATED_KEYS_DB = {}

def is_owner(email: str) -> bool:
    """Check if email is owner."""
    return email.lower() in [e.lower() for e in OWNER_EMAILS]

def check_subscription(email: str) -> dict:
    """Check if user has active subscription."""
    if is_owner(email):
        return {"has_subscription": True, "is_owner": True, "status": "active"}
    if email.lower() not in ACTIVATED_KEYS_DB:
        return {"has_subscription": False, "status": "no_subscription"}
    activation = ACTIVATED_KEYS_DB[email.lower()]
    expires_at = datetime.fromisoformat(activation["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires_at:
        return {"has_subscription": False, "status": "expired"}
    return {
        "has_subscription": True,
        "is_owner": False,
        "subscription_type": activation["subscription_type"],
        "expires_at": activation["expires_at"],
        "status": "active"
    }

# ============================================================================
# MODEL CONFIG
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


# ============================================================================
# ML MODEL
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
security = HTTPBearer()


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    name: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    requires_2fa: bool = False
    temp_token: Optional[str] = None
    user: Optional[Dict] = None


class Verify2FARequest(BaseModel):
    temp_token: str
    code: str


class Setup2FAResponse(BaseModel):
    secret: str
    qr_code: str
    uri: str


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    is_2fa_enabled: bool
    created_at: str


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
    description: str
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
    max_depth: int = 10


class AttackPathResponse(BaseModel):
    paths: Dict[str, List[Dict]]
    risk_summary: Dict[str, Any]
    processing_time_ms: float


# ============================================================================
# AUTH HELPERS
# ============================================================================

def create_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None


def generate_qr_code(email: str, secret: str) -> tuple[str, str]:
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name=TOTP_ISSUER)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    return f"data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode()}", uri


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    payload = verify_token(creds.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    email = payload.get("sub")
    if email not in USERS_DB:
        raise HTTPException(status_code=401, detail="User not found")
    user = USERS_DB[email]
    if user["is_2fa_enabled"] and not payload.get("2fa_ok"):
        raise HTTPException(status_code=401, detail="2FA required")
    # Check subscription (owners bypass)
    if not is_owner(email):
        sub = check_subscription(email)
        if not sub["has_subscription"]:
            raise HTTPException(status_code=403, detail="No active subscription. Please activate a product key.")
    return user


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
    if cvss is None:
        return [state.config.cvss_vocab_sizes[k] - 1 for k in CVSS_MAP.keys()]
    return [CVSS_MAP[k].get(getattr(cvss, k, None), state.config.cvss_vocab_sizes[k] - 1) for k in CVSS_MAP.keys()]


# ============================================================================
# MODEL LOADING
# ============================================================================

def load_model(model_dir: str = "../models/severity_v3"):
    """Load model from local path or download from Hugging Face"""
    from huggingface_hub import hf_hub_download, snapshot_download
    import os
    
    HF_REPO = "RuthvikBandari/ctppo-severity-model"
    model_path = Path(model_dir)
    
    # Try to download from Hugging Face if not exists locally
    if not (model_path / "checkpoint_best.pt").exists():
        print(f"Model not found locally. Downloading from Hugging Face...")
        try:
            # Create directory
            model_path.mkdir(parents=True, exist_ok=True)
            
            # Download all files from HF repo
            snapshot_download(
                repo_id=HF_REPO,
                local_dir=str(model_path),
                local_dir_use_symlinks=False
            )
            print(f"✓ Downloaded model from {HF_REPO}")
        except Exception as e:
            print(f"Warning: Could not download model: {e}")
            return False
    
    # Check again after download
    if not (model_path / "checkpoint_best.pt").exists():
        print(f"Warning: Model not found at {model_path}")
        return False
    
    # Set device
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
    state.tokenizer = DistilBertTokenizer.from_pretrained(tok_path if tok_path.exists() else state.config.model_name)
    
    # Load model
    state.model = MultiModalCVEClassifier(state.config, len(state.cwe_vocab))
    checkpoint = torch.load(model_path / "checkpoint_best.pt", map_location=state.device, weights_only=False)
    state.model.load_state_dict(checkpoint['model_state_dict'])
    state.model = state.model.to(state.device)
    state.model.eval()
    
    state.loaded = True
    print(f"✓ Model loaded (val_f1: {checkpoint.get('val_f1', 0):.4f})")
    return True
    return True

# ============================================================================
# INFERENCE
# ============================================================================

def classify_cve(req: CVEClassifyRequest) -> CVEClassifyResponse:
    if not state.loaded:
        raise HTTPException(503, "Model not loaded")
    
    start = time.time()
    enc = state.tokenizer(req.description, max_length=state.config.max_length, padding='max_length', truncation=True, return_tensors='pt')
    cvss = encode_cvss(req.cvss_vector)
    cwe_idx = state.cwe_vocab.get(req.cwe_id or '<UNK>', state.cwe_vocab.get('<UNK>', 0))
    
    numeric = torch.tensor([[req.cvss_score / 10.0, req.exploitability_score / 4.0, req.impact_score / 6.0, float(req.has_exploit), float(req.has_patch), 0.0, 0.0, 0.0]], dtype=torch.float32)
    
    with torch.no_grad():
        logits = state.model(
            enc['input_ids'].to(state.device),
            enc['attention_mask'].to(state.device),
            torch.tensor([cvss], dtype=torch.long).to(state.device),
            numeric.to(state.device),
            torch.tensor([cwe_idx], dtype=torch.long).to(state.device)
        )
        probs = torch.softmax(logits, dim=-1)
        pred = torch.argmax(logits, dim=-1).item()
    
    return CVEClassifyResponse(
        cve_id=req.cve_id,
        predicted_severity=state.config.class_names[pred],
        confidence=round(probs[0, pred].item(), 4),
        probabilities={state.config.class_names[i]: round(probs[0, i].item(), 4) for i in range(state.config.num_classes)},
        processing_time_ms=round((time.time() - start) * 1000, 2)
    )


async def lifespan(app: FastAPI):
    # Initialize database (with error handling)
    try:
        init_db()
    except Exception as e:
        print(f"⚠️ Database init failed: {e}")
    # Load model in background (non-blocking)
    async def load_model_bg():
        await asyncio.sleep(1)  # Let server start first
        load_model(os.environ.get("MODEL_DIR", "../models/severity_v3"))
    # asyncio.create_task(load_model_bg())  # Disabled - causes OOM on free tier
    yield


app = FastAPI(title="CTPPO API", description="Cyber Threat Prioritization & Path Optimization", version="3.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# AUTH ENDPOINTS
# ============================================================================

@app.post("/api/auth/register", response_model=LoginResponse)
async def register(req: RegisterRequest):
    # Check database first, fallback to in-memory
    if is_db_available():
        if db_user_exists(req.email):
            raise HTTPException(400, "Email already registered")
        user_data = db_create_user(req.email, req.name, _hash(req.password))
        if not user_data:
            raise HTTPException(500, "Failed to create user")
    else:
        if req.email in USERS_DB:
            raise HTTPException(400, "Email already registered")
        user_id = f"usr_{secrets.token_hex(4)}"
        USERS_DB[req.email] = {
            "id": user_id, "email": req.email, "name": req.name,
            "password_hash": _hash(req.password), "totp_secret": None,
            "is_2fa_enabled": False, "role": "user",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    
    access_token = create_token({"sub": req.email, "2fa_ok": True}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_token({"sub": req.email, "type": "refresh"}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    return LoginResponse(
        access_token=access_token, refresh_token=refresh_token,
        user={"id": "usr_db", "email": req.email, "name": req.name, "role": "user", "is_2fa_enabled": False}
    )



@app.post("/api/auth/login", response_model=LoginResponse)
async def login(req: LoginRequest):
    user = USERS_DB.get(req.email)
    if not user or user["password_hash"] != _hash(req.password):
        raise HTTPException(401, "Invalid credentials")
    
    if user["is_2fa_enabled"]:
        temp_token = create_token({"sub": req.email, "type": "2fa_pending"}, timedelta(minutes=5))
        return LoginResponse(access_token="", refresh_token="", requires_2fa=True, temp_token=temp_token)
    
    access_token = create_token({"sub": req.email, "2fa_ok": True}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_token({"sub": req.email, "type": "refresh"}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user={"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"], "is_2fa_enabled": user["is_2fa_enabled"]}
    )


@app.post("/api/auth/verify-2fa", response_model=LoginResponse)
async def verify_2fa(req: Verify2FARequest):
    payload = verify_token(req.temp_token)
    if not payload or payload.get("type") != "2fa_pending":
        raise HTTPException(401, "Invalid token")
    
    email = payload["sub"]
    user = USERS_DB.get(email)
    if not user or not user["totp_secret"]:
        raise HTTPException(401, "2FA not configured")
    
    if not pyotp.TOTP(user["totp_secret"]).verify(req.code, valid_window=1):
        raise HTTPException(401, "Invalid 2FA code")
    
    access_token = create_token({"sub": email, "2fa_ok": True}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_token({"sub": email, "type": "refresh"}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user={"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"], "is_2fa_enabled": True}
    )


@app.post("/api/auth/setup-2fa", response_model=Setup2FAResponse)
async def setup_2fa(user: dict = Depends(get_current_user)):
    secret = pyotp.random_base32()
    qr_code, uri = generate_qr_code(user["email"], secret)
    USERS_DB[user["email"]]["totp_secret"] = secret
    return Setup2FAResponse(secret=secret, qr_code=qr_code, uri=uri)


@app.post("/api/auth/enable-2fa")
async def enable_2fa(request: dict, user: dict = Depends(get_current_user)):
    code = request.get("code") or request.get("totp_code")
    if not code:
        raise HTTPException(400, "Code is required")
    secret = USERS_DB[user["email"]].get("totp_secret")
    if not secret:
        raise HTTPException(400, "Setup 2FA first")
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        raise HTTPException(401, "Invalid code")
    USERS_DB[user["email"]]["is_2fa_enabled"] = True
    return {"message": "2FA enabled"}


@app.post("/api/auth/disable-2fa")
async def disable_2fa(request: dict, user: dict = Depends(get_current_user)):
    code = request.get("code") or request.get("totp_code")
    if not code:
        raise HTTPException(400, "Code is required")
    secret = USERS_DB[user["email"]].get("totp_secret")
    if not secret or not pyotp.TOTP(secret).verify(code, valid_window=1):
        raise HTTPException(401, "Invalid code")
    USERS_DB[user["email"]]["is_2fa_enabled"] = False
    USERS_DB[user["email"]]["totp_secret"] = None
    return {"message": "2FA disabled"}


@app.get("/api/auth/me", response_model=UserResponse)
async def get_me(user: dict = Depends(get_current_user)):
    return UserResponse(**{k: user[k] for k in ["id", "email", "name", "role", "is_2fa_enabled", "created_at"]})


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
    return {"loaded": state.loaded, "device": str(state.device), "classes": state.config.class_names, "test_f1": "97.50%", "cwe_vocab_size": len(state.cwe_vocab)}


@app.post("/api/classify", response_model=CVEClassifyResponse)
async def classify(req: CVEClassifyRequest, user: dict = Depends(get_current_user)):
    return classify_cve(req)


@app.post("/api/classify/batch", response_model=BatchClassifyResponse)
async def classify_batch(req: BatchClassifyRequest, user: dict = Depends(get_current_user)):
    start = time.time()
    results = [classify_cve(cve) for cve in req.cves]
    return BatchClassifyResponse(results=results, total_time_ms=round((time.time() - start) * 1000, 2))


@app.post("/api/attack-paths/analyze", response_model=AttackPathResponse)
async def analyze_attack_paths(req: AttackPathRequest, user: dict = Depends(get_current_user)):
    start = time.time()
    graph = AttackGraph()
    for node in req.nodes:
        graph.add_node(node.id, node.is_entry_point, node.is_critical_asset)
    for v in req.vulnerabilities:
        graph.add_edge(Vulnerability(cve_id=v.cve_id, source=v.source, target=v.target, severity=v.severity, cvss_score=v.cvss_score, exploitability_score=v.exploitability_score, impact_score=v.impact_score, has_exploit=v.has_exploit))
    
    analyzer = NAMOAPathAnalyzer(graph)
    all_paths = analyzer.find_all_critical_paths(req.max_depth)
    summary = analyzer.get_risk_summary()
    
    return AttackPathResponse(paths={k: [p.to_dict() for p in v] for k, v in all_paths.items()}, risk_summary=summary, processing_time_ms=round((time.time() - start) * 1000, 2))


@app.get("/api/attack-paths/sample")
async def sample_attack_paths(user: dict = Depends(get_current_user)):
    start = time.time()
    graph = create_sample_network()
    analyzer = NAMOAPathAnalyzer(graph)
    all_paths = analyzer.find_all_critical_paths()
    summary = analyzer.get_risk_summary()
    return {"network": graph.to_dict(), "paths": {k: [p.to_dict() for p in v] for k, v in all_paths.items()}, "risk_summary": summary, "processing_time_ms": round((time.time() - start) * 1000, 2)}


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


# ============================================================================
# REFRESH TOKEN ENDPOINT (Missing)
# ============================================================================

@app.post("/api/auth/refresh")
async def refresh_token(request: dict):
    """Refresh access token using refresh token."""
    refresh_token = request.get("refresh_token")
    if not refresh_token:
        raise HTTPException(400, "Refresh token required")
    
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(401, "Invalid token type")
        
        email = payload.get("sub")
        if email not in USERS_DB:
            raise HTTPException(401, "User not found")
        
        # Generate new access token
        user = USERS_DB[email]
        access_token = jwt.encode({
            "sub": email,
            "type": "access",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        }, SECRET_KEY, algorithm=ALGORITHM)
        
        return {
            "access_token": access_token,
            "token_type": "bearer"
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid refresh token")


# ============================================================================
# SUBSCRIPTION SYSTEM
# ============================================================================

import secrets as sec
import string

# Owner emails (no subscription needed)
OWNER_EMAILS = [
    "bandari.ru@northeastern.edu",
    "ruthvik299@gmail.com"
]

# Product keys storage
PRODUCT_KEYS_DB = {}
ACTIVATED_KEYS_DB = {}

def generate_product_key() -> str:
    """Generate a unique product key: CTPPO-XXXX-XXXX-XXXX-XXXX"""
    chars = string.ascii_uppercase + string.digits
    segments = [''.join(sec.choice(chars) for _ in range(4)) for _ in range(4)]
    return f"CTPPO-{'-'.join(segments)}"

def create_product_key(subscription_type: str = "individual", validity_days: int = 365) -> dict:
    """Create a new product key."""
    key = generate_product_key()
    while key in PRODUCT_KEYS_DB:
        key = generate_product_key()
    
    key_data = {
        "key": key,
        "subscription_type": subscription_type,
        "validity_days": validity_days,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "is_activated": False,
        "activated_by": None,
        "expires_at": None
    }
    PRODUCT_KEYS_DB[key] = key_data
    return key_data

def is_owner(email: str) -> bool:
    """Check if email is owner."""
    return email.lower() in [e.lower() for e in OWNER_EMAILS]

def check_subscription(email: str) -> dict:
    """Check if user has active subscription."""
    if is_owner(email):
        return {"has_subscription": True, "is_owner": True, "status": "active"}
    
    if email.lower() not in ACTIVATED_KEYS_DB:
        return {"has_subscription": False, "status": "no_subscription"}
    
    activation = ACTIVATED_KEYS_DB[email.lower()]
    expires_at = datetime.fromisoformat(activation["expires_at"].replace('Z', '+00:00'))
    
    if datetime.now(timezone.utc) > expires_at:
        return {"has_subscription": False, "status": "expired"}
    
    return {
        "has_subscription": True,
        "is_owner": False,
        "subscription_type": activation["subscription_type"],
        "expires_at": activation["expires_at"],
        "status": "active"
    }


class ProductKeyActivation(BaseModel):
    product_key: str
    email: EmailStr


@app.post("/api/subscription/activate")
async def activate_product_key(data: ProductKeyActivation):
    """Activate a product key for a user."""
    if is_owner(data.email):
        return {"success": True, "message": "Owner account - no activation required", "is_owner": True}
    
    if data.product_key not in PRODUCT_KEYS_DB:
        raise HTTPException(400, "Invalid product key")
    
    key_data = PRODUCT_KEYS_DB[data.product_key]
    
    if key_data["is_activated"]:
        raise HTTPException(400, "Product key already activated")
    
    expires_at = datetime.now(timezone.utc) + timedelta(days=key_data["validity_days"])
    
    key_data["is_activated"] = True
    key_data["activated_by"] = data.email
    key_data["expires_at"] = expires_at.isoformat()
    
    ACTIVATED_KEYS_DB[data.email.lower()] = {
        "key": data.product_key,
        "subscription_type": key_data["subscription_type"],
        "expires_at": expires_at.isoformat()
    }
    
    return {
        "success": True,
        "message": "Product key activated",
        "subscription_type": key_data["subscription_type"],
        "expires_at": expires_at.isoformat()
    }


@app.post("/api/subscription/check")
async def check_user_subscription(email: str):
    """Check subscription status."""
    return check_subscription(email)


@app.post("/api/subscription/generate-key")
async def generate_key(subscription_type: str = "individual", validity_days: int = 365, admin_secret: str = ""):
    """Generate a new product key (admin only)."""
    if admin_secret != os.environ.get("ADMIN_SECRET", "ctppo-admin-2026"):
        raise HTTPException(403, "Invalid admin credentials")
    
    key_data = create_product_key(subscription_type, validity_days)
    return {"success": True, "product_key": key_data["key"], "validity_days": validity_days}


# Generate demo keys on startup
_demo_keys = [
    create_product_key("individual", 30),
    create_product_key("individual", 365),
    create_product_key("enterprise", 365),
]
# print("=" * 60)
# print("CTPPO - Demo Product Keys Generated:")
# print("=" * 60)
# for k in _demo_keys:
#     print(f"  {k['key']} ({k['subscription_type']}, {k['validity_days']} days)")
# print("=" * 60)
# # ============================================================================
# ADMIN ENDPOINTS - Add these to server_secure.py before the last lines
# ============================================================================

import os

# Add this near the top with other configs
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "ctppo-admin-2026")

# Add these endpoints after the subscription endpoints

@app.post("/api/admin/verify")
async def verify_admin(request: dict):
    """Verify admin secret"""
    if request.get("admin_secret") != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Invalid admin secret")
    return {"success": True}


@app.get("/api/admin/keys")
async def get_all_keys(admin_secret: str):
    """Get all product keys"""
    if admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Invalid admin secret")
    
    keys = []
    for key, data in PRODUCT_KEYS_DB.items():
        # Check if key is used
        used_by = None
        for email, activation in ACTIVATED_KEYS_DB.items():
            if activation.get("product_key") == key:
                used_by = email
                break
        
        keys.append({
            "key": key,
            "subscription_type": data["subscription_type"],
            "validity_days": data["validity_days"],
            "created_at": data["created_at"],
            "used": used_by is not None,
            "used_by": used_by
        })
    
    return {"keys": keys}


@app.get("/api/admin/activations")
async def get_all_activations(admin_secret: str):
    """Get all activated subscriptions"""
    if admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Invalid admin secret")
    
    activations = []
    for email, data in ACTIVATED_KEYS_DB.items():
        activations.append({
            "email": email,
            "subscription_type": data["subscription_type"],
            "activated_at": data["activated_at"],
            "expires_at": data["expires_at"]
        })
    
    return {"activations": activations}


@app.post("/api/admin/generate-key")
async def admin_generate_key(request: dict):
    """Generate a new product key"""
    if request.get("admin_secret") != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Invalid admin secret")
    
    subscription_type = request.get("subscription_type", "individual")
    validity_days = request.get("validity_days", 365)
    
    key = create_product_key(subscription_type, validity_days)
    
    return {
        "key": key,
        "subscription_type": subscription_type,
        "validity_days": validity_days
    }


@app.post("/api/admin/revoke-key")
async def revoke_key(request: dict):
    """Revoke a product key"""
    if request.get("admin_secret") != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Invalid admin secret")
    
    product_key = request.get("product_key")
    
    if product_key in PRODUCT_KEYS_DB:
        del PRODUCT_KEYS_DB[product_key]
    
    # Also remove from activated keys if used
    to_remove = None
    for email, data in ACTIVATED_KEYS_DB.items():
        if data.get("product_key") == product_key:
            to_remove = email
            break
    
    if to_remove:
        del ACTIVATED_KEYS_DB[to_remove]
    
    return {"success": True, "message": "Key revoked successfully"}
