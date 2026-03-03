#!/usr/bin/env python3
"""
Cyber Risk Model v3 - FastAPI Deployment
==========================================

Enhanced API that uses v3 models with 28 features.
This version can:
  1. Serve predictions for CVEs from the enriched dataset
  2. Provide real-time prediction with simplified features
  3. Compare v1 vs v3 predictions

Usage:
  python deploy_model_v3.py

Then visit:
  - http://localhost:8000/docs (Swagger UI)
  - http://localhost:8000/predict (POST endpoint)
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict
import requests
import json
import os
import pandas as pd
from datetime import datetime, timezone
from dotenv import load_dotenv
import numpy as np
from xgboost import XGBRegressor, XGBClassifier
import uvicorn

# Load environment variables
load_dotenv()

# ── Configuration ────────────────────────────────────────────────────────────

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# Model paths
REGRESSOR_PATH = "cyber_risk_model_v3.json"
CLASSIFIER_PATH = "cyber_risk_severity_model_v3.json"
ENRICHED_DATA_PATH = "cves_enhanced_tier3.csv"

# Load enhanced CVE data for demo/testing
try:
    enriched_df = pd.read_csv(ENRICHED_DATA_PATH)
    ENRICHED_CVES = {row['cve_id']: row.to_dict() for _, row in enriched_df.iterrows()}
    print(f"✓ Loaded {len(ENRICHED_CVES)} enriched CVEs from {ENRICHED_DATA_PATH}")
except FileNotFoundError:
    ENRICHED_CVES = {}
    print(f"⚠ Enriched data file not found: {ENRICHED_DATA_PATH}")

# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="Cyber Risk Scoring API - Model v3",
    description="Production-ready CVE risk assessment (28 features)",
    version="3.0"
)

# ── Request/Response Models ──────────────────────────────────────────────────

class PredictionRequest(BaseModel):
    """Request for risk prediction"""
    cve_id: str
    use_enriched_data: bool = True  # Use pre-computed enrichment if available
    model_config = ConfigDict(json_schema_extra={"example": {"cve_id": "CVE-2025-12604"}})


class PredictionResponse(BaseModel):
    """Risk prediction response"""
    cve_id: str
    model_version: str
    
    # Input features
    cvss_score: float
    epss_score: float
    days_since_published: int
    
    # Predictions
    predicted_risk_score: float
    severity_label: str
    severity_numeric: int
    confidence: float
    
    # Metadata
    data_source: str
    timestamp: str
    features_available: int


def fetch_cve_from_nvd(cve_id: str) -> dict:
    """Fetch CVE from NVD API"""
    try:
        if not NVD_API_KEY:
            raise ValueError("NVD_API_KEY not configured")
        
        url = f"{NVD_API_URL}?cveId={cve_id}"
        headers = {"apiKey": NVD_API_KEY}
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            raise ValueError(f"CVE not found: {cve_id}")
        
        cve = vulnerabilities[0]["cve"]
        
        # Extract CVSS
        cvss_score = 5.0
        metrics = cve.get("metrics", {})
        if metrics.get("cvssMetricV31"):
            cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif metrics.get("cvssMetricV40"):
            cvss_score = metrics["cvssMetricV40"][0]["cvssData"]["baseScore"]
        
        # Extract published date
        published = cve.get("published", "")
        
        return {
            "cve_id": cve.get("id", cve_id),
            "cvss_score": cvss_score,
            "published": published
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"NVD API error: {str(e)}")


def fetch_epss_score(cve_id: str) -> float:
    """Fetch EPSS score"""
    try:
        url = f"{EPSS_API_URL}?cve={cve_id}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("data"):
            epss_str = data["data"][0].get("epss", None)
            if epss_str:
                return float(epss_str)
        return 0.0
    except Exception:
        return 0.0


def calculate_days_since_published(published_str: str) -> int:
    """Calculate days since CVE publication"""
    try:
        pub_date = datetime.fromisoformat(published_str.rstrip("Z"))
        if pub_date.tzinfo is None:
            pub_date = pub_date.replace(tzinfo=timezone.utc)
        today = datetime.now(timezone.utc)
        return (today - pub_date).days
    except Exception:
        return 0


def prepare_features_v3(cve_data: dict) -> tuple:
    """
    Prepare feature vector for v3 model (28 features).
    
    For live predictions, we estimate missing enrichment features.
    For enriched data, we use actual computed values.
    """
    # Base features (always available)
    cvss_score = cve_data.get("cvss_score", 5.0)
    epss_score = cve_data.get("epss_score", 0.0)
    days_since = cve_data.get("days_since_published", 0)
    
    # Initialize 28-feature vector with defaults
    features = np.zeros(28)
    
    # Fill available features (indices must match training order)
    feature_mapping = {
        0: ("cvss_score", cvss_score),
        1: ("epss_score", epss_score),
        2: ("days_since_published", days_since),
        # Additional binary features (default to 0 for live predictions)
        3: ("in_cisa_kev", cve_data.get("in_cisa_kev", 0)),
        4: ("has_public_poc", cve_data.get("has_public_poc", 0)),
        5: ("poc_count", cve_data.get("poc_count", 0)),
        6: ("affected_packages_count", cve_data.get("affected_packages_count", 0)),
        7: ("has_fixed_version", cve_data.get("has_fixed_version", 0)),
        8: ("requires_authentication", cve_data.get("requires_authentication", 0)),
        9: ("requires_user_interaction", cve_data.get("requires_user_interaction", 0)),
        10: ("scope_changed", cve_data.get("scope_changed", 0)),
        11: ("in_github_advisories", cve_data.get("in_github_advisories", 0)),
        12: ("github_affected_count", cve_data.get("github_affected_count", 0)),
        13: ("patch_available", cve_data.get("patch_available", 0)),
        14: ("otx_threat_score", cve_data.get("otx_threat_score", 0)),
        15: ("malware_associated", cve_data.get("malware_associated", 0)),
        16: ("active_exploits", cve_data.get("active_exploits", 0)),
        17: ("metasploit_modules", cve_data.get("metasploit_modules", 0)),
        18: ("has_metasploit_module", cve_data.get("has_metasploit_module", 0)),
        19: ("censys_exposed_count", cve_data.get("censys_exposed_count", 0)),
        20: ("has_censys_data", cve_data.get("has_censys_data", 0)),
        21: ("is_critical_cvss", cve_data.get("is_critical_cvss", 0)),
        22: ("is_high_cvss", cve_data.get("is_high_cvss", 0)),
        # Encoded categorical features
        23: ("attack_vector_encoded", cve_data.get("attack_vector_encoded", 1)),
        24: ("primary_ecosystem_encoded", cve_data.get("primary_ecosystem_encoded", 0)),
        25: ("min_exploit_difficulty_encoded", cve_data.get("min_exploit_difficulty_encoded", 0)),
        26: ("module_rank_encoded", cve_data.get("module_rank_encoded", 0)),
        27: ("module_type_encoded", cve_data.get("module_type_encoded", 0)),
    }
    
    for idx, (name, value) in feature_mapping.items():
        features[idx] = float(value)
    
    return features, cvss_score, epss_score, days_since


@app.post("/predict", response_model=PredictionResponse)
async def predict(request: PredictionRequest):
    """
    Predict CVE risk using model v3.
    
    If use_enriched_data=True and CVE is in enriched dataset, uses actual enrichment.
    Otherwise, computes features from NVD API (simplified).
    """
    cve_id = request.cve_id.upper()
    data_source = "unknown"
    
    # ── Try to use enriched data first ────────────────────────────────────────
    
    if request.use_enriched_data and cve_id in ENRICHED_CVES:
        cve_data = ENRICHED_CVES[cve_id].copy()
        data_source = "enriched_dataset"
        cvss_score = cve_data.get("cvss_score", 5.0)
        epss_score = cve_data.get("epss_score", 0.0)
        days_since = cve_data.get("days_since_published", 0)
        features_available = 28
        
        # Encode categorical features
        attack_vector_map = {"network": 3, "adjacent_network": 2, "local": 1, "physical": 0, "unknown": -1}
        cve_data["attack_vector_encoded"] = attack_vector_map.get(str(cve_data.get("attack_vector", "unknown")).lower(), -1)
        
    else:
        # ── Fetch from NVD + EPSS (live prediction) ──────────────────────────
        
        try:
            nvd_data = fetch_cve_from_nvd(cve_id)
            cve_data = nvd_data.copy()
            
            epss_score = fetch_epss_score(cve_id)
            cve_data["epss_score"] = epss_score
            
            cvss_score = cve_data.get("cvss_score", 5.0)
            days_since = calculate_days_since_published(cve_data.get("published", ""))
            cve_data["days_since_published"] = days_since
            
            data_source = "nvd_live"
            features_available = 3  # Only basic features available
            
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to fetch CVE: {str(e)}")
    
    # ── Prepare features and load models ─────────────────────────────────────
    
    try:
        features, _, _, _ = prepare_features_v3(cve_data)
        
        # Load models
        regressor = XGBRegressor()
        regressor.load_model(REGRESSOR_PATH)
        
        classifier = XGBClassifier()
        classifier.load_model(CLASSIFIER_PATH)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model loading error: {str(e)}")
    
    # ── Make predictions ─────────────────────────────────────────────────────
    
    try:
        # Reshape for prediction
        X = features.reshape(1, -1)
        
        # Risk score prediction
        risk_score = float(regressor.predict(X)[0])
        
        # Severity classification
        severity_numeric = int(classifier.predict(X)[0])
        severity_labels = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
        severity_label = severity_labels.get(severity_numeric, "Unknown")
        
        # Model confidence (use probability from classifier)
        prob = classifier.predict_proba(X)
        confidence = float(np.max(prob[0]))
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")
    
    # ── Build response ───────────────────────────────────────────────────────
    
    return PredictionResponse(
        cve_id=cve_id,
        model_version="v3",
        cvss_score=cvss_score,
        epss_score=epss_score,
        days_since_published=days_since,
        predicted_risk_score=risk_score,
        severity_label=severity_label,
        severity_numeric=severity_numeric,
        confidence=confidence,
        data_source=data_source,
        timestamp=datetime.now(timezone.utc).isoformat(),
        features_available=features_available
    )


@app.get("/health")
async def health():
    """Health check - verify models can load"""
    try:
        regressor = XGBRegressor()
        regressor.load_model(REGRESSOR_PATH)
        classifier = XGBClassifier()
        classifier.load_model(CLASSIFIER_PATH)
        
        return {
            "status": "healthy",
            "model_version": "v3",
            "regressor": REGRESSOR_PATH,
            "classifier": CLASSIFIER_PATH,
            "enriched_cves": len(ENRICHED_CVES),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model load error: {str(e)}")


@app.get("/")
async def root():
    """API information"""
    return {
        "name": "Cyber Risk Scoring API - Model v3",
        "version": "3.0",
        "features": 28,
        "models": {
            "regressor": "XGBRegressor (risk score prediction)",
            "classifier": "XGBClassifier (severity classification)"
        },
        "endpoints": {
            "POST /predict": "Predict CVE risk",
            "GET /health": "Health check",
            "GET /docs": "Interactive API docs (Swagger)"
        },
        "example": {
            "method": "POST",
            "url": "/predict",
            "body": {"cve_id": "CVE-2025-12604", "use_enriched_data": True}
        }
    }


if __name__ == "__main__":
    print(f"""
╔════════════════════════════════════════════════════════════╗
║   CYBER RISK MODEL v3 - PRODUCTION DEPLOYMENT              ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  Starting FastAPI server on http://localhost:8000          ║
║                                                            ║
║  Features: 28 (TIER 1-3 enrichment)                        ║
║  Regressor: Test MAE=0.0058, R²=0.9806                     ║
║  Classifier: Test Accuracy=100%, F1=1.0                    ║
║                                                            ║
║  Available Endpoints:                                      ║
║  • POST http://localhost:8000/predict                      ║
║  • GET  http://localhost:8000/health                       ║
║  • GET  http://localhost:8000/docs (Swagger)               ║
║                                                            ║
║  Enriched CVEs in dataset: {len(ENRICHED_CVES)}                          ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
