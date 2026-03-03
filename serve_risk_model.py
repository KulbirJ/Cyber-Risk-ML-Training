# serve_risk_model.py
"""
FastAPI server that serves the cyber risk model via HTTP.

Endpoints:
  POST /predict - Takes a CVE ID, enriches it with NVD + EPSS data,
                   loads the trained model, and returns risk score + severity

Example usage:
  curl -X POST "http://localhost:8000/predict" \
    -H "Content-Type: application/json" \
    -d '{"cve_id": "CVE-2025-11749"}'
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict
import requests
import json
import os
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
import numpy as np
from xgboost import XGBRegressor
import uvicorn

# Load environment variables from .env file
load_dotenv()

# ── Configuration ────────────────────────────────────────────────────────────

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# NVD API Key from environment variable (loaded from .env)
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
if not NVD_API_KEY:
    raise ValueError("NVD_API_KEY not found in environment. Please set it in .env file.")

MODEL_PATH = "cyber_risk_model_v1.json"

# ── Set up FastAPI app ───────────────────────────────────────────────────────

app = FastAPI(
    title="Cyber Risk Scoring API",
    description="ML-powered CVE risk assessment and severity classification",
    version="1.0"
)

# ── Request/Response models ──────────────────────────────────────────────────

class CVEPredictionRequest(BaseModel):
    """Request payload for risk prediction"""
    cve_id: str  # e.g. "CVE-2025-11749"
    
    model_config = ConfigDict(
        json_schema_extra={"example": {"cve_id": "CVE-2025-11749"}}
    )


class RiskPredictionResponse(BaseModel):
    """Response payload with risk assessment"""
    cve_id: str
    cvss_score: float
    epss_score: float
    days_since_published: int
    text_length_of_description: int
    attack_count: int
    
    predicted_risk_score: float
    severity_label: str  # Low, Medium, High, Critical
    priority_score: float  # 0-100, derived from risk_score
    
    enrichment_source: str  # "NVD", "API", etc.
    timestamp: str

# ── Helper: Fetch CVE from NVD API ──────────────────────────────────────────

def fetch_cve_from_nvd(cve_id: str) -> dict:
    """
    Fetches single CVE details from NVD API.
    
    Args:
        cve_id: CVE identifier (e.g. "CVE-2025-11749")
    
    Returns:
        Dictionary with CVSS, description, and published date
    """
    try:
        # Build URL with CVE ID parameter
        url = f"{NVD_API_URL}?cveId={cve_id}"
        headers = {"apiKey": NVD_API_KEY}
        
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            raise ValueError(f"CVE not found in NVD: {cve_id}")
        
        # Extract the first (and should be only) match
        cve = vulnerabilities[0]["cve"]
        
        # Parse CVSS score (prefer v3.1)
        cvss_score = None
        metrics = cve.get("metrics", {})
        
        if metrics.get("cvssMetricV31"):
            cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif metrics.get("cvssMetricV40"):
            cvss_score = metrics["cvssMetricV40"][0]["cvssData"]["baseScore"]
        elif metrics.get("cvssMetricV2"):
            cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        
        # Extract description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else ""
        )
        
        # Extract published date
        published = cve.get("published", "")
        
        return {
            "cve_id": cve.get("id", cve_id),
            "cvss_score": cvss_score,
            "description": description,
            "published": published
        }
    
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"NVD API error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch CVE: {str(e)}")


# ── Helper: Fetch EPSS score ─────────────────────────────────────────────────

def fetch_epss_score(cve_id: str) -> float:
    """
    Fetches EPSS score from FIRST.org API.
    
    Args:
        cve_id: CVE identifier
    
    Returns:
        EPSS score (0.0 - 1.0), or 0.0 if not found
    """
    try:
        # Build URL manually to avoid colon encoding issues
        url = f"{EPSS_API_URL}?cve={cve_id}"
        
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get("data"):
            epss_str = data["data"][0].get("epss", None)
            if epss_str:
                return float(epss_str)
        
        return 0.0  # Default to 0 if not found
    
    except Exception:
        # If EPSS fetch fails, return 0 (conservative assumption)
        return 0.0


# ── Helper: Calculate days since published ──────────────────────────────────

def calculate_days_since_published(published_str: str) -> int:
    """
    Calculates days elapsed since CVE publication date.
    
    Args:
        published_str: ISO 8601 date string (e.g. "2025-11-02T22:15:33.407")
    
    Returns:
        Number of days since publication
    """
    try:
        pub_date = datetime.fromisoformat(published_str.rstrip("Z"))
        if pub_date.tzinfo is None:
            pub_date = pub_date.replace(tzinfo=timezone.utc)
        
        today = datetime.now(timezone.utc)
        delta = today - pub_date
        return delta.days
    
    except Exception:
        return 0


# ── Helper: Assign severity label ────────────────────────────────────────────

def assign_severity_label(cvss_score: float, epss_score: float) -> str:
    """
    Assigns a severity label based on CVSS and EPSS scores.
    
    Logic:
      - CRITICAL: EPSS > 0.7 OR CVSS >= 9.0
      - HIGH:     CVSS >= 7.0 AND (EPSS > 0.2 OR CVSS >= 8.5)
      - MEDIUM:   CVSS >= 5.0 AND (EPSS > 0.05 OR CVSS >= 6.5)
      - LOW:      Everything else
    """
    if epss_score > 0.7 or cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0 and (epss_score > 0.2 or cvss_score >= 8.5):
        return "High"
    elif cvss_score >= 5.0 and (epss_score > 0.05 or cvss_score >= 6.5):
        return "Medium"
    else:
        return "Low"


# ── Helper: Calculate priority score ─────────────────────────────────────────

def calculate_priority_score(risk_score: float) -> float:
    """
    Converts risk score to a 0-100 priority scale.
    
    Priority = min(100, risk_score * 2)
    This is because risk_score ranges 0-~65, so multiply by ~1.5-2 to get 0-100
    """
    # Normalize to 0-100 scale
    # Assuming max risk_score is ~60 (10 * 1.5 + 1 * 50)
    priority = (risk_score / 60.0) * 100.0
    return min(100.0, max(0.0, priority))  # Clamp to 0-100


# ── Main prediction endpoint ─────────────────────────────────────────────────

@app.post(
    "/predict",
    response_model=RiskPredictionResponse,
    summary="Predict CVE Risk Score",
    description="Fetches CVE data from NVD, enriches with EPSS, and predicts risk"
)
async def predict_cve_risk(request: CVEPredictionRequest):
    """
    Main endpoint: Takes a CVE ID and returns risk prediction.
    
    Process:
      1. Fetch CVE details from NVD API
      2. Fetch EPSS score from FIRST.org
      3. Calculate days since published
      4. Load pre-trained XGBoost model
      5. Prepare features and make prediction
      6. Determine severity and priority
      7. Return comprehensive JSON response
    """
    
    cve_id = request.cve_id.upper()
    
    # ── Step 1: Enrich CVE with NVD data ─────────────────────────────────────
    
    cve_data = fetch_cve_from_nvd(cve_id)
    cvss_score = cve_data.get("cvss_score", 5.0)
    description = cve_data.get("description", "")
    published = cve_data.get("published", "")
    
    # ── Step 2: Fetch EPSS score ─────────────────────────────────────────────
    
    epss_score = fetch_epss_score(cve_id)
    
    # ── Step 3: Calculate derived features ────────────────────────────────────
    
    days_since = calculate_days_since_published(published)
    text_length = len(description)
    attack_count = 0  # Placeholder; could fetch from exploit DBs
    
    # ── Step 4: Load model ───────────────────────────────────────────────────
    
    try:
        model = XGBRegressor()
        model.load_model(MODEL_PATH)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load model: {str(e)}"
        )
    
    # ── Step 5: Create feature vector ────────────────────────────────────────
    # Must match training features in same order:
    # ["cvss_score", "epss_score", "days_since_published", "attack_count"]
    
    features = np.array([
        [cvss_score, epss_score, days_since, attack_count]
    ])
    
    # ── Step 6: Make prediction ──────────────────────────────────────────────
    
    predicted_risk_score = float(model.predict(features)[0])
    
    # ── Step 7: Determine severity ──────────────────────────────────────────
    
    severity = assign_severity_label(cvss_score, epss_score)
    
    # ── Step 8: Calculate priority score ────────────────────────────────────
    
    priority_score = calculate_priority_score(predicted_risk_score)
    
    # ── Step 9: Build response ──────────────────────────────────────────────
    
    response = RiskPredictionResponse(
        cve_id=cve_id,
        cvss_score=cvss_score,
        epss_score=epss_score,
        days_since_published=days_since,
        text_length_of_description=text_length,
        attack_count=attack_count,
        predicted_risk_score=predicted_risk_score,
        severity_label=severity,
        priority_score=priority_score,
        enrichment_source="NVD + EPSS",
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    
    return response


# ── Health check endpoint ────────────────────────────────────────────────────

@app.get(
    "/health",
    summary="Health Check",
    description="Returns API status and model info"
)
async def health_check():
    """
    Simple health check endpoint.
    Verifies model can be loaded.
    """
    try:
        model = XGBRegressor()
        model.load_model(MODEL_PATH)
        return {
            "status": "healthy",
            "model": "XGBRegressor",
            "model_path": MODEL_PATH,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Model load failed: {str(e)}"
        )


# ── Root endpoint ────────────────────────────────────────────────────────────

@app.get(
    "/",
    summary="API Information",
    description="Returns API documentation and available endpoints"
)
async def root():
    """
    Root endpoint with API information.
    """
    return {
        "name": "Cyber Risk Scoring API",
        "version": "1.0",
        "description": "ML-powered CVE risk assessment",
        "endpoints": {
            "POST /predict": "Predict risk score for a CVE",
            "GET /health": "Health check",
            "GET /docs": "Interactive API documentation (Swagger)"
        },
        "example_request": {
            "cve_id": "CVE-2025-11749"
        }
    }


# ── Example usage / batch prediction ────────────────────────────────────────

@app.post(
    "/predict-batch",
    summary="Batch Predict (Multiple CVEs)",
    description="Predict risk scores for multiple CVEs"
)
async def predict_batch(cve_ids: list[str]):
    """
    Batch prediction endpoint for multiple CVEs.
    
    Args:
        cve_ids: List of CVE IDs (e.g. ["CVE-2025-11749", "CVE-2025-12604"])
    
    Returns:
        List of predictions
    """
    results = []
    
    for cve_id in cve_ids:
        try:
            request = CVEPredictionRequest(cve_id=cve_id)
            prediction = await predict_cve_risk(request)
            results.append(prediction)
        except Exception as e:
            results.append({
                "cve_id": cve_id,
                "error": str(e)
            })
    
    return results


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("""
╔════════════════════════════════════════════════════════════╗
║     CYBER RISK MODEL API SERVER                           ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  Starting FastAPI server...                                ║
║                                                            ║
║  📊 Endpoints:                                             ║
║   • GET  http://localhost:8000/              (info)       ║
║   • GET  http://localhost:8000/health        (status)     ║
║   • POST http://localhost:8000/predict       (single CVE) ║
║   • POST http://localhost:8000/predict-batch (multiple)   ║
║   • GET  http://localhost:8000/docs          (Swagger UI) ║
║                                                            ║
║  💾 Model: cyber_risk_model_v1.json                        ║
║  🔑 API Keys: NVD + EPSS configured                        ║
║                                                            ║
║  Example curl command:                                     ║
║  --------------------------------------------------         ║
║  curl -X POST http://localhost:8000/predict \\             ║
║    -H "Content-Type: application/json" \\                 ║
║    -d '{\"cve_id\": \"CVE-2025-11749\"}'                   ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    # Start the server
    # host="0.0.0.0" to listen on all interfaces
    # port=8000 is the default
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=False
    )
