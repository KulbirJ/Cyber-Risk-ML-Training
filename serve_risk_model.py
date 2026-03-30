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
from xgboost import XGBRegressor, XGBClassifier
import uvicorn
import time
import csv
import io
from typing import Any, Dict, List, Optional

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
V3_REGRESSOR_PATH = "cyber_risk_model_v3.json"
V3_CLASSIFIER_PATH = "cyber_risk_severity_model_v3.json"

# V3 feature order (28 features) — must match training column order
V3_FEATURE_COLUMNS = [
    "cvss_score", "epss_score", "days_since_published",
    "in_cisa_kev", "has_public_poc", "poc_count",
    "affected_packages_count", "has_fixed_version",
    "requires_authentication", "requires_user_interaction", "scope_changed",
    "in_github_advisories", "github_affected_count", "patch_available",
    "otx_threat_score", "malware_associated", "active_exploits",
    "metasploit_modules", "has_metasploit_module",
    "censys_exposed_count", "has_censys_data",
    "is_critical_cvss", "is_high_cvss",
    "attack_vector", "primary_ecosystem",
    "min_exploit_difficulty", "module_rank", "module_type",
]

# Categorical encoding maps (match training pipeline)
ATTACK_VECTOR_MAP = {"network": 3, "adjacent_network": 2, "local": 1, "physical": 0, "unknown": -1}
ECOSYSTEM_MAP = {"npm": 6, "pypi": 5, "maven": 4, "nuget": 3, "go": 2, "rubygems": 1, "unknown": 0}
DIFFICULTY_MAP = {"easy": 3, "medium": 2, "hard": 1, "unknown": 0}
RANK_MAP = {"excellent": 4, "great": 3, "good": 2, "normal": 1, "unknown": 0}
TYPE_MAP = {"exploit": 3, "auxiliary": 2, "post": 1, "unknown": 0}

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


# ═══════════════════════════════════════════════════════════════════════════
# Batch Enrich + Score Endpoint (v3 model, 28 features, 3-tier enrichment)
# ═══════════════════════════════════════════════════════════════════════════

# ── Tier 1 enrichment helpers ────────────────────────────────────────────────

_CISA_KEV_CACHE: Dict[str, Dict] = {}
_CISA_KEV_LOADED = False
_REQUEST_TIMEOUT = 5


def _load_cisa_kev() -> None:
    """Fetch CISA KEV catalogue into a module-level cache (called once)."""
    global _CISA_KEV_CACHE, _CISA_KEV_LOADED
    if _CISA_KEV_LOADED:
        return
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        for vuln in resp.json().get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "").strip().upper()
            if cve_id:
                _CISA_KEV_CACHE[cve_id] = vuln
    except Exception:
        pass
    _CISA_KEV_LOADED = True


def _enrich_tier1(cve_id: str) -> Dict[str, Any]:
    """Tier 1: CISA KEV + Exploit-DB PoC + OSV."""
    _load_cisa_kev()
    features: Dict[str, Any] = {
        "in_cisa_kev": 0,
        "has_public_poc": 0,
        "poc_count": 0,
        "affected_packages_count": 0,
        "has_fixed_version": 0,
    }

    # CISA KEV
    if cve_id in _CISA_KEV_CACHE:
        features["in_cisa_kev"] = 1

    # OSV (affected packages + fix status)
    try:
        resp = requests.post(
            "https://api.osv.dev/v1/query",
            json={"query": cve_id},
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.ok:
            vulns = resp.json().get("vulns", [])
            packages: set = set()
            has_fix = False
            for v in vulns:
                for item in v.get("affected", []):
                    pkg = item.get("package", {}).get("name", "")
                    if pkg:
                        packages.add(pkg)
                    for rng in item.get("ranges", []):
                        for evt in rng.get("events", []):
                            if "fixed" in evt:
                                has_fix = True
            features["affected_packages_count"] = len(packages)
            features["has_fixed_version"] = 1 if has_fix else 0
            if packages:
                features["has_public_poc"] = 1
                features["poc_count"] = len(packages)
    except Exception:
        pass
    return features


def _enrich_tier2(cve_id: str, nvd_metrics: Optional[Dict] = None) -> Dict[str, Any]:
    """Tier 2: NVD CVSS vector details + GitHub advisories + OTX."""
    features: Dict[str, Any] = {
        "attack_vector": "unknown",
        "requires_authentication": 0,
        "requires_user_interaction": 0,
        "scope_changed": 0,
        "in_github_advisories": 0,
        "github_affected_count": 0,
        "patch_available": 0,
        "otx_threat_score": 0,
        "malware_associated": 0,
        "active_exploits": 0,
    }

    # NVD CVSS vector details (re-use metrics already fetched for base score)
    if nvd_metrics:
        cvss_data_list = nvd_metrics.get("cvssMetricV31") or nvd_metrics.get("cvssMetricV30") or []
        if cvss_data_list:
            cvss = cvss_data_list[0].get("cvssData", {})
            features["attack_vector"] = cvss.get("attackVector", "unknown").lower()
            priv = cvss.get("privilegesRequired", "NONE")
            features["requires_authentication"] = 0 if priv.upper() == "NONE" else 1
            ui = cvss.get("userInteraction", "NONE")
            features["requires_user_interaction"] = 0 if ui.upper() == "NONE" else 1
            scope = cvss.get("scope", "UNCHANGED")
            features["scope_changed"] = 1 if scope.upper() == "CHANGED" else 0

    # GitHub advisory search
    try:
        resp = requests.get(
            f"https://api.github.com/search/repositories?q=security+advisory+{cve_id}",
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.ok:
            data = resp.json()
            if data.get("total_count", 0) > 0:
                features["in_github_advisories"] = 1
                features["github_affected_count"] = min(data["total_count"], 100)
                features["patch_available"] = 1
    except Exception:
        pass

    # OTX threat intel
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/pulses/search?q={cve_id}",
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.ok:
            results = resp.json().get("results", [])
            if results:
                features["otx_threat_score"] = min(len(results) * 10, 100)
                for pulse in results:
                    tags = [t.lower() for t in pulse.get("tags", [])]
                    if any(t in tags for t in ["malware", "ransomware", "trojan"]):
                        features["malware_associated"] = 1
                    if any(t in tags for t in ["exploit", "poc", "0day", "zero-day"]):
                        features["active_exploits"] = 1
    except Exception:
        pass
    return features


def _enrich_tier3(cve_id: str) -> Dict[str, Any]:
    """Tier 3: Metasploit + Censys (best-effort, short timeouts)."""
    features: Dict[str, Any] = {
        "metasploit_modules": 0,
        "has_metasploit_module": 0,
        "censys_exposed_count": 0,
        "has_censys_data": 0,
    }
    # Metasploit via Exploit-DB search
    try:
        resp = requests.get(
            "https://www.exploit-db.com/api/search",
            params={"q": cve_id, "type": "metasploit"},
            timeout=(2, 3),
            allow_redirects=False,
        )
        if resp.ok:
            results = resp.json().get("results", [])
            features["metasploit_modules"] = len(results)
            features["has_metasploit_module"] = 1 if results else 0
    except Exception:
        pass

    # Censys only if API keys are present
    censys_id = os.getenv("CENSYS_API_ID", "")
    censys_secret = os.getenv("CENSYS_API_SECRET", "")
    if censys_id and censys_secret:
        try:
            resp = requests.post(
                "https://api.censys.io/v1/search/ipv4",
                json={"q": f'"{cve_id}"', "page": 1, "fields": ["ip"]},
                auth=(censys_id, censys_secret),
                timeout=(2, 3),
                allow_redirects=False,
            )
            if resp.ok:
                total = resp.json().get("metadata", {}).get("count", 0)
                features["censys_exposed_count"] = total
                features["has_censys_data"] = 1 if total > 0 else 0
        except Exception:
            pass
    return features


def _build_v3_feature_vector(raw: Dict[str, Any]) -> np.ndarray:
    """Convert a raw feature dict into a 28-element numpy vector (v3 format)."""
    vec = np.zeros(28)
    cvss = raw.get("cvss_score", 5.0)
    vec[0] = cvss
    vec[1] = raw.get("epss_score", 0.0)
    vec[2] = raw.get("days_since_published", 0)
    vec[3] = raw.get("in_cisa_kev", 0)
    vec[4] = raw.get("has_public_poc", 0)
    vec[5] = raw.get("poc_count", 0)
    vec[6] = raw.get("affected_packages_count", 0)
    vec[7] = raw.get("has_fixed_version", 0)
    vec[8] = raw.get("requires_authentication", 0)
    vec[9] = raw.get("requires_user_interaction", 0)
    vec[10] = raw.get("scope_changed", 0)
    vec[11] = raw.get("in_github_advisories", 0)
    vec[12] = raw.get("github_affected_count", 0)
    vec[13] = raw.get("patch_available", 0)
    vec[14] = raw.get("otx_threat_score", 0)
    vec[15] = raw.get("malware_associated", 0)
    vec[16] = raw.get("active_exploits", 0)
    vec[17] = raw.get("metasploit_modules", 0)
    vec[18] = raw.get("has_metasploit_module", 0)
    vec[19] = raw.get("censys_exposed_count", 0)
    vec[20] = raw.get("has_censys_data", 0)
    vec[21] = 1 if cvss >= 9.0 else 0   # is_critical_cvss
    vec[22] = 1 if cvss >= 7.0 else 0   # is_high_cvss
    vec[23] = ATTACK_VECTOR_MAP.get(str(raw.get("attack_vector", "unknown")).lower(), -1)
    vec[24] = ECOSYSTEM_MAP.get(str(raw.get("primary_ecosystem", "unknown")).lower(), 0)
    vec[25] = DIFFICULTY_MAP.get(str(raw.get("min_exploit_difficulty", "unknown")).lower(), 0)
    vec[26] = RANK_MAP.get(str(raw.get("module_rank", "unknown")).lower(), 0)
    vec[27] = TYPE_MAP.get(str(raw.get("module_type", "unknown")).lower(), 0)
    return vec


# ── Pydantic models for /enrich-and-score ────────────────────────────────────

class ThreatInput(BaseModel):
    threat_id: str
    cve_ids: List[str]

class EnrichAndScoreRequest(BaseModel):
    threats: List[ThreatInput]

class ThreatResult(BaseModel):
    threat_id: str
    features: Dict[str, Any]
    risk_score: float
    severity_label: str
    severity_numeric: int
    confidence: float
    cves_processed: int
    model_version: str = "v3"

class EnrichAndScoreResponse(BaseModel):
    results: List[ThreatResult]
    threats_scored: int
    errors: List[str]
    timestamp: str


@app.post(
    "/enrich-and-score",
    response_model=EnrichAndScoreResponse,
    summary="Batch Enrich + Score Threats",
    description=(
        "Accepts threats with CVE IDs, runs 3-tier enrichment "
        "(CISA KEV, OSV, NVD CPE, GitHub, OTX, Metasploit, Censys), "
        "builds 28-feature v3 vector, and predicts risk score + severity."
    ),
)
async def enrich_and_score(request: EnrichAndScoreRequest):
    """
    Main integration endpoint called by the Threat Risk Assessment platform.

    For each threat:
      1. Fetch NVD base data (CVSS, published date) for lead CVE
      2. Run Tier 1-3 enrichment across all CVE IDs
      3. Build 28-feature v3 vector
      4. Predict with XGBRegressor (risk score) + XGBClassifier (severity)
    """
    # Load v3 models
    try:
        regressor = XGBRegressor()
        regressor.load_model(V3_REGRESSOR_PATH)
        classifier = XGBClassifier()
        classifier.load_model(V3_CLASSIFIER_PATH)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"v3 model load error: {e}")

    results: List[ThreatResult] = []
    errors: List[str] = []
    threats_scored = 0

    for threat in request.threats:
        try:
            merged: Dict[str, Any] = {}
            cves_processed = 0

            for cve_id in threat.cve_ids[:5]:  # Cap at 5 CVEs
                cve_id = cve_id.upper().strip()
                if not cve_id.startswith("CVE-"):
                    continue

                # NVD base data (CVSS + published date)
                nvd_metrics: Optional[Dict] = None
                try:
                    url = f"{NVD_API_URL}?cveId={cve_id}"
                    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
                    resp = requests.get(url, headers=headers, timeout=10)
                    if resp.ok:
                        vulns = resp.json().get("vulnerabilities", [])
                        if vulns:
                            cve_obj = vulns[0]["cve"]
                            metrics = cve_obj.get("metrics", {})
                            nvd_metrics = metrics
                            # CVSS score
                            if metrics.get("cvssMetricV31"):
                                merged["cvss_score"] = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                            elif metrics.get("cvssMetricV40"):
                                merged["cvss_score"] = metrics["cvssMetricV40"][0]["cvssData"]["baseScore"]
                            elif metrics.get("cvssMetricV2"):
                                merged["cvss_score"] = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                            # Published date
                            published = cve_obj.get("published", "")
                            merged["days_since_published"] = calculate_days_since_published(published)
                except Exception:
                    pass

                # EPSS
                epss = fetch_epss_score(cve_id)
                if epss > merged.get("epss_score", 0):
                    merged["epss_score"] = epss

                # Tier 1
                t1 = _enrich_tier1(cve_id)
                for k, v in t1.items():
                    merged[k] = max(merged.get(k, 0), v) if isinstance(v, (int, float)) else v

                # Tier 2
                t2 = _enrich_tier2(cve_id, nvd_metrics)
                for k, v in t2.items():
                    if k in ("attack_vector",):
                        merged.setdefault(k, v)
                    else:
                        merged[k] = max(merged.get(k, 0), v) if isinstance(v, (int, float)) else v

                # Tier 3
                t3 = _enrich_tier3(cve_id)
                for k, v in t3.items():
                    merged[k] = max(merged.get(k, 0), v) if isinstance(v, (int, float)) else v

                cves_processed += 1
                time.sleep(0.15)  # Rate-limit between CVEs

            if not merged:
                errors.append(f"No data found for threat {threat.threat_id}")
                continue

            # Derived features
            cvss = merged.get("cvss_score", 5.0)
            merged.setdefault("is_critical_cvss", 1 if cvss >= 9.0 else 0)
            merged.setdefault("is_high_cvss", 1 if cvss >= 7.0 else 0)

            # Build v3 vector and predict
            vec = _build_v3_feature_vector(merged)
            X = vec.reshape(1, -1)
            risk_score = float(regressor.predict(X)[0])
            severity_numeric = int(classifier.predict(X)[0])
            severity_labels = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
            severity_label = severity_labels.get(severity_numeric, "Unknown")
            prob = classifier.predict_proba(X)
            confidence = float(np.max(prob[0]))

            results.append(ThreatResult(
                threat_id=threat.threat_id,
                features=merged,
                risk_score=risk_score,
                severity_label=severity_label,
                severity_numeric=severity_numeric,
                confidence=confidence,
                cves_processed=cves_processed,
            ))
            threats_scored += 1

        except Exception as exc:
            errors.append(f"Error processing threat {threat.threat_id}: {str(exc)[:200]}")

    return EnrichAndScoreResponse(
        results=results,
        threats_scored=threats_scored,
        errors=errors,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# ── Health check endpoint ────────────────────────────────────────────────────

@app.get(
    "/health",
    summary="Health Check",
    description="Returns API status and model info"
)
async def health_check():
    """
    Simple health check endpoint.
    Verifies v1 and v3 models can be loaded.
    """
    try:
        model = XGBRegressor()
        model.load_model(MODEL_PATH)
        reg_v3 = XGBRegressor()
        reg_v3.load_model(V3_REGRESSOR_PATH)
        cls_v3 = XGBClassifier()
        cls_v3.load_model(V3_CLASSIFIER_PATH)
        return {
            "status": "healthy",
            "models": {
                "v1_regressor": MODEL_PATH,
                "v3_regressor": V3_REGRESSOR_PATH,
                "v3_classifier": V3_CLASSIFIER_PATH,
            },
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
            "POST /predict": "Predict risk score for a CVE (v1 model)",
            "POST /enrich-and-score": "Batch enrich + score threats (v3 model, 28 features)",
            "POST /predict-batch": "Batch predict (multiple CVEs, v1 model)",
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
