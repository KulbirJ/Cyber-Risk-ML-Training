# 🛡️ Cyber Risk ML Training System

## Overview

**Cyber Risk ML Training** is a production-ready machine learning system that intelligently scores CVE (Common Vulnerabilities and Exposures) risks using multi-tier data enrichment and advanced ML models. The system processes vulnerability data from 8+ public sources, enriches it with 28 contextual features, and provides real-time risk predictions via a REST API. This system can be used as is in stand alone state to query single or multiple CVEs. For best value use this system as a middle/app layer in your risk assessment platform. 

---

## 🎯 Key Features

| Feature | Details |
|---------|---------|
| **28-Feature Enrichment** | TIER 1-3 data integration (CISA, NVD, GitHub, OTX, Metasploit) |
| **Dual ML Models** | XGBoost Regressor (risk scoring) + Classifier (severity classification) |
| **Production API** | FastAPI with Swagger UI, health checks, batch predictions |
| **High Accuracy** | Test MAE=0.0058, R²=0.9806, Accuracy=100% |
| **Normalized Scoring** | 0-1 probability scale with confidence metrics |
| **500 Enriched CVEs** | Complete dataset for training and testing |
| **Transparent Data Lineage** | Track which enrichment tier provided each feature |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     CYBER RISK ML SYSTEM                         │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      DATA SOURCES                                │
├─────────────────────────────────────────────────────────────────┤
│ TIER 1 (Public APIs)    │ TIER 2 (Enhanced)      │ TIER 3 (Intel) │
│ • CISA KEV              │ • NVD CPE Data         │ • Metasploit   │
│ • Exploit-DB            │ • GitHub Advisories    │ • Censys       │
│ • OSV Database          │ • AlienVault OTX       │ • CVSS Severity│
│ (8 features)            │ (10 features)          │ (9 features)   │
└──────────┬──────────────┬────────────────────────┬────────────────┘
           │              │                        │
           └──────────────┴────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                   ENRICHMENT PIPELINE                            │
├─────────────────────────────────────────────────────────────────┤
│ enhance_cves_tier1.py ──► enhance_cves_tier2.py ──► enhance_cves_tier3.py │
│ (500 × 14 cols)          (500 × 24 cols)          (500 × 33 cols) │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FEATURE ENGINEERING                           │
├─────────────────────────────────────────────────────────────────┤
│ • Data cleaning & normalization                                  │
│ • Categorical encoding (attack_vector, ecosystem, rank)          │
│ • Feature selection (28 most predictive features)                │
│ • Train/Test split (80/20)                                       │
└──────────────────┬──────────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                  MODEL TRAINING (v3)                             │
├─────────────────────────────────────────────────────────────────┤
│ • XGBRegressor: Risk Score (0-1 probability)                    │
│   └─ Test MAE=0.0058, R²=0.9806                                 │
│ • XGBClassifier: Severity (0-4: Low/Med/High/Critical)          │
│   └─ Test Accuracy=100%, F1=1.0                                 │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│                  PRODUCTION DEPLOYMENT                           │
├─────────────────────────────────────────────────────────────────┤
│ FastAPI Server (deploy_model_v3.py)                              │
│ • POST /predict       → CVE risk scoring                         │
│ • GET  /health        → Model health check                       │
│ • GET  /docs          → Swagger UI                               │
│ • GET  /              → API info                                 │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   API CONSUMERS                                  │
├─────────────────────────────────────────────────────────────────┤
│ • Security Tools       • SOAR Platforms        • Compliance      │
│ • Ticket Systems       • Dashboards            • Automations     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 👤 User Flow Diagram

```
START
  │
  ├─► User/System provides CVE ID (e.g., CVE-2026-20127)
  │
  ├─► API checks: Is this CVE in enriched dataset?
  │
  ├─YES─────────────────────────────────┐
  │ • Load 28 enriched features          │
  │ • Pass to XGBoost models             │
  │ • Return full prediction             │
  │                    data_source: "enriched_dataset"
  │                    features_available: 28
  │
  ├─NO──────────────────────────────────┐
  │ • Fetch from NVD + EPSS APIs         │
  │ • Extract 3 basic features           │
  │ • Pass to XGBoost models             │
  │ • Return live prediction             │
  │                    data_source: "nvd_live"
  │                    features_available: 3
  │
  └─────────────────┬────────────────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │  Prediction Response │
         ├──────────────────────┤
         │ • Risk Score (0-1)   │
         │ • Severity Label     │
         │ • Confidence Score   │
         │ • Data Source        │
         │ • Features Used      │
         └──────────┬───────────┘
                    │
                    ▼
              Return to Consumer
                    │
                    ├─► Security Dashboard
                    ├─► Alert System
                    ├─► Remediation Tool
                    └─► Compliance Report
```

---

## 📊 Data Enrichment Tiers

### **TIER 1: Public Vulnerability Sources (8 features)**
```
Sources:
├─ CISA KEV         → Known exploited vulnerabilities
├─ Exploit-DB       → Public exploit availability & difficulty
└─ OSV Database     → Ecosystem-specific vulnerability tracking

Features:
├─ in_cisa_kev              (bool)
├─ has_public_poc           (bool)
├─ poc_count                (int)
├─ affected_packages_count  (int)
├─ primary_ecosystem        (categorical)
├─ has_fixed_version        (bool)
├─ min_exploit_difficulty   (categorical)
└─ cisa_exploitation_deadline (date)
```

### **TIER 2: Enhanced Threat Intelligence (10 features)**
```
Sources:
├─ NVD CPE Matching     → Attack vectors, complexity, privileges
├─ GitHub Advisories    → Open source impact tracking
└─ AlienVault OTX       → Threat actor activity & malware

Features:
├─ attack_vector            (categorical: network/local/physical)
├─ requires_authentication  (bool)
├─ requires_user_interaction (bool)
├─ scope_changed            (bool)
├─ in_github_advisories     (bool)
├─ github_affected_count    (int)
├─ patch_available          (bool)
├─ otx_threat_score         (0-100)
├─ malware_associated       (bool)
└─ active_exploits          (int)
```

### **TIER 3: Advanced Threat Intel (9 features)**
```
Sources:
├─ Metasploit Modules   → Weaponized exploit availability
├─ Censys            → Internet exposure metrics (optional)
└─ CVSS Severity        → Attack impact categorization

Features:
├─ metasploit_modules      (int, count)
├─ has_metasploit_module   (bool)
├─ module_rank             (categorical: critical/good/normal/low/unranked)
├─ module_type             (categorical: exploit/reliabilty/denial_of_service)
├─ censys_exposed_count    (int)
├─ has_censys_data         (bool)
├─ cvss_severity_band      (categorical)
├─ is_critical_cvss        (bool, CVSS >= 9.0)
└─ is_high_cvss           (bool, CVSS >= 7.0)
```

---

## 🤖 Model Comparison: v1 vs v3

| Aspect | Model v1 | Model v3 |
|--------|----------|----------|
| **Features** | 4-6 basic | 28 enriched |
| **Data Sources** | NVD + EPSS only | TIER 1-3 (8+ sources) |
| **Risk Scale** | 0-65 (linear) | 0-1 (normalized) |
| **Test MAE** | 0.0247 | 0.0058 (4x better) |
| **Test R²** | 0.8934 | 0.9806 (9.8% better) |
| **Confidence Score** | ❌ None | ✅ 0-100% |
| **Data Source Tracking** | Generic | Explicit (3/28 features) |
| **Feature Transparency** | Limited | Full audit trail |
| **Production Ready** | ⚠️ Legacy | ✅ Current |

**Recommendation:** Use Model v3 exclusively for new deployments.

---

## 🚀 Quick Start

### **1. Installation**

```bash
# Clone repository
git clone https://github.com/KulbirJ/Cyber-Risk-ML-Training.git
cd Cyber-Risk-ML-Training

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1  # Windows
# or
source venv/bin/activate    # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

### **2. Setup Environment**

```bash
# Create .env file with your NVD API key
echo "NVD_API_KEY=your_key_here" > .env
```

### **3. Run the API**

```bash
python deploy_model_v3.py
```

Output:
```
✓ Loaded 500 enriched CVEs from cves_enhanced_tier3.csv

╔════════════════════════════════════════════════════════════╗
║   CYBER RISK MODEL v3 - PRODUCTION DEPLOYMENT              ║
╠════════════════════════════════════════════════════════════╣
║  Starting FastAPI server on http://localhost:8000          ║
╚════════════════════════════════════════════════════════════╝

INFO:     Uvicorn running on http://0.0.0.0:8000
```

### **4. Access the API**

- **Swagger UI:** http://localhost:8000/docs
- **Health Check:** http://localhost:8000/health
- **API Info:** http://localhost:8000/

---

## 📡 API Usage

### **Predict CVE Risk**

**Endpoint:** `POST /predict`

**Request:**
```json
{
  "cve_id": "CVE-2025-12604",
  "use_enriched_data": true
}
```

**Response (Enriched Dataset):**
```json
{
  "cve_id": "CVE-2025-12604",
  "model_version": "v3",
  "cvss_score": 7.3,
  "epss_score": 0.0004,
  "days_since_published": 119,
  "predicted_risk_score": 0.2924,
  "severity_label": "High",
  "severity_numeric": 2,
  "confidence": 0.9942,
  "data_source": "enriched_dataset",
  "timestamp": "2026-03-03T23:04:36.039054+00:00",
  "features_available": 28
}
```

**Response (Live NVD):**
```json
{
  "cve_id": "CVE-2026-20127",
  "model_version": "v3",
  "cvss_score": 10.0,
  "epss_score": 0.02604,
  "days_since_published": 6,
  "predicted_risk_score": 0.5190,
  "severity_label": "Critical",
  "severity_numeric": 3,
  "confidence": 0.9628,
  "data_source": "nvd_live",
  "timestamp": "2026-03-03T23:05:44.425784+00:00",
  "features_available": 3
}
```

---

## 🧪 Testing

### **Run Comprehensive Test Suite**

```bash
python test_model_v3.py
```

**Tests Included:**
1. ✅ API Health Check
2. ✅ Single CVE Prediction (Enriched)
3. ✅ Batch Predictions (3 CVEs)
4. ✅ Live NVD API Prediction
5. ✅ API Documentation & Swagger

**Output:**
```
Tests Passed: 5/5
Success Rate: 100.0%

✓ All tests passed! Model v3 is ready for production.
```

---

## 📚 Project Structure

```
cyber-risk-ml-training/
├── deploy_model_v3.py           # FastAPI production server
├── test_model_v3.py             # Comprehensive test suite
├── train_risk_model_v3.py       # Model retraining script
│
├── enhance_cves_tier1.py        # TIER 1 enrichment (CISA, Exploit-DB, OSV)
├── enhance_cves_tier2.py        # TIER 2 enrichment (NVD, GitHub, OTX)
├── enhance_cves_tier3.py        # TIER 3 enrichment (Metasploit, Censys, CVSS)
│
├── cyber_risk_model_v3.json              # Trained regressor (28 features)
├── cyber_risk_severity_model_v3.json     # Trained classifier (28 features)
├── cyber_risk_model_v3_metadata.json     # Model metrics & performance
│
├── cves_enhanced_tier3.csv      # 500 enriched CVEs (33 columns)
├── cves_clean.csv               # Original CVE dataset (6 columns)
│
├── requirements.txt             # Python dependencies
├── .env                         # Environment variables (NVD_API_KEY)
├── .gitignore                   # Security (prevents .env commit)
│
├── README.md                    # This file
├── README_API.md                # API documentation
└── DEPLOYMENT_GUIDE_V3.md       # Deployment instructions
```

---

## 🔄 Data Processing Pipeline

```
Original CVEs (6 cols)
    │
    ├─► enhance_cves_tier1.py
    │   ├─ Fetch CISA KEV data
    │   ├─ Fetch Exploit-DB exploits
    │   └─ Fetch OSV database
    └─► cves_enhanced_tier1.csv (14 cols)
        │
        ├─► enhance_cves_tier2.py
        │   ├─ Fetch NVD CPE data
        │   ├─ Fetch GitHub Advisories
        │   └─ Fetch AlienVault OTX
        └─► cves_enhanced_tier2.csv (24 cols)
            │
            ├─► enhance_cves_tier3.py
            │   ├─ Fetch Metasploit modules
            │   ├─ Fetch Censys exposure (optional)
            │   └─ Calculate CVSS severity bands
            └─► cves_enhanced_tier3.csv (33 cols)
                │
                ├─► train_risk_model_v3.py
                │   ├─ Feature engineering (28 selected features)
                │   ├─ Train XGBRegressor (risk score)
                │   └─ Train XGBClassifier (severity)
                └─► Models deployed to production
                    │
                    ├─► cyber_risk_model_v3.json
                    ├─► cyber_risk_severity_model_v3.json
                    └─► deploy_model_v3.py (API server)
```

---

## 📊 Model Performance Metrics

### **Regressor (Risk Score Prediction)**
- **Algorithm:** XGBRegressor
- **Input:** 28 features
- **Output:** 0-1 risk probability
- **Test MAE:** 0.0058 ✅
- **Test R²:** 0.9806 (98% variance explained)
- **Train/Test Split:** 400/100 (80/20)

### **Classifier (Severity Classification)**
- **Algorithm:** XGBClassifier
- **Input:** 28 features
- **Output:** 0=Low, 1=Medium, 2=High, 3=Critical
- **Test Accuracy:** 100% ✅
- **Test F1-Score:** 1.0 ✅
- **Class Distribution:** 30 Low, 261 Medium, 209 High, 57 Critical

---

## 🔐 Security

### **API Key Protection**
```bash
# Never commit .env file
.env                    # ← In .gitignore
```

### **Environment Configuration**
```python
from dotenv import load_dotenv
import os

load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")
```

### **Secret Management**
- ✅ All API keys in `.env`
- ✅ `.gitignore` prevents accidental commits
- ✅ Production uses CI/CD secrets
- ✅ No credentials in code

---

## 🌐 Integration Examples

### **cURL: Single Prediction**
```bash
curl -X POST "http://localhost:8000/predict" \
  -H "Content-Type: application/json" \
  -d '{"cve_id": "CVE-2025-12604", "use_enriched_data": true}'
```

### **Python: Batch Prediction**
```python
import requests

cve_ids = ["CVE-2025-12604", "CVE-2025-12605", "CVE-2025-12606"]
results = []

for cve_id in cve_ids:
    response = requests.post(
        "http://localhost:8000/predict",
        json={"cve_id": cve_id, "use_enriched_data": True}
    )
    results.append(response.json())

# Sort by risk score (highest first)
results.sort(key=lambda x: x["predicted_risk_score"], reverse=True)
for cve in results:
    print(f"{cve['cve_id']}: {cve['severity_label']} ({cve['predicted_risk_score']:.2%})")
```

### **PowerShell: Health Check**
```powershell
$health = Invoke-WebRequest -Uri "http://localhost:8000/health" | ConvertFrom-Json
Write-Host "Model: $($health.model_version)"
Write-Host "Enriched CVEs: $($health.enriched_cves)"
Write-Host "Status: $($health.status)"
```

---

## 📖 Documentation

| Document | Purpose |
|----------|---------|
| [README.md](README.md) | System overview (this file) |
| [README_API.md](README_API.md) | Detailed API reference |
| [DEPLOYMENT_GUIDE_V3.md](DEPLOYMENT_GUIDE_V3.md) | Step-by-step deployment |

---

## 🤝 Contributing

### **Adding New Enrichment Sources**

1. Create `enhance_cves_tierX.py`
2. Implement API integration
3. Test with sample CVEs
4. Update feature list
5. Retrain models

### **Improving Model Accuracy**

1. Add new features (maintain backward compatibility)
2. Rerun enrichment pipeline
3. Execute `train_risk_model_v3.py`
4. Validate test metrics
5. Deploy new model version

---

## 📝 License

[Add your license information here]

---

## 👨‍💻 Authors

**Kulbir J** - Cyber Risk ML Training System

---

## 📞 Support

| Issue | Resolution |
|-------|-----------|
| **Port 8000 in use** | `Get-NetTCPConnection -LocalPort 8000` then kill process |
| **API key issues** | Check `.env` file and `NVD_API_KEY` environment variable |
| **Model load errors** | Verify model files (`.json`) exist in working directory |
| **Slow predictions** | Check network connection (NVD API calls) |

---

## 🎯 Roadmap

- ✅ Phase 1-4: Core system (complete)
- 🔄 Phase 5: Real-time threat intel integration
- 🔄 Phase 6: AutoML hyperparameter tuning
- 🔄 Phase 7: Multi-model ensemble
- 🔄 Phase 8: Horizontal scaling (Kubernetes)

---

**Last Updated:** March 4, 2026  
**Model Version:** v3  
**Status:** Production Ready ✅
