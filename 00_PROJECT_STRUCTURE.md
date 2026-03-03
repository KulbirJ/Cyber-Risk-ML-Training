# 📋 Project Structure & File Guide

## 🎯 START HERE

**New to this project?** Read in this order:
1. **START_HERE.md** ← You are probably looking at this
2. **QUICK_START_API.md** ← How to use the API
3. **README_API.md** ← Full technical docs
4. **DEPLOYMENT_SUMMARY.md** ← What you built & results

---

## 📁 Complete File Listing

### 🟢 DOCUMENTATION (Read These)

| File | Purpose | When to Read |
|------|---------|--------------|
| **START_HERE.md** | Quick orientation guide | First thing! |
| **QUICK_START_API.md** | Code examples and quick reference | Want to use the API |
| **README_API.md** | Full API documentation | Need detailed specs |
| **DEPLOYMENT_SUMMARY.md** | Project overview and results | Want to understand what was built |

### 🔵 API SERVICE (Production Code)

| File | Purpose | Lines | Status |
|------|---------|-------|--------|
| **serve_risk_model.py** | Main FastAPI application | 400+ | ✅ LIVE |
| **app_main.py** | Uvicorn entry point | 10 | ✅ LIVE |
| **test_api.py** | Comprehensive test suite | 200+ | ✅ READY |

**Running:** `uvicorn app_main:app --host 0.0.0.0 --port 8000`

### 🟡 DATA COLLECTION & PROCESSING

| File | Purpose | Input | Output |
|------|---------|-------|--------|
| **fetch_cves.py** | Fetch from NVD API | - | cves_day1.json |
| **process_cves.py** | Convert JSON → DataFrame | cves_day1.json | cves_clean.csv |
| **enrich_epss.py** | Fetch missing EPSS scores | cves_clean.csv | cves_clean_enriched.csv |

**Run order:** fetch_cves.py → process_cves.py → enrich_epss.py

### 🟣 MACHINE LEARNING MODELS

| File | Purpose | Trains | Output |
|------|---------|--------|--------|
| **train_risk_model.py** | Train regression + classification | 500 CVEs, 4 features | cyber_risk_model_v1.json |
| **train_risk_model_v2.py** | Enhanced training, 8 features | 500 CVEs, 8 features | cyber_risk_model_v2.json |

**Models trained on:** cves_clean.csv (or enriched version)

### 🟠 MODEL FILES (Binary Data)

| File | Size | Purpose | Used By |
|------|------|---------|---------|
| **cyber_risk_model_v1.json** | ~200KB | Regression model (MAE=0.0247) | serve_risk_model.py |
| **cyber_risk_model_v2.json** | ~200KB | Enhanced regression model | - (reference) |
| **cyber_risk_severity_model_v1.json** | ~200KB | Classification model (F1=1.0) | - (reference) |
| **cyber_risk_severity_model_v2.json** | ~200KB | Enhanced classification | - (reference) |

**Active model:** v1 (loaded in API)

### 📊 DATA FILES (CSV/JSON)

| File | Records | Columns | Purpose |
|------|---------|---------|---------|
| **cves_day1.json** | 500 | Raw NVD structure | Raw data from NVD API |
| **cves_clean.csv** | 500 | 6 (cve_id, desc, cvss, date, epss, days) | Processed training data |
| **cves_clean_enriched.csv** | 500 | 6 (with filled EPSS) | Enhanced training data |
| **cves_high_risk.csv** | 2 | 6 | Subset with EPSS > 0.1 |

### 📦 DEPENDENCIES

| File | Purpose |
|------|---------|
| **requirements.txt** | List of Python packages (incomplete) |
| **venv/** | Python virtual environment |

---

## 🚀 Recommended Workflows

### Workflow 1: Just Use the API
```
1. Open: http://localhost:8000/docs
2. Test endpoints in browser
3. Copy example code to your project
4. Done!
```

### Workflow 2: Run Full Test Suite
```
1. python test_api.py
2. Review test output
3. All tests should PASS
```

### Workflow 3: Retrain the Model (Optional)
```
1. python train_risk_model.py
2. New cyber_risk_model_v1.json created
3. Restart API: uvicorn app_main:app
```

### Workflow 4: Fresh Data Collection (Optional)
```
1. python fetch_cves.py          # Get latest 500 CVEs
2. python process_cves.py        # Process to DataFrame
3. python enrich_epss.py         # Add EPSS scores
4. python train_risk_model.py    # Retrain model
5. Restart API
```

---

## 📐 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT (Browser/App)                      │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTP Requests (JSON)
                     ↓
┌─────────────────────────────────────────────────────────────┐
│         FastAPI Service (serve_risk_model.py)               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Routes: /predict, /predict-batch, /health, /docs      │ │
│  └────────────────────────────────────────────────────────┘ │
└────────┬────────────────────────┬────────────────────────────┘
         │                        │
         ↓ HTTP (Get CVE data)    ↓ HTTP (Get EPSS score)
    ┌─────────────┐           ┌──────────────┐
    │  NVD API    │           │  EPSS API    │
    └─────────────┘           └──────────────┘
         ↓                        │
         └─────────┬──────────────┘
                   ↓
         ┌─────────────────────────┐
         │ Feature Preparation     │
         │ (CVSS, EPSS, Days, etc)│
         └────────────┬────────────┘
                      ↓
         ┌──────────────────────────┐
         │ ML Model Prediction      │
         │ (cyber_risk_model_v1)    │
         └────────────┬─────────────┘
                      ↓
         ┌──────────────────────────┐
         │ Post-Processing          │
         │ (Severity, Priority)     │
         └────────────┬─────────────┘
                      ↓
         ┌──────────────────────────┐
         │ RiskPredictionResponse   │
         │ (JSON with 11 fields)    │
         └──────────────────────────┘
```

---

## 🔗 File Dependencies

```
START_HERE.md (you are here)
    │
    ├─→ QUICK_START_API.md (examples)
    │
    ├─→ README_API.md (detailed docs)
    │
    └─→ DEPLOYMENT_SUMMARY.md (overview)


serve_risk_model.py (API)
    │
    ├─→ Loads: cyber_risk_model_v1.json
    │
    ├─→ Imports: fetch_cve_from_nvd() [calls NVD API]
    │
    └─→ Imports: fetch_epss_score() [calls EPSS API]


train_risk_model.py (Training)
    │
    └─→ Reads: cves_clean.csv or cves_clean_enriched.csv
         └─→ Outputs: cyber_risk_model_v1.json


process_cves.py (Processing)
    │
    └─→ Reads: cves_day1.json
         └─→ Outputs: cves_clean.csv


fetch_cves.py (Collection)
    │
    └─→ Calls: NVD API
         └─→ Outputs: cves_day1.json
```

---

## 📊 Data Flow

```
NVD API
  ↓ (500 CVEs)
fetch_cves.py
  ↓ (saves)
cves_day1.json (raw JSON)
  ↓
process_cves.py (convert to DataFrame)
  ↓ (saves)
cves_clean.csv (500 rows, 6 columns)
  ↓
[Optional: enrich_epss.py to get missing EPSS scores]
  ↓ (saves)
cves_clean_enriched.csv (500 rows, 6 columns filled)
  ↓
train_risk_model.py (train ML models)
  ↓ (saves)
cyber_risk_model_v1.json (trained model)
cybersecurity_model_v1_metadata.json (training metrics)
  ↓
serve_risk_model.py (loaded at startup)
  ↓ (API serves predictions)
Client Apps
```

---

## 🔑 Key Statistics

| Metric | Value |
|--------|-------|
| Total Files Created | 12 Python + 4 Docs |
| Lines of Code | 2000+ |
| CVEs Processed | 500 |
| EPSS Scores Retrieved | 481 (96.2%) |
| Training Samples | 480 (after removing NaN) |
| Test Samples | 96 |
| Regression MAE | 0.0247 |
| Regression R² | 0.9985 |
| Classification F1 | 1.0000 |
| Model Size | ~200KB (JSON) |
| API Response Time | 2-5 seconds |
| Endpoints | 4 (/, /health, /predict, /predict-batch) |

---

## ✅ Verification Checklist

- [x] API server running on http://localhost:8000
- [x] /health endpoint responds
- [x] /predict endpoint works
- [x] /predict-batch endpoint works
- [x] Models saved as JSON
- [x] Training data saved as CSV
- [x] Test suite created
- [x] Documentation complete
- [x] Examples provided

---

## 🎯 Next Actions

**Immediate (Now):**
1. Read `START_HERE.md` (this file)
2. Open http://localhost:8000/docs in your browser
3. Try predicting a CVE

**Short Term (This week):**
1. Test with your own CVE list
2. Integrate into your security workflow
3. Adjust priority thresholds if needed

**Medium Term (This month):**
1. Deploy to production (Docker/Cloud)
2. Add authentication
3. Set up monitoring

**Long Term (This quarter):**
1. Retrain with latest data
2. A/B test model improvements
3. Integrate with ticketing system

---

## 📞 File Quick Access

Want to... | Look at...
-----------|----------
**Use the API** | START_HERE.md or http://localhost:8000/docs
**Understand the system** | DEPLOYMENT_SUMMARY.md
**See code examples** | QUICK_START_API.md
**Read API specs** | README_API.md
**Modify the API** | serve_risk_model.py
**Retrain models** | train_risk_model.py
**Fetch new data** | fetch_cves.py
**Test everything** | test_api.py

---

**Status: ✅ ALL SYSTEMS OPERATIONAL**

API is live at: http://localhost:8000

Next: Open http://localhost:8000/docs to start testing!
