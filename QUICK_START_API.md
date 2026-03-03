# QUICK_START_API.md
# Cyber Risk Model API - Quick Start Guide

## 🚀 Start the Server

```bash
cd c:\Users\user1-baseNaultha\cyber-risk-ml-training

# Start the API server
uvicorn app_main:app --host 0.0.0.0 --port 8000
```

**Output when ready:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete
```

## 🌍 Access Points

Once running:

| Resource | URL | Purpose |
|----------|-----|---------|
| **Swagger UI** | http://localhost:8000/docs | Interactive testing |
| **ReDoc** | http://localhost:8000/redoc | Alternative docs |
| **Health Check** | http://localhost:8000/health | Verify status |

## 📋 Example 1: Predict Single CVE

Using curl:
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"cve_id": "CVE-2025-11749"}'
```

Using Python:
```python
import requests

response = requests.post(
    "http://localhost:8000/predict",
    json={"cve_id": "CVE-2025-11749"}
)
result = response.json()

print(f"CVE: {result['cve_id']}")
print(f"Severity: {result['severity_label']}")
print(f"Risk Score: {result['predicted_risk_score']:.2f}")
print(f"Priority: {result['priority_score']:.1f}/100")
```

**Sample Output:**
```json
{
  "cve_id": "CVE-2025-11749",
  "cvss_score": 9.8,
  "epss_score": 0.85413,
  "days_since_published": 117,
  "text_length_of_description": 450,
  "attack_count": 0,
  "predicted_risk_score": 50.31,
  "severity_label": "Critical",
  "priority_score": 83.85,
  "enrichment_source": "NVD + EPSS",
  "timestamp": "2026-03-03T12:45:00.000Z"
}
```

## 📦 Example 2: Batch Predict Multiple CVEs

```bash
curl -X POST http://localhost:8000/predict-batch \
  -H "Content-Type: application/json" \
  -d '["CVE-2025-11749","CVE-2025-12604","CVE-2025-12139"]'
```

## 🏥 Example 3: Check Health

```bash
curl http://localhost:8000/health

# Returns:
# {"status": "healthy", "model": "XGBRegressor", ...}
```

## 🧪 Run Full Test Suite

```bash
python test_api.py
```

This tests all endpoints and shows expected outputs.

## 📊 Understanding the Response

| Field | What it means |
|-------|---------------|
| `severity_label` | Low 🟢 / Medium 🟡 / High 🟠 / Critical 🔴 |
| `priority_score` | 0-100 ranking for patch urgency |
| `predicted_risk_score` | ML model's risk assessment (0-65) |
| `cvss_score` | NIST base severity (0-10) |
| `epss_score` | Real-world exploit probability (0-1) |
| `days_since_published` | How old is this CVE (days) |

## 🎯 Priority Guidelines

| Score | Action |
|-------|--------|
| 0-20 | ✅ Can wait - patch in next quarter |
| 20-50 | ⚠️ Schedule patch - target 1-2 months |
| 50-80 | 🔔 Urgent - patch within weeks |
| 80-100 | 🚨 Critical - patch immediately |

## 🔧 Common Operations

### Sort CVEs by priority:
```python
import requests

response = requests.post(
    "http://localhost:8000/predict-batch",
    json=["CVE-2025-11749","CVE-2025-12604"]
)

# Sort by priority descending
sorted_cves = sorted(
    response.json(),
    key=lambda x: x["priority_score"],
    reverse=True
)

for cve in sorted_cves:
    print(f"{cve['cve_id']}: {cve['priority_score']:.0f}/100 ({cve['severity_label']})")
```

### Filter Critical/High severity:
```python
response = requests.post("http://localhost:8000/predict-batch", json=cve_list)

critical = [
    r for r in response.json() 
    if r["severity_label"] in ["Critical", "High"]
]
print(f"Critical/High CVEs: {len(critical)}")
```

### Export results to CSV:
```python
import requests
import csv

response = requests.post("http://localhost:8000/predict-batch", json=cve_list)
results = response.json()

with open("risk_rankings.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)
```

## 🌐 Deployment

### Docker:
```bash
docker build -t cyber-risk-api .
docker run -p 8000:8000 cyber-risk-api
```

### Production (4 workers):
```bash
gunicorn app_main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000
```

## 📞 Troubleshooting

**Server won't start:**
```bash
# Check if port 8000 is in use
netstat -an | find "8000"

# Kill the process using port 8000 (Windows)
netsh int ipv4 show tcpconn | find "8000"
taskkill /PID <PID> /F
```

**Model not found:**
```bash
# Retrain the model
python train_risk_model.py

# Verify files exist
dir cyber_risk_model_v*.json
```

**API request times out:**
- NVD API might be slow (2-5 seconds is normal)
- Check internet connection
- Increase request timeout to 60 seconds

---

**API Server**: Active on http://localhost:8000
**Docs**: http://localhost:8000/docs
**Status**: ✅ Ready for requests

---

For full documentation, see: `README_API.md`
