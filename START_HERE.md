# 🎬 START HERE - API Quick Reference

## ✅ Your API is LIVE RIGHT NOW

**Server Address:** `http://localhost:8000`
**Status:** 🟢 Running and responding to requests

---

## 📱 Try It Immediately

### Option 1: Browser (Easiest)
Open this in your browser right now:
```
http://localhost:8000/docs
```
This opens an interactive Swagger UI where you can test endpoints with a GUI.

### Option 2: Command Line (Windows PowerShell)
```powershell
# Test health
Invoke-WebRequest -Uri "http://localhost:8000/health" | ConvertFrom-Json

# Predict single CVE
$body = @{"cve_id" = "CVE-2025-11749"} | ConvertTo-Json
Invoke-WebRequest -Uri "http://localhost:8000/predict" -Method Post `
  -ContentType "application/json" -Body $body | ConvertFrom-Json
```

### Option 3: Python Script
```python
import requests

# Single prediction
response = requests.post(
    "http://localhost:8000/predict",
    json={"cve_id": "CVE-2025-11749"}
)
print(response.json())
```

### Option 4: curl (if available)
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d "{\"cve_id\": \"CVE-2025-11749\"}"
```

---

## 🎯 What Each Endpoint Does

| Endpoint | Use When | Example |
|----------|----------|---------|
| **GET /health** | Verify server is running | Check if API is up |
| **GET /docs** | View & test all APIs | Use interactive Swagger UI |
| **POST /predict** | Score a single CVE | `{"cve_id": "CVE-2025-11749"}` |
| **POST /predict-batch** | Score multiple CVEs at once | `["CVE-2025-11749", "CVE-2025-12139"]` |

---

## 📊 Understand the Response

When you make a prediction, you get back:

```json
{
  "cve_id": "CVE-2025-11749",
  "cvss_score": 9.8,
  "epss_score": 0.8640,
  "days_since_published": 118,
  "predicted_risk_score": 57.12,
  "severity_label": "Critical",
  "priority_score": 95.2
}
```

**What it means:**
- `severity_label`: How bad is it? (Low 🟢 / Medium 🟡 / High 🟠 / Critical 🔴)
- `priority_score`: How soon should I patch? (0-100, higher = faster)
- `predicted_risk_score`: AI's risk assessment

---

## 🎓 Real-World Use Cases

### Use Case 1: Check if one CVE is critical
```python
import requests

cve = "CVE-2025-11749"
response = requests.post("http://localhost:8000/predict", json={"cve_id": cve})
result = response.json()

if result["severity_label"] == "Critical":
    print(f"ALERT: {cve} needs immediate patching!")
else:
    print(f"OK: {cve} can wait")
```

### Use Case 2: Prioritize a list of CVEs
```python
import requests

cves = ["CVE-2025-11749", "CVE-2025-12139", "CVE-2025-12604"]
response = requests.post("http://localhost:8000/predict-batch", json=cves)

# Sort by priority (highest = patch first)
results = sorted(
    response.json(),
    key=lambda x: x["priority_score"],
    reverse=True
)

for cve in results:
    print(f"{cve['cve_id']}: {cve['priority_score']:.0f}/100 ({cve['severity_label']})")
```

### Use Case 3: Filter for critical/high severity
```python
import requests

cves = [...]  # your CVE list
response = requests.post("http://localhost:8000/predict-batch", json=cves)

urgent = [r for r in response.json() if r["priority_score"] > 80]
print(f"Urgent patches needed: {len(urgent)}")
for cve in urgent:
    print(f"  - {cve['cve_id']} (Priority {cve['priority_score']:.0f})")
```

### Use Case 4: Export results to CSV
```python
import requests
import csv

cves = [...]
response = requests.post("http://localhost:8000/predict-batch", json=cves)

with open("risk_report.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=[
        "cve_id", "severity_label", "priority_score", "predicted_risk_score"
    ])
    writer.writeheader()
    for r in response.json():
        writer.writerow({
            "cve_id": r["cve_id"],
            "severity_label": r["severity_label"],
            "priority_score": f"{r['priority_score']:.1f}",
            "predicted_risk_score": f"{r['predicted_risk_score']:.2f}"
        })

print("Report saved to risk_report.csv")
```

---

## 🔧 Common Issues & Fixes

| Problem | Solution |
|---------|----------|
| "Connection refused" | Server is down. Run: `uvicorn app_main:app --host 0.0.0.0 --port 8000` |
| "404 Not Found" on /predict | Check request format. Must be POST with `{"cve_id": "..."}` |
| Takes 10+ seconds | Normal for first request. NVD API is slow sometimes. |
| Wrong risk score | Model trained on 500 recent CVEs. Older CVEs may be less accurate. |
| EPSS score is 0 | CVE too new for EPSS database. Model still works fine. |

---

## 📚 Where to Go Next

1. **Try the interactive API**: http://localhost:8000/docs
2. **Read full docs**: See `README_API.md` in this folder
3. **Run tests**: `python test_api.py`
4. **See example code**: Check `QUICK_START_API.md`
5. **Understand what's under the hood**: Read `DEPLOYMENT_SUMMARY.md`

---

## 🚀 Deploy to Production

When ready to go live:

```bash
# Option 1: Scale with multiple workers
gunicorn app_main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker

# Option 2: Docker
docker build -t cyber-risk-api .
docker run -p 8000:8000 cyber-risk-api

# Option 3: Cloud (AWS, Azure, etc.)
# Follow your cloud provider's FastAPI deployment guide
```

---

## 💾 File Reference

### API & Code
- `serve_risk_model.py` - The actual API service (400+ lines)
- `app_main.py` - Entry point for uvicorn
- `test_api.py` - Test suite (run with: `python test_api.py`)

### Models & Data
- `cyber_risk_model_v1.json` - The trained ML model
- `cves_clean.csv` - The training data (500 CVEs)

### Documentation
- `README_API.md` - Full technical documentation
- `QUICK_START_API.md` - Code examples
- `DEPLOYMENT_SUMMARY.md` - Overview of what you built
- `START_HERE.md` - This file!

---

## 🎯 Success Criteria - You're Done When:

✅ Server running on http://localhost:8000
✅ `/health` endpoint returns 200 OK
✅ `/predict` returns severity and priority for a CVE
✅ `/predict-batch` works with multiple CVEs
✅ Response times are reasonable (2-5 seconds)
✅ You can access http://localhost:8000/docs in browser

**All boxes checked? Congratulations! Your system is live! 🎉**

---

## 📞 Need Help?

**Question:** How do I run this?
**Answer:** `uvicorn app_main:app --host 0.0.0.0 --port 8000`

**Question:** What's the format for requests?
**Answer:** See examples above or open http://localhost:8000/docs

**Question:** Can I use it from Excel/Sheets?
**Answer:** Yes! Use IMPORTJSON or similar functions with the POST endpoint

**Question:** Can I automate scanning my systems?
**Answer:** Yes! Write a script to pull your CVEs, batch predict, and generate reports

**Question:** What about authentication?
**Answer:** Add API keys later (see optional production enhancements in DEPLOYMENT_SUMMARY.md)

---

**Status: 🟢 LIVE AND READY**

Start with: http://localhost:8000/docs

*Happy vulnerability scoring!* 🔐
