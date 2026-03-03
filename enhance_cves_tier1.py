import pandas as pd
import requests
import csv
import io
import time
from datetime import datetime, timezone
from typing import Dict, List

INPUT_FILE = "cves_clean.csv"
OUTPUT_FILE = "cves_enhanced_tier1.csv"

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv"
EXPLOIT_DB_API_URL = "https://www.exploit-db.com/api/search"
OSV_API_URL = "https://api.osv.dev/v1/query"

HEADERS = {"User-Agent": "CVE-Enhancement/1.0"}
REQUEST_TIMEOUT = 10

def fetch_cisa_kev() -> Dict[str, Dict]:
    print("\n[1/3] Fetching CISA KEV data...")
    try:
        response = requests.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT, headers=HEADERS)
        response.raise_for_status()
        csv_reader = csv.DictReader(io.StringIO(response.text))
        kev_data = {}
        for row in csv_reader:
            cve_id = row.get("cveID", "").strip()
            if cve_id:
                kev_data[cve_id] = {
                    "dateAdded": row.get("dateAdded", ""),
                    "dueDate": row.get("dueDate", "")
                }
        print(f"   OK: {len(kev_data)} CVEs from CISA KEV")
        return kev_data
    except Exception as e:
        print(f"   ERROR: {e}")
        return {}

def fetch_exploit_db() -> Dict[str, Dict]:
    print("\n[2/3] Fetching Exploit-DB data...")
    exploit_data = {}
    try:
        params = {"type": "cve", "limit": 500, "sort": "date"}
        response = requests.get(EXPLOIT_DB_API_URL, params=params, timeout=REQUEST_TIMEOUT, headers=HEADERS)
        if response.status_code == 200:
            data = response.json()
            for exploit in data.get("results", []):
                cve_id = exploit.get("cve", "").strip().upper()
                if cve_id and cve_id.startswith("CVE-"):
                    if cve_id not in exploit_data:
                        exploit_data[cve_id] = {"count": 0, "difficulty": "unknown"}
                    exploit_data[cve_id]["count"] += 1
                    if "difficulty" in exploit:
                        exploit_data[cve_id]["difficulty"] = exploit["difficulty"].lower()
        print(f"   OK: {len(exploit_data)} CVEs with exploits")
        return exploit_data
    except Exception as e:
        print(f"   ERROR: {e}")
        return {}

def fetch_osv_for_cve(cve_id: str) -> Dict:
    features = {"affected_packages_count": 0, "primary_ecosystem": "unknown", "has_fixed_version": 0}
    try:
        payload = {"query": cve_id}
        response = requests.post(OSV_API_URL, json=payload, timeout=REQUEST_TIMEOUT, headers=HEADERS)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulns", [])
            if vulns:
                packages = set()
                ecosystems = {}
                has_fix = False
                for vuln in vulns:
                    for item in vuln.get("affected", []):
                        pkg_name = item.get("package", {}).get("name", "")
                        ecosystem = item.get("package", {}).get("ecosystem", "").lower()
                        if pkg_name:
                            packages.add(pkg_name)
                        if ecosystem:
                            ecosystems[ecosystem] = ecosystems.get(ecosystem, 0) + 1
                        for event in item.get("ranges", [{}])[0].get("events", []):
                            if "fixed" in event:
                                has_fix = True
                features["affected_packages_count"] = len(packages)
                if ecosystems:
                    features["primary_ecosystem"] = max(ecosystems, key=ecosystems.get)
                features["has_fixed_version"] = 1 if has_fix else 0
        time.sleep(0.5)
    except:
        pass
    return features

def main():
    print("="*70)
    print("PHASE 1: TIER 1 ENHANCEMENT")
    print("="*70)
    
    print(f"\nLoading {INPUT_FILE}...")
    df = pd.read_csv(INPUT_FILE)
    print(f"OK: {len(df)} CVEs loaded")
    
    print("\nInitializing new columns...")
    df["in_cisa_kev"] = 0
    df["cisa_exploitation_deadline"] = -1
    df["has_public_poc"] = 0
    df["poc_count"] = 0
    df["min_exploit_difficulty"] = "unknown"
    df["affected_packages_count"] = 0
    df["primary_ecosystem"] = "unknown"
    df["has_fixed_version"] = 0
    
    kev_data = fetch_cisa_kev()
    exploit_data = fetch_exploit_db()
    
    print(f"\nEnriching with CISA KEV...")
    for idx, row in df.iterrows():
        cve_id = row["cve_id"]
        if cve_id in kev_data:
            df.loc[idx, "in_cisa_kev"] = 1
            try:
                due_date_str = kev_data[cve_id].get("dueDate", "")
                if due_date_str:
                    due_date = datetime.strptime(due_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_to_deadline = (due_date - now).days
                    df.loc[idx, "cisa_exploitation_deadline"] = max(-1, days_to_deadline)
            except:
                pass
    
    kev_count = df["in_cisa_kev"].sum()
    print(f"   Found {kev_count} CVEs in CISA KEV")
    
    print(f"\nEnriching with Exploit-DB...")
    for idx, row in df.iterrows():
        cve_id = row["cve_id"]
        if cve_id in exploit_data:
            df.loc[idx, "has_public_poc"] = 1
            df.loc[idx, "poc_count"] = exploit_data[cve_id].get("count", 0)
            df.loc[idx, "min_exploit_difficulty"] = exploit_data[cve_id].get("difficulty", "unknown")
    
    poc_count = df["has_public_poc"].sum()
    print(f"   Found {poc_count} CVEs with public POCs")
    
    print(f"\n[3/3] Querying OSV API (this takes time due to rate limits)...")
    for i, cve_id in enumerate(df["cve_id"]):
        if (i + 1) % 50 == 0:
            print(f"   Progress: {i+1}/{len(df)}...")
        idx = df[df["cve_id"] == cve_id].index[0]
        osv_features = fetch_osv_for_cve(cve_id)
        df.loc[idx, "affected_packages_count"] = osv_features["affected_packages_count"]
        df.loc[idx, "primary_ecosystem"] = osv_features["primary_ecosystem"]
        df.loc[idx, "has_fixed_version"] = osv_features["has_fixed_version"]
    
    pkg_count = (df["affected_packages_count"] > 0).sum()
    print(f"   Found {pkg_count} CVEs in package ecosystems")
    
    print(f"\n{"="*70}")
    print("ENRICHMENT COMPLETE")
    print(f"{"="*70}")
    print(f"CVEs in CISA KEV: {kev_count}")
    print(f"CVEs with public POC: {poc_count}")
    print(f"CVEs in packages: {pkg_count}")
    
    print(f"\nSaving to {OUTPUT_FILE}...")
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"OK: Saved {len(df)} rows to {OUTPUT_FILE}")
    
    print(f"\nData Preview:")
    print(df[["cve_id", "in_cisa_kev", "has_public_poc", "affected_packages_count"]].head(10).to_string())

if __name__ == "__main__":
    main()
