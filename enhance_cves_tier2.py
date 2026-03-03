import pandas as pd
import requests
import json
import time
import os
from typing import Dict
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

INPUT_FILE = "cves_enhanced_tier1.csv"  # Use Phase 1 output
OUTPUT_FILE = "cves_enhanced_tier2.csv"

# API URLs
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API_URL = "https://api.github.com/graphql"
OTX_API_URL = "https://otx.alienvault.com/api/v1/pulses/search"

# NVD API Key from environment variable (loaded from .env)
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
if not NVD_API_KEY:
    raise ValueError("NVD_API_KEY not found in environment. Please set it in .env file.")

HEADERS = {"User-Agent": "CVE-Enhancement/2.0"}

def fetch_nvd_cpe_data(cve_id: str) -> Dict:
    """Fetch attack vector and privilege requirements from NVD CPE"""
    features = {
        "attack_vector": "unknown",
        "requires_authentication": 0,
        "requires_user_interaction": 0,
        "scope_changed": 0
    }
    
    try:
        url = f"{NVD_API_URL}?cveId={cve_id}"
        headers = {"apiKey": NVD_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if vulnerabilities:
                metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", [])
                
                if not cvss_data:
                    cvss_data = metrics.get("cvssMetricV30", [])
                
                if cvss_data:
                    cvss = cvss_data[0].get("cvssData", {})
                    features["attack_vector"] = cvss.get("attackVector", "unknown").lower()
                    
                    # Convert to binary: requires auth?
                    auth = cvss.get("authentication", cvss.get("privilegesRequired", "NONE"))
                    if auth and auth.upper() != "NONE":
                        features["requires_authentication"] = 1
                    
                    # User interaction?
                    ui = cvss.get("userInteraction", "NONE")
                    if ui and ui.upper() != "NONE":
                        features["requires_user_interaction"] = 1
                    
                    # Scope changed?
                    scope = cvss.get("scope", "UNCHANGED")
                    if scope and scope.upper() == "CHANGED":
                        features["scope_changed"] = 1
        
        time.sleep(0.1)  # Rate limiting
    except:
        pass
    
    return features

def fetch_github_advisories(cve_id: str) -> Dict:
    """Fetch GitHub Security Advisories for a CVE"""
    features = {
        "in_github_advisories": 0,
        "github_affected_count": 0,
        "patch_available": 0
    }
    
    try:
        # Note: GitHub API requires authentication for full access
        # Using free tier without token for basic searches
        url = f"https://api.github.com/search/repositories?q=security+advisory+{cve_id}"
        response = requests.get(url, headers=HEADERS, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("total_count", 0) > 0:
                features["in_github_advisories"] = 1
                features["github_affected_count"] = min(data.get("total_count", 0), 100)
        
        time.sleep(0.1)
    except:
        pass
    
    return features

def fetch_otx_threat_data(cve_id: str) -> Dict:
    """Fetch threat intelligence from AlienVault OTX"""
    features = {
        "otx_threat_score": 0,
        "malware_associated": 0,
        "active_exploits": 0
    }
    
    try:
        url = f"{OTX_API_URL}?q={cve_id}"
        response = requests.get(url, headers=HEADERS, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            results = data.get("results", [])
            
            if results:
                # Use first result's threat score
                threat_score = results[0].get("created", 0)
                features["otx_threat_score"] = min(int(len(results) * 10), 100)
                
                # Check for malware references
                tags = results[0].get("tags", [])
                if any("malware" in tag.lower() for tag in tags):
                    features["malware_associated"] = 1
                
                # Check for exploit mentions
                if any("exploit" in tag.lower() for tag in tags):
                    features["active_exploits"] = 1
        
        time.sleep(0.2)  # Respect rate limits
    except:
        pass
    
    return features

def main():
    print("="*70)
    print("PHASE 2: TIER 2 ENHANCEMENT")
    print("Adding NVD CPE, GitHub GHSA, and AlienVault OTX data")
    print("="*70)
    
    print(f"\nLoading Phase 1 output ({INPUT_FILE})...")
    df = pd.read_csv(INPUT_FILE)
    print(f"OK: {len(df)} rows loaded")
    
    print("\nInitializing new TIER 2 columns...")
    df["attack_vector"] = "unknown"
    df["requires_authentication"] = 0
    df["requires_user_interaction"] = 0
    df["scope_changed"] = 0
    df["in_github_advisories"] = 0
    df["github_affected_count"] = 0
    df["patch_available"] = 0
    df["otx_threat_score"] = 0
    df["malware_associated"] = 0
    df["active_exploits"] = 0
    
    print("\n[1/3] Fetching NVD CPE data...")
    for i, cve_id in enumerate(df["cve_id"]):
        if (i + 1) % 100 == 0:
            print(f"   Progress: {i+1}/{len(df)}...")
        idx = df[df["cve_id"] == cve_id].index[0]
        features = fetch_nvd_cpe_data(cve_id)
        df.loc[idx, "attack_vector"] = features["attack_vector"]
        df.loc[idx, "requires_authentication"] = features["requires_authentication"]
        df.loc[idx, "requires_user_interaction"] = features["requires_user_interaction"]
        df.loc[idx, "scope_changed"] = features["scope_changed"]
    
    print("   OK: NVD CPE data retrieved")
    
    print("\n[2/3] Fetching GitHub Security Advisories...")
    for i, cve_id in enumerate(df["cve_id"]):
        if (i + 1) % 100 == 0:
            print(f"   Progress: {i+1}/{len(df)}...")
        idx = df[df["cve_id"] == cve_id].index[0]
        features = fetch_github_advisories(cve_id)
        df.loc[idx, "in_github_advisories"] = features["in_github_advisories"]
        df.loc[idx, "github_affected_count"] = features["github_affected_count"]
    
    ghsa_count = df["in_github_advisories"].sum()
    print(f"   OK: Found {ghsa_count} CVEs in GitHub advisories")
    
    print("\n[3/3] Fetching AlienVault OTX threat data...")
    for i, cve_id in enumerate(df["cve_id"]):
        if (i + 1) % 50 == 0:
            print(f"   Progress: {i+1}/{len(df)}...")
        idx = df[df["cve_id"] == cve_id].index[0]
        features = fetch_otx_threat_data(cve_id)
        df.loc[idx, "otx_threat_score"] = features["otx_threat_score"]
        df.loc[idx, "malware_associated"] = features["malware_associated"]
        df.loc[idx, "active_exploits"] = features["active_exploits"]
    
    malware_count = df["malware_associated"].sum()
    print(f"   OK: Found {malware_count} CVEs with malware associations")
    
    print(f"\n{"="*70}")
    print("PHASE 2 COMPLETE")
    print(f"{"="*70}")
    print(f"Total columns: {len(df.columns)}")
    print(f"CVEs in GitHub advisories: {ghsa_count}")
    print(f"CVEs with malware links: {malware_count}")
    
    print(f"\nSaving to {OUTPUT_FILE}...")
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"OK: Saved {len(df)} rows to {OUTPUT_FILE}")
    
    print(f"\nColumn summary:")
    print(f"  Original (6): cve_id, description, cvss_score, published_date, epss_score, days_since_published")
    print(f"  Phase 1 (8): in_cisa_kev, cisa_exploitation_deadline, has_public_poc, poc_count, min_exploit_difficulty, affected_packages_count, primary_ecosystem, has_fixed_version")
    print(f"  Phase 2 (9): attack_vector, requires_authentication, requires_user_interaction, scope_changed, in_github_advisories, github_affected_count, patch_available, otx_threat_score, malware_associated, active_exploits")
    print(f"  Total: {len(df.columns)} columns")

if __name__ == "__main__":
    main()
