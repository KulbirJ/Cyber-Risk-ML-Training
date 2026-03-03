"""
Phase 3: TIER 3 Enhancement - Metasploit Modules + Optional Censys Data
=========================================================================

Adds exploitation framework data and internet exposure metrics:
  - Metasploit module availability and metadata
  - Optional: Censys internet-facing asset data

Input:  cves_enhanced_tier2.csv (500 rows × 24 columns)
Output: cves_enhanced_tier3.csv (500 rows × ~30 columns)

APIs used:
  - Metasploit RPC API (local or remote)
  - Censys API (optional - requires API key)
"""

import pandas as pd
import requests
import json
import time
import os
from typing import Dict
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

INPUT_FILE = "cves_enhanced_tier2.csv"  # Use Phase 2 output
OUTPUT_FILE = "cves_enhanced_tier3.csv"

# Metasploit search API (public endpoint - no auth required)
METASPLOIT_SEARCH_URL = "https://www.exploit-db.com/api/search"

# Censys API (optional - requires API key)
CENSYS_API_BASE = "https://api.censys.io/v1"
CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")

HEADERS = {"User-Agent": "CVE-Enhancement/3.0"}


def fetch_metasploit_modules(cve_id: str) -> Dict:
    """
    Fetch Metasploit module availability for a given CVE.
    Uses Exploit-DB public API which includes Metasploit module references.
    
    Uses shorter timeout to avoid hanging on slow/unresponsive APIs.
    """
    features = {
        "metasploit_modules": 0,
        "has_metasploit_module": 0,
        "module_rank": "unknown",
        "module_type": "unknown"
    }
    
    try:
        params = {"q": cve_id, "type": "metasploit"}
        # Use shorter timeout (3 seconds) - fail fast if API is slow
        response = requests.get(METASPLOIT_SEARCH_URL, params=params, headers=HEADERS, 
                               timeout=(2, 3), allow_redirects=False)
        
        if response.status_code == 200:
            data = response.json()
            results = data.get("results", [])
            
            if results:
                features["metasploit_modules"] = len(results)
                features["has_metasploit_module"] = 1
                
                # Get highest-ranked module
                if results:
                    module = results[0]
                    features["module_rank"] = module.get("type", "unknown").lower()
                    features["module_type"] = module.get("platform", "unknown").lower()
        
        # Minimal delay to respect rate limits
        time.sleep(0.1)
        
    except requests.exceptions.Timeout:
        # Quick timeout - move to next CVE
        pass
    except requests.exceptions.ConnectionError:
        pass
    except Exception:
        pass  # Silent fail - continue with other CVEs
    
    return features


def fetch_censys_exposure(cve_id: str) -> Dict:
    """
    Fetch internet-facing asset exposure data from Censys.
    This shows how many internet-facing systems might be affected.
    
    Optional: Only works if CENSYS_API_ID and CENSYS_API_SECRET are set.
    Uses shorter timeout to fail fast on slow APIs.
    """
    features = {
        "censys_exposed_count": 0,
        "has_censys_data": 0
    }
    
    # Skip if credentials not provided
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        return features
    
    try:
        # Query Censys for services matching CVE keywords
        url = f"{CENSYS_API_BASE}/search/ipv4"
        auth = (CENSYS_API_ID, CENSYS_API_SECRET)
        
        # Simple search: look for services related to the CVE
        # (This is a simplified example - real usage would parse CVE details)
        query = f'"{cve_id}"'
        payload = {"q": query, "page": 1, "fields": ["ip"]}
        
        # Use shorter timeout (2 seconds) - fail fast
        response = requests.post(url, json=payload, auth=auth, headers=HEADERS, 
                                timeout=(2, 3), allow_redirects=False)
        
        if response.status_code == 200:
            data = response.json()
            count = data.get("metadata", {}).get("count", 0)
            
            if count > 0:
                features["censys_exposed_count"] = min(count, 10000)  # Cap at max for feature
                features["has_censys_data"] = 1
        
        # Rate limiting for Censys API
        time.sleep(0.5)
        
    except requests.exceptions.Timeout:
        pass  # Quick timeout - move to next CVE
    except requests.exceptions.ConnectionError:
        pass
    except Exception:
        pass  # Silent fail - continue with other CVEs
    
    return features


def fetch_cvss_severity_metrics(cvss_score: float) -> Dict:
    """
    Derive additional severity metrics from CVSS score.
    These are deterministic features based on CVSS ranges.
    """
    severity_band = "critical" if cvss_score >= 9.0 else \
                   "high" if cvss_score >= 7.0 else \
                   "medium" if cvss_score >= 4.0 else \
                   "low"
    
    is_critical = 1 if cvss_score >= 9.0 else 0
    is_high = 1 if cvss_score >= 7.0 else 0
    
    return {
        "cvss_severity_band": severity_band,
        "is_critical_cvss": is_critical,
        "is_high_cvss": is_high
    }


def main():
    """
    Main enrichment pipeline for Phase 3.
    1. Load Phase 2 output
    2. Add Metasploit module data
    3. Add optional Censys exposure data
    4. Add CVSS severity metrics
    5. Save to Phase 3 output
    """
    print("=" * 70)
    print("PHASE 3: TIER 3 CVE ENRICHMENT")
    print("=" * 70)
    
    # Load Phase 2 output
    print(f"\nLoading {INPUT_FILE}...")
    try:
        df = pd.read_csv(INPUT_FILE)
        print(f"OK: Loaded {len(df)} CVEs with {len(df.columns)} columns")
    except FileNotFoundError:
        print(f"ERROR: {INPUT_FILE} not found. Run Phase 2 first.")
        return
    
    # Add new Phase 3 columns
    df["metasploit_modules"] = 0
    df["has_metasploit_module"] = 0
    df["module_rank"] = "unknown"
    df["module_type"] = "unknown"
    df["censys_exposed_count"] = 0
    df["has_censys_data"] = 0
    df["cvss_severity_band"] = "unknown"
    df["is_critical_cvss"] = 0
    df["is_high_cvss"] = 0
    
    print("\n[1/3] Fetching Metasploit module data...")
    for i, cve_id in enumerate(df["cve_id"]):
        if (i + 1) % 50 == 0:
            print(f"   Progress: {i+1}/{len(df)}...")
        idx = df[df["cve_id"] == cve_id].index[0]
        features = fetch_metasploit_modules(cve_id)
        df.loc[idx, "metasploit_modules"] = features["metasploit_modules"]
        df.loc[idx, "has_metasploit_module"] = features["has_metasploit_module"]
        df.loc[idx, "module_rank"] = features["module_rank"]
        df.loc[idx, "module_type"] = features["module_type"]
    
    msf_count = df["has_metasploit_module"].sum()
    print(f"   OK: Found {msf_count} CVEs with Metasploit modules")
    
    print("\n[2/3] Fetching Censys internet exposure data...")
    if CENSYS_API_ID and CENSYS_API_SECRET:
        for i, cve_id in enumerate(df["cve_id"]):
            if (i + 1) % 100 == 0:
                print(f"   Progress: {i+1}/{len(df)}...")
            idx = df[df["cve_id"] == cve_id].index[0]
            features = fetch_censys_exposure(cve_id)
            df.loc[idx, "censys_exposed_count"] = features["censys_exposed_count"]
            df.loc[idx, "has_censys_data"] = features["has_censys_data"]
        censys_count = df["has_censys_data"].sum()
        print(f"   OK: Found {censys_count} CVEs with Censys data")
    else:
        print("   SKIP: Censys API credentials not provided (optional)")
        print("   To enable: Set CENSYS_API_ID and CENSYS_API_SECRET in .env")
    
    print("\n[3/3] Computing CVSS severity metrics...")
    for idx, row in df.iterrows():
        features = fetch_cvss_severity_metrics(row["cvss_score"])
        df.loc[idx, "cvss_severity_band"] = features["cvss_severity_band"]
        df.loc[idx, "is_critical_cvss"] = features["is_critical_cvss"]
        df.loc[idx, "is_high_cvss"] = features["is_high_cvss"]
    
    critical_count = df["is_critical_cvss"].sum()
    high_count = df["is_high_cvss"].sum()
    print(f"   OK: Computed severity bands ({critical_count} critical, {high_count} high)")
    
    print(f"\n{'='*70}")
    print("PHASE 3 COMPLETE")
    print(f"{'='*70}")
    print(f"Total columns: {len(df.columns)}")
    print(f"CVEs with Metasploit modules: {msf_count}")
    print(f"CVEs with Censys exposure data: {df['has_censys_data'].sum()}")
    print(f"Critical severity (CVSS >= 9.0): {critical_count}")
    print(f"High severity (CVSS >= 7.0): {high_count}")
    
    print(f"\nSaving to {OUTPUT_FILE}...")
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"OK: Saved {len(df)} rows to {OUTPUT_FILE}")
    
    print(f"\nColumn summary:")
    print(f"  Original (6): cve_id, description, cvss_score, published_date, epss_score, days_since_published")
    print(f"  Phase 1 (8): in_cisa_kev, cisa_exploitation_deadline, has_public_poc, poc_count, min_exploit_difficulty, affected_packages_count, primary_ecosystem, has_fixed_version")
    print(f"  Phase 2 (10): attack_vector, requires_authentication, requires_user_interaction, scope_changed, in_github_advisories, github_affected_count, patch_available, otx_threat_score, malware_associated, active_exploits")
    print(f"  Phase 3 (9): metasploit_modules, has_metasploit_module, module_rank, module_type, censys_exposed_count, has_censys_data, cvss_severity_band, is_critical_cvss, is_high_cvss")
    print(f"  Total: {len(df.columns)} columns")
    
    print(f"\nData preview:")
    preview_cols = ['cve_id', 'has_metasploit_module', 'cvss_severity_band', 'is_critical_cvss']
    print(df[preview_cols].head(10).to_string())


if __name__ == "__main__":
    main()
