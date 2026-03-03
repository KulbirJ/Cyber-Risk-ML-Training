# enrich_epss.py
"""
Fetches EPSS scores for CVEs from the official FIRST.org API,
one at a time with rate limiting and progress tracking using tqdm.
Merges results back into cves_clean.csv.
"""

import requests
import pandas as pd
import time
from tqdm import tqdm
import json

# ── Configuration ─────────────────────────────────────────────────────────────

EPSS_API_URL = "https://api.first.org/data/v1/epss"
RATE_LIMIT_DELAY = 0.5  # seconds between requests (conservative to respect API)
INPUT_CSV = "cves_clean.csv"
OUTPUT_CSV = "cves_clean_enriched.csv"

# ── Helper function: fetch single CVE EPSS score ──────────────────────────────

def fetch_epss_score(cve_id: str) -> float | None:
    """
    Fetches the EPSS score for a single CVE ID from the FIRST.org API.
    
    Args:
        cve_id: CVE identifier string (e.g. "CVE-2025-11749")
    
    Returns:
        EPSS score as a float [0.0, 1.0], or None if not found or error occurs.
    """
    try:
        # Build the URL with the CVE ID as a query parameter
        url = f"{EPSS_API_URL}?cve={cve_id}"
        
        # Send GET request with a short timeout
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        # Parse the JSON response
        data = response.json()
        
        # The "data" key contains a list; we want the first (and only) entry
        if data.get("data"):
            # Extract the EPSS score string and convert to float
            epss_str = data["data"][0].get("epss", None)
            if epss_str:
                return float(epss_str)
        
        return None
    
    except requests.exceptions.RequestException as e:
        # Network or HTTP error; log it but don't crash
        print(f"  Warning: Failed to fetch {cve_id}: {e}")
        return None
    except (ValueError, KeyError) as e:
        # JSON parsing or key error
        print(f"  Warning: Malformed response for {cve_id}: {e}")
        return None


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # Load the CSV
    print(f"Loading {INPUT_CSV}...")
    df = pd.read_csv(INPUT_CSV)
    
    # Find rows where epss_score is NaN (missing)
    missing_mask = df["epss_score"].isna()
    missing_cves = df[missing_mask]["cve_id"].tolist()
    
    print(f"Found {len(missing_cves)} CVEs with missing EPSS scores")
    print(f"Total CVEs: {len(df)}")
    
    if not missing_cves:
        print("No missing EPSS scores to fetch. Exiting.")
        return
    
    # Dictionary to store newly fetched scores
    new_scores = {}
    
    # Use tqdm to show a progress bar and handle rate limiting
    # desc: label for the progress bar
    # unit: "CVE" (shown as "1 CVE/s")
    # total: number of items to iterate
    for cve_id in tqdm(
        missing_cves,
        desc="Fetching EPSS scores",
        unit="CVE",
        ncols=80
    ):
        # Fetch the EPSS score
        score = fetch_epss_score(cve_id)
        new_scores[cve_id] = score
        
        # Rate limit: sleep between requests to avoid overwhelming the API
        time.sleep(RATE_LIMIT_DELAY)
    
    # Update the DataFrame with newly fetched scores
    # using map() to look up each CVE ID in new_scores
    # This will fill in the NaN values but leave existing scores unchanged
    for cve_id, score in new_scores.items():
        df.loc[df["cve_id"] == cve_id, "epss_score"] = score
    
    # Count how many we successfully fetched
    newly_filled = sum(1 for score in new_scores.values() if score is not None)
    print(f"\nSuccessfully fetched {newly_filled} out of {len(missing_cves)} missing scores")
    
    # Save the enriched DataFrame
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Saved enriched data to {OUTPUT_CSV}")
    
    # Summary statistics
    total_with_epss = df["epss_score"].notna().sum()
    total_without = df["epss_score"].isna().sum()
    
    print(f"\n── Final EPSS coverage ──")
    print(f"   With EPSS score: {total_with_epss} / {len(df)} ({100 * total_with_epss / len(df):.1f}%)")
    print(f"   Missing EPSS:    {total_without} / {len(df)}")
    print(f"   Mean EPSS:       {df['epss_score'].mean():.6f}")
    print(f"   Max EPSS:        {df['epss_score'].max():.6f}")


if __name__ == "__main__":
    main()
