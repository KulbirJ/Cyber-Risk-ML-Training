# process_cves.py
"""
Loads cves_day1.json, converts it to a clean pandas DataFrame,
fetches EPSS scores from the FIRST.org API, adds a days_since_published
column, and saves the result to cves_clean.csv.
"""

# ── Imports ───────────────────────────────────────────────────────────────────

import json                          # built-in: read the local JSON file
import requests                      # HTTP requests for the EPSS API
import pandas as pd                  # DataFrame creation and manipulation
from datetime import datetime, timezone  # date arithmetic for days_since_published

# ── Step 1: Load the raw JSON file ───────────────────────────────────────────

# Open and parse cves_day1.json into a Python list of dicts.
# Each element is one NVD vulnerability record (wrapper: {"cve": {...}}).
with open("cves_day1.json", "r", encoding="utf-8") as f:
    raw = json.load(f)               # raw is a list of {"cve": {...}} objects

print(f"Loaded {len(raw)} CVE records from cves_day1.json")

# ── Step 2: Helper – extract the best available CVSS base score ───────────────

def get_cvss_score(metrics: dict) -> float | None:
    """
    Tries CVSS v3.1 first (most common), then v4.0, then v2.0.
    Returns the baseScore as a float, or None if no score is present.
    """
    # cvssMetricV31 is a list; grab the first entry's baseScore if it exists
    if metrics.get("cvssMetricV31"):
        return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

    # Fall back to CVSS v4.0 if v3.1 is absent
    if metrics.get("cvssMetricV40"):
        return metrics["cvssMetricV40"][0]["cvssData"]["baseScore"]

    # Last resort: CVSS v2.0 (older CVEs)
    if metrics.get("cvssMetricV2"):
        return metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

    return None   # No score available for this CVE

# ── Step 3: Build a flat list of dicts (one per CVE) ─────────────────────────

records = []                         # will hold one dict per CVE

for item in raw:
    cve = item["cve"]                # unwrap the inner "cve" object

    # --- CVE ID (e.g. "CVE-2025-12345") ---
    cve_id = cve.get("id", "")

    # --- English description (first entry in the descriptions list) ---
    descriptions = cve.get("descriptions", [])
    # Filter to English; fall back to the first available if none tagged "en"
    en_desc = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else ""
    )

    # --- CVSS score (best available version) ---
    metrics = cve.get("metrics", {})
    cvss_score = get_cvss_score(metrics)

    # --- Published date (ISO 8601 string, e.g. "2025-11-02T22:15:33.407") ---
    published_date = cve.get("published", "")

    records.append({
        "cve_id":         cve_id,
        "description":    en_desc,
        "cvss_score":     cvss_score,
        "published_date": published_date,
        "epss_score":     None,      # placeholder; filled in Step 5
    })

print(f"Extracted fields for {len(records)} CVEs")

# ── Step 4: Create the initial DataFrame ─────────────────────────────────────

# pd.DataFrame() accepts a list of dicts; each dict becomes one row,
# with dict keys becoming column names.
df = pd.DataFrame(records)

# Convert published_date from string to a timezone-aware datetime object
# so we can do date arithmetic later.
# errors="coerce" turns unparseable strings into NaT instead of crashing.
df["published_date"] = pd.to_datetime(df["published_date"], errors="coerce", utc=True)

# Cast cvss_score to float (it may be None/NaN for some records)
df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")

# ── Step 5: Fetch EPSS scores from the FIRST.org API ─────────────────────────
# EPSS (Exploit Prediction Scoring System) rates the probability (0–1) that
# a CVE will be exploited in the wild within the next 30 days.
# API docs: https://www.first.org/epss/api

EPSS_API = "https://api.first.org/data/v1/epss"
CHUNK_SIZE = 100     # maximum safe number of CVE IDs per request
epss_map = {}        # will map cve_id → epss_score (float)

all_ids = df["cve_id"].tolist()      # extract all CVE IDs as a Python list

# Process IDs in chunks to avoid overly long URLs
for i in range(0, len(all_ids), CHUNK_SIZE):
    chunk = all_ids[i : i + CHUNK_SIZE]   # slice CHUNK_SIZE IDs at a time

    try:
        # Build the URL manually to keep commas unencoded (%2C breaks the API)
        url = f"{EPSS_API}?cve={','.join(chunk)}"
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        # "data" is a list of {"cve": "CVE-...", "epss": "0.001", "percentile": "..."}
        for entry in data.get("data", []):
            epss_map[entry["cve"]] = float(entry["epss"])   # store score keyed by CVE ID

    except Exception as e:
        # If a single chunk fails, warn but continue with remaining chunks
        print(f"  Warning: EPSS fetch failed for chunk starting at index {i}: {e}")

print(f"Retrieved EPSS scores for {len(epss_map)} out of {len(all_ids)} CVEs")

# ── Step 6: Merge EPSS scores into the DataFrame ─────────────────────────────

# map() looks up each cve_id in epss_map; CVEs not in the map become NaN
df["epss_score"] = df["cve_id"].map(epss_map)

# ── Step 7: Add days_since_published column ───────────────────────────────────

# Get today's date as a timezone-aware UTC timestamp so subtraction works
today = pd.Timestamp(datetime.now(timezone.utc))

# Subtract published_date from today; .dt.days extracts the integer day count
# NaT values (bad dates) will produce NaN here, which is safe
df["days_since_published"] = (today - df["published_date"]).dt.days

# ── Step 8: Final column order and cleanup ────────────────────────────────────

# Reorder columns for readability
df = df[[
    "cve_id",
    "description",
    "cvss_score",
    "published_date",
    "epss_score",
    "days_since_published",
]]

# ── Step 9: Save to CSV ───────────────────────────────────────────────────────

OUTPUT = "cves_clean.csv"

# index=False prevents pandas from writing the row numbers as a column
df.to_csv(OUTPUT, index=False, encoding="utf-8")

print(f"\nSaved clean CSV to '{OUTPUT}'")

# ── Step 10: Summary stats ────────────────────────────────────────────────────

print(f"\n── DataFrame shape: {df.shape[0]} rows × {df.shape[1]} columns")
print(f"── CVSS score  — mean: {df['cvss_score'].mean():.2f}  "
      f"min: {df['cvss_score'].min()}  max: {df['cvss_score'].max()}")
print(f"── EPSS score  — mean: {df['epss_score'].mean():.4f}  "
      f"nulls: {df['epss_score'].isna().sum()}")
print(f"── Days since published — mean: {df['days_since_published'].mean():.1f}  "
      f"max: {df['days_since_published'].max()}")
print(f"\nFirst 3 rows preview:")
print(df[["cve_id", "cvss_score", "epss_score", "days_since_published"]].head(3).to_string(index=False))
