# fetch_cves.py
"""
Fetches the latest 500 CVEs from the NVD API (v2.0),
saves them to cves_day1.json, and prints how many are from 2025-2026.
"""

import requests
import json
from datetime import datetime, timezone, timedelta

# NVD CVE API v2.0 endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# API key sent as a request header (recommended by NVD for higher rate limits)
HEADERS = {
    "apiKey": "78ec782a-f743-4872-b091-f43720b7e710"
}

# NVD enforces a max 120-day window for date range filters.
# Use a rolling window: 120 days ago → today (UTC).
_now = datetime.now(timezone.utc)
_start = _now - timedelta(days=120)

PARAMS = {
    "resultsPerPage": 500,
    "startIndex": 0,
    "pubStartDate": _start.strftime("%Y-%m-%dT%H:%M:%S.000"),
    "pubEndDate":   _now.strftime("%Y-%m-%dT%H:%M:%S.000")
}

OUTPUT_FILE = "cves_day1.json"


def fetch_latest_cves():
    """
    Sends a GET request to the NVD CVE API and returns the list of CVE items.
    Date params are appended directly to the URL to avoid colon (%3A) encoding
    issues that can cause 404 errors with the NVD API.
    Returns an empty list if the request fails.
    """
    try:
        print(f"Fetching CVEs from NVD API...")

        # Build query string manually to keep colons unencoded in date params
        pub_start = PARAMS["pubStartDate"]
        pub_end   = PARAMS["pubEndDate"]
        url = (
            f"{NVD_API_URL}"
            f"?resultsPerPage={PARAMS['resultsPerPage']}"
            f"&startIndex={PARAMS['startIndex']}"
            f"&pubStartDate={pub_start}"
            f"&pubEndDate={pub_end}"
        )

        response = requests.get(url, headers=HEADERS, timeout=60)
        response.raise_for_status()  # Raise exception for 4xx/5xx responses
        data = response.json()

        total = data.get("totalResults", 0)
        print(f"Total CVEs available in NVD: {total}")

        vulnerabilities = data.get("vulnerabilities", [])
        print(f"CVEs fetched in this request: {len(vulnerabilities)}")
        return vulnerabilities

    except requests.exceptions.HTTPError as e:
        print(f"HTTP error: {e}")
    except requests.exceptions.ConnectionError:
        print("Connection error: Could not reach the NVD API.")
    except requests.exceptions.Timeout:
        print("Request timed out. NVD API may be slow; try again later.")
    except Exception as e:
        print(f"Unexpected error while fetching CVEs: {e}")

    return []


def save_to_json(data, filename):
    """
    Saves data as formatted JSON to the given filename.
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"Saved {len(data)} CVEs to '{filename}'")
    except IOError as e:
        print(f"Error saving to file: {e}")


def count_cves_in_year_range(vulnerabilities, start_year, end_year):
    """
    Counts CVEs whose published date falls within [start_year, end_year] inclusive.
    """
    count = 0
    for item in vulnerabilities:
        try:
            # Published date is in ISO 8601 format, e.g. "2025-01-15T12:00:00.000"
            published_str = item["cve"]["published"]
            year = datetime.fromisoformat(published_str.rstrip("Z")).year
            if start_year <= year <= end_year:
                count += 1
        except (KeyError, ValueError):
            # Skip entries with missing or malformed dates
            continue
    return count


def main():
    # Step 1: Fetch the latest 500 CVEs from the NVD API
    cves = fetch_latest_cves()

    if not cves:
        print("No CVEs were retrieved. Exiting.")
        return

    # Step 2: Save the raw CVE data to a JSON file
    save_to_json(cves, OUTPUT_FILE)

    # Step 3: Count and print how many CVEs are from 2025-2026
    count = count_cves_in_year_range(cves, 2025, 2026)
    print(f"\nCVEs published in 2025-2026: {count} out of {len(cves)} fetched")


if __name__ == "__main__":
    main()
