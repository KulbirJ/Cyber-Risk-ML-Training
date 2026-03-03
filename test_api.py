# test_api.py
"""
Test script for the Cyber Risk Model API.
Tests all endpoints with real CVE IDs.
"""

import requests
import json
from time import sleep

API_BASE_URL = "http://localhost:8000"

def print_section(title):
    """Print a formatted section header"""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")

def test_health_check():
    """Test the health check endpoint"""
    print_section("TEST 1: Health Check")
    
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        response.raise_for_status()
        data = response.json()
        
        print("✅ Health check passed")
        print(json.dumps(data, indent=2))
        return True
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False

def test_root_endpoint():
    """Test the root endpoint"""
    print_section("TEST 2: Root Endpoint (Info)")
    
    try:
        response = requests.get(f"{API_BASE_URL}/", timeout=5)
        response.raise_for_status()
        data = response.json()
        
        print("✅ Root endpoint responded")
        print(json.dumps(data, indent=2))
        return True
    except Exception as e:
        print(f"❌ Root endpoint failed: {e}")
        return False

def test_single_prediction(cve_id):
    """Test single CVE prediction"""
    print_section(f"TEST 3: Single Prediction - {cve_id}")
    
    try:
        payload = {"cve_id": cve_id}
        response = requests.post(
            f"{API_BASE_URL}/predict",
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        
        print(f"✅ Prediction successful for {cve_id}")
        print("\nResponse:")
        print(json.dumps(data, indent=2))
        
        # Extract key info
        print(f"\n📊 Summary:")
        print(f"   CVE ID:              {data['cve_id']}")
        print(f"   CVSS Score:          {data['cvss_score']}")
        print(f"   EPSS Score:          {data['epss_score']:.4f}")
        print(f"   Days Since Published: {data['days_since_published']}")
        print(f"   Predicted Risk Score: {data['predicted_risk_score']:.2f}")
        print(f"   Severity:            {data['severity_label']}")
        print(f"   Priority Score:      {data['priority_score']:.1f}/100")
        
        return True
    except Exception as e:
        print(f"❌ Prediction failed: {e}")
        if hasattr(e, 'response'):
            try:
                print(f"   Error details: {e.response.json()}")
            except:
                pass
        return False

def test_batch_prediction():
    """Test batch prediction"""
    print_section("TEST 4: Batch Prediction (Multiple CVEs)")
    
    cve_list = [
        "CVE-2025-11749",
        "CVE-2025-12604",
        "CVE-2025-12139"
    ]
    
    try:
        payload = cve_list
        response = requests.post(
            f"{API_BASE_URL}/predict-batch",
            json=payload,
            timeout=60
        )
        response.raise_for_status()
        data = response.json()
        
        print(f"✅ Batch prediction successful for {len(cve_list)} CVEs")
        print("\nResults:")
        
        # Show summary for each
        if isinstance(data, list):
            for result in data:
                if "error" in result:
                    print(f"   {result['cve_id']}: ❌ Error - {result['error']}")
                else:
                    print(f"   {result['cve_id']}: "
                          f"Risk={result['predicted_risk_score']:.2f}, "
                          f"Severity={result['severity_label']}, "
                          f"Priority={result['priority_score']:.1f}")
        
        return True
    except Exception as e:
        print(f"❌ Batch prediction failed: {e}")
        return False

def main():
    """Run all tests"""
    print("""
╔════════════════════════════════════════════════════════════╗
║      CYBER RISK MODEL API - TEST SUITE                    ║
╚════════════════════════════════════════════════════════════╝

Testing the FastAPI endpoints...
Make sure the server is running first:
  uvicorn app_main:app --host 0.0.0.0 --port 8000

""")
    
    # Check if server is running
    print("⏳ Waiting for server connection...", end=" ", flush=True)
    max_retries = 10
    for i in range(max_retries):
        try:
            requests.get(f"{API_BASE_URL}/health", timeout=2)
            print("✅ Connected!\n")
            break
        except:
            if i == max_retries - 1:
                print(f"❌ Could not connect to server at {API_BASE_URL}")
                print("   Make sure the server is running:")
                print(f"   uvicorn app_main:app --host 0.0.0.0 --port 8000")
                return
            sleep(1)
    
    # Run tests
    results = []
    
    results.append(("Health Check", test_health_check()))
    results.append(("Root Endpoint", test_root_endpoint()))
    results.append(("Single Prediction", test_single_prediction("CVE-2025-11749")))
    results.append(("Batch Prediction", test_batch_prediction()))
    
    # Summary
    print_section("TEST SUMMARY")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status:8} {name}")
    
    print(f"\n  {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")

if __name__ == "__main__":
    main()
