#!/usr/bin/env python3
"""
Test Suite for Cyber Risk Model v3
===================================

This script provides comprehensive testing for the deployed model v3.
Run this AFTER starting the API server (deploy_model_v3.py).

Usage:
  python test_model_v3.py

Note: Make sure the API server is running on localhost:8000
"""

import requests
import json
import time
import subprocess
import sys
from datetime import datetime

# Configuration
API_URL = "http://localhost:8000"
TEST_CVES = [
    "CVE-2025-12604",  # From enriched dataset
    "CVE-2025-12605",  # From enriched dataset
    "CVE-2025-11749",  # Live fetch from NVD (may not exist)
]

# Colors for console output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"

def print_header(text):
    """Print formatted header"""
    print(f"\n{BOLD}{BLUE}{'='*70}{RESET}")
    print(f"{BOLD}{BLUE}{text:^70}{RESET}")
    print(f"{BOLD}{BLUE}{'='*70}{RESET}\n")

def print_success(text):
    """Print success message"""
    print(f"{GREEN}✓ {text}{RESET}")

def print_error(text):
    """Print error message"""
    print(f"{RED}✗ {text}{RESET}")

def print_warning(text):
    """Print warning message"""
    print(f"{YELLOW}⚠ {text}{RESET}")

def print_info(text):
    """Print info message"""
    print(f"{BLUE}ℹ {text}{RESET}")

def test_api_health():
    """Test 1: Check API health"""
    print_header("TEST 1: API Health Check")
    
    try:
        response = requests.get(f"{API_URL}/health", timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            print_success(f"API is healthy")
            print(f"  Model Version: {data.get('model_version')}")
            print(f"  Features: 28")
            print(f"  Enriched CVEs available: {data.get('enriched_cves')}")
            return True
        else:
            print_error(f"Unexpected status code: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print_error(f"Cannot connect to API at {API_URL}")
        print_warning("Make sure the server is running: python deploy_model_v3.py")
        return False
    except Exception as e:
        print_error(f"Health check failed: {str(e)}")
        return False


def test_single_prediction(cve_id):
    """Test 2: Single CVE prediction"""
    print_header(f"TEST 2: Single CVE Prediction - {cve_id}")
    
    try:
        payload = {
            "cve_id": cve_id,
            "use_enriched_data": True
        }
        
        print_info(f"Sending prediction request for {cve_id}...")
        response = requests.post(
            f"{API_URL}/predict",
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            prediction = response.json()
            
            print_success(f"Prediction successful")
            print(f"\n  CVE ID: {prediction['cve_id']}")
            print(f"  Model Version: {prediction['model_version']}")
            print(f"  Data Source: {prediction['data_source']}")
            print(f"  Features Available: {prediction['features_available']}/28")
            
            print(f"\n  Input Features:")
            print(f"    CVSS Score: {prediction['cvss_score']:.1f}")
            print(f"    EPSS Score: {prediction['epss_score']:.4f}")
            print(f"    Days Since Published: {prediction['days_since_published']}")
            
            print(f"\n  Predictions:")
            print(f"    Risk Score: {prediction['predicted_risk_score']:.4f}")
            print(f"    Severity: {prediction['severity_label']} ({prediction['severity_numeric']})")
            print(f"    Confidence: {prediction['confidence']:.2%}")
            print(f"    Timestamp: {prediction['timestamp']}")
            
            return True, prediction
            
        else:
            print_error(f"API returned status {response.status_code}")
            print(f"  Response: {response.text}")
            return False, None
            
    except requests.exceptions.Timeout:
        print_error(f"Request timed out")
        return False, None
    except Exception as e:
        print_error(f"Prediction failed: {str(e)}")
        return False, None


def test_batch_predictions():
    """Test 3: Batch predictions comparison"""
    print_header("TEST 3: Batch Predictions (Enriched Dataset)")
    
    batch_cves = ["CVE-2025-12604", "CVE-2025-12605", "CVE-2025-12606"]
    results = []
    
    for cve_id in batch_cves:
        try:
            payload = {"cve_id": cve_id, "use_enriched_data": True}
            response = requests.post(f"{API_URL}/predict", json=payload, timeout=10)
            
            if response.status_code == 200:
                results.append(response.json())
                print_success(f"Predicted {cve_id}")
            else:
                print_error(f"Failed to predict {cve_id}: {response.status_code}")
                
        except Exception as e:
            print_error(f"Error predicting {cve_id}: {str(e)}")
    
    # Display comparison table
    if results:
        print(f"\n{BOLD}Prediction Summary:{RESET}")
        print(f"{'CVE ID':<15} {'CVSS':<7} {'Risk Score':<12} {'Severity':<12} {'Confidence':<12}")
        print("-" * 70)
        
        for pred in results:
            print(f"{pred['cve_id']:<15} {pred['cvss_score']:<7.1f} {pred['predicted_risk_score']:<12.4f} {pred['severity_label']:<12} {pred['confidence']:<12.2%}")
        
        return True, results
    else:
        return False, []


def test_live_prediction():
    """Test 4: Live prediction (from NVD API)"""
    print_header("TEST 4: Live Prediction (NVD API)")
    
    cve_id = "CVE-2025-11749"
    
    try:
        payload = {
            "cve_id": cve_id,
            "use_enriched_data": False  # Force live API fetch
        }
        
        print_info(f"Fetching {cve_id} from NVD API...")
        response = requests.post(
            f"{API_URL}/predict",
            json=payload,
            timeout=45
        )
        
        if response.status_code == 200:
            prediction = response.json()
            
            print_success(f"Live prediction successful")
            print(f"  CVE: {prediction['cve_id']}")
            print(f"  Data Source: {prediction['data_source']}")
            print(f"  Features Available: {prediction['features_available']}/28 (limited to basic features)")
            print(f"  Risk Score: {prediction['predicted_risk_score']:.4f}")
            print(f"  Severity: {prediction['severity_label']}")
            print(f"  Confidence: {prediction['confidence']:.2%}")
            
            return True, prediction
            
        elif response.status_code == 400:
            print_warning(f"CVE not found in NVD (expected for future CVEs)")
            print(f"  This is normal - NVD API only has published CVEs")
            return False, None
        else:
            print_error(f"Unexpected status: {response.status_code}")
            return False, None
            
    except requests.exceptions.Timeout:
        print_warning(f"NVD API request timed out (network/API delay)")
        return False, None
    except Exception as e:
        print_error(f"Live prediction failed: {str(e)}")
        return False, None


def test_api_documentation():
    """Test 5: Check API documentation"""
    print_header("TEST 5: API Documentation")
    
    try:
        # Root endpoint
        response = requests.get(f"{API_URL}/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print_success(f"API root endpoint working")
            print(f"  Name: {data.get('name')}")
            print(f"  Version: {data.get('version')}")
            print(f"  Features: {data.get('features')}")
        
        # Swagger UI
        response = requests.get(f"{API_URL}/docs", timeout=5)
        if response.status_code == 200:
            print_success(f"Swagger UI available at {API_URL}/docs")
        
        print_info(f"\nOpenAPI schema: {API_URL}/openapi.json")
        
        return True
        
    except Exception as e:
        print_error(f"Documentation check failed: {str(e)}")
        return False


def generate_report(test_results):
    """Generate test report"""
    print_header("TEST REPORT SUMMARY")
    
    passed = sum(1 for result in test_results if result)
    total = len(test_results)
    
    print(f"Tests Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%\n")
    
    if passed == total:
        print_success("All tests passed! Model v3 is ready for production.")
    elif passed >= total * 0.8:
        print_warning("Most tests passed. Minor issues detected.")
    else:
        print_error("Several tests failed. Review output above.")
    
    print(f"\nTimestamp: {datetime.now().isoformat()}")


def main():
    """Main test suite"""
    print(f"""
{BOLD}{BLUE}╔════════════════════════════════════════════════════════════╗
║  CYBER RISK MODEL v3 - TEST SUITE                          ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  This script runs comprehensive tests on the deployed API  ║
║  Make sure the server is running:                          ║
║    python deploy_model_v3.py                               ║
║                                                            ║
║  Warning: Tests may take 1-2 minutes                        ║
║           (includes NVD API calls)                         ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝{RESET}
    """)
    
    print(f"{BOLD}Starting tests...{RESET}\n")
    
    test_results = []
    
    # Test 1: Health
    test_results.append(test_api_health())
    if not test_results[0]:
        print_error("Health check failed. Stopping tests.")
        return
    
    # Test 2: Single prediction (enriched)
    success, prediction = test_single_prediction(TEST_CVES[0])
    test_results.append(success)
    
    # Test 3: Batch predictions
    success, results = test_batch_predictions()
    test_results.append(success)
    
    # Test 4: Live prediction
    success, prediction = test_live_prediction()
    test_results.append(success)
    
    # Test 5: Documentation
    test_results.append(test_api_documentation())
    
    # Generate report
    generate_report(test_results)
    
    print(f"\n{BOLD}Next Steps:{RESET}")
    print(f"  1. Review test results above")
    print(f"  2. Check Swagger UI: {BLUE}{API_URL}/docs{RESET}")
    print(f"  3. Try custom CVE IDs with curl or Swagger")
    print(f"  4. Integrate into production pipeline")


if __name__ == "__main__":
    main()
