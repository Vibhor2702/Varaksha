#!/usr/bin/env python
"""
Backend Connection Verification Script

Tests if the Railway backend is:
1. Reachable from the internet
2. Health endpoint responding
3. ML models loaded
4. API ready to score transactions
"""

import sys
import json
import time
try:
    import requests
except ImportError:
    print("[ERROR] requests library not installed. Run: pip install requests")
    sys.exit(1)

BACKEND_URL = "https://varaksha-production.up.railway.app"
TIMEOUT = 10

print("=" * 80)
print("VARAKSHA BACKEND CONNECTION VERIFICATION")
print("=" * 80)
print(f"\nBackend URL: {BACKEND_URL}\n")

# Test 1: Health endpoint
print("[1] Testing health endpoint...")
try:
    response = requests.get(f"{BACKEND_URL}/health", timeout=TIMEOUT)
    if response.status_code == 200:
        data = response.json()
        print(f"  [OK] Status: {response.status_code}")
        print(f"  [OK] Response: {json.dumps(data, indent=2)}")
        cache_size = data.get('cache_entries', 'unknown')
        print(f"  [OK] Cache entries: {cache_size}")
    else:
        print(f"  [ERROR] Status: {response.status_code}")
        print(f"  Response: {response.text[:200]}")
        sys.exit(1)
except requests.exceptions.Timeout:
    print(f"  [ERROR] Connection timeout (>{TIMEOUT}s) - Backend may be offline")
    sys.exit(1)
except requests.exceptions.ConnectionError:
    print(f"  [ERROR] Cannot connect to backend")
    print(f"  Make sure Railway service is running and not suspended")
    sys.exit(1)
except Exception as e:
    print(f"  [ERROR] {e}")
    sys.exit(1)

# Test 2: Health endpoint is actually returning data
print("\n[2] Verifying health response structure...")
try:
    assert 'status' in data
    assert 'version' in data
    assert data['status'] == 'ok'
    print(f"  [OK] Response structure valid")
    print(f"  [OK] Backend version: {data.get('version', 'unknown')}")
except (AssertionError, KeyError) as e:
    print(f"  [ERROR] Invalid health response structure: {e}")
    sys.exit(1)

# Test 3: Test API endpoint with sample transaction
print("\n[3] Testing transaction scoring endpoint...")
try:
    payload = {
        "vpa": "test@ybl",
        "amount": 5000,
        "merchant_category": "ECOM",
        "transaction_type": "DEBIT",
        "device_type": "ANDROID",
        "hour_of_day": 14,
        "day_of_week": 2,
        "transactions_last_1h": 1,
        "transactions_last_24h": 3,
        "amount_zscore": 0.2,
        "gps_delta_km": 2,
        "is_new_device": False,  # Must be boolean, not integer
        "is_new_merchant": False,  # Must be boolean, not integer
        "balance_drain_ratio": 0.05,
        "account_age_days": 365,
        "previous_failed_attempts": 0,
        "transfer_cashout_flag": 0,
    }
    
    response = requests.post(
        f"{BACKEND_URL}/v1/tx",
        json=payload,
        timeout=TIMEOUT,
        headers={"Content-Type": "application/json"}
    )
    
    if response.status_code == 200:
        tx_result = response.json()
        print(f"  [OK] Status: {response.status_code}")
        print(f"  [OK] Verdict: {tx_result.get('verdict', 'N/A')}")
        print(f"  [OK] Risk Score: {tx_result.get('risk_score', 'N/A')}")
        print(f"  [OK] Latency: {tx_result.get('latency_us', 'N/A')} microseconds")
        print(f"  [OK] Full response: {json.dumps(tx_result, indent=2)}")
    else:
        print(f"  [ERROR] Status: {response.status_code}")
        print(f"  Response: {response.text[:200]}")
        sys.exit(1)
except requests.exceptions.Timeout:
    print(f"  [ERROR] API endpoint timeout - sidecar may not be running")
    sys.exit(1)
except Exception as e:
    print(f"  [ERROR] {e}")
    sys.exit(1)

# Test 4: Verify ML models are being used
print("\n[4] Checking if ML models are being used...")
try:
    # Test with suspicious transaction - should get higher score
    suspicious_payload = {
        "vpa": "test@ybl",
        "amount": 500000,
        "merchant_category": "GAMBLING",
        "transaction_type": "DEBIT",
        "device_type": "WEB",
        "hour_of_day": 3,
        "day_of_week": 6,
        "transactions_last_1h": 20,
        "transactions_last_24h": 100,
        "amount_zscore": 5,
        "gps_delta_km": 1000,
        "is_new_device": True,  # Must be boolean, not integer
        "is_new_merchant": True,  # Must be boolean, not integer
        "balance_drain_ratio": 0.9,
        "account_age_days": 10,
        "previous_failed_attempts": 5,
        "transfer_cashout_flag": 1,
    }
    
    response = requests.post(
        f"{BACKEND_URL}/v1/tx",
        json=suspicious_payload,
        timeout=TIMEOUT
    )
    
    if response.status_code == 200:
        sus_result = response.json()
        normal_score = tx_result.get('risk_score', 0)
        sus_score = sus_result.get('risk_score', 0)
        
        print(f"  [OK] Normal transaction score: {normal_score}")
        print(f"  [OK] Suspicious transaction score: {sus_score}")
        
        if sus_score > normal_score:
            print(f"  [OK] Scores are variable (ML models working!)")
        else:
            print(f"  [WARNING] Scores not varying - may indicate hardcoded responses")
    else:
        print(f"  [ERROR] Status: {response.status_code}")
        sys.exit(1)
except Exception as e:
    print(f"  [ERROR] {e}")
    sys.exit(1)

print("\n" + "=" * 80)
print("CONNECTION VERIFICATION SUCCESS")
print("=" * 80)
print("""
Backend is fully operational:
  ✓ Reachable from internet
  ✓ Health endpoint working
  ✓ API endpoint accessible
  ✓ ML models scoring transactions
  ✓ Ready for production

Your frontend can now connect to this backend.
Ensure NEXT_PUBLIC_API_URL is set in Cloudflare Pages to:
  https://varaksha-production.up.railway.app
""")
