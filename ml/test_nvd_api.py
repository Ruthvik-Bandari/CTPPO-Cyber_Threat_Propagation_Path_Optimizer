#!/usr/bin/env python3
"""
Quick test to find correct NVD API 2.0 format
"""

import requests

API_KEY = "2a206156-1674-4d3c-aef0-9fd0fcb681a2"

headers = {
    'apiKey': API_KEY,
    'User-Agent': 'CTPPO-Research/1.0'
}

# Test 1: Fetch a specific CVE (should always work)
print("Test 1: Fetching specific CVE...")
url1 = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"
r1 = requests.get(url1, headers=headers)
print(f"  Status: {r1.status_code}")
if r1.status_code == 200:
    data = r1.json()
    print(f"  ✅ Works! Found: {data.get('totalResults', 0)} CVEs")
else:
    print(f"  ❌ Failed: {r1.text[:200]}")

# Test 2: Date format with UTC offset
print("\nTest 2: Date format with +00:00...")
url2 = "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2024-01-01T00:00:00.000%2B00:00&pubEndDate=2024-01-02T00:00:00.000%2B00:00&resultsPerPage=5"
r2 = requests.get(url2, headers=headers)
print(f"  Status: {r2.status_code}")
if r2.status_code == 200:
    data = r2.json()
    print(f"  ✅ Works! Found: {data.get('totalResults', 0)} CVEs")

# Test 3: Using lastModStartDate instead
print("\nTest 3: Using lastModStartDate...")
url3 = "https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=2024-01-01T00:00:00.000&lastModEndDate=2024-01-02T00:00:00.000&resultsPerPage=5"
r3 = requests.get(url3, headers=headers)
print(f"  Status: {r3.status_code}")
if r3.status_code == 200:
    data = r3.json()
    print(f"  ✅ Works! Found: {data.get('totalResults', 0)} CVEs")

# Test 4: No date filter, just get recent
print("\nTest 4: No date filter (recent CVEs)...")
url4 = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5"
r4 = requests.get(url4, headers=headers)
print(f"  Status: {r4.status_code}")
if r4.status_code == 200:
    data = r4.json()
    print(f"  ✅ Works! Total available: {data.get('totalResults', 0)} CVEs")
    if data.get('vulnerabilities'):
        cve = data['vulnerabilities'][0]['cve']
        print(f"  Sample CVE: {cve.get('id')}")
        metrics = cve.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            cvss = metrics['cvssMetricV31'][0]['cvssData']
            print(f"  CVSS v3.1: {cvss.get('baseScore')} - {cvss.get('attackVector')}")

# Test 5: Proper URL encoding with requests params
print("\nTest 5: Using requests params dict...")
params = {
    'pubStartDate': '2024-01-01T00:00:00.000',
    'pubEndDate': '2024-01-02T00:00:00.000',
    'resultsPerPage': 5
}
r5 = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, headers=headers)
print(f"  Status: {r5.status_code}")
print(f"  Actual URL: {r5.url}")
if r5.status_code == 200:
    data = r5.json()
    print(f"  ✅ Works! Found: {data.get('totalResults', 0)} CVEs")

print("\n" + "="*60)
print("Run this script to find which format works!")
print("="*60)
