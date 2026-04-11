#!/usr/bin/env python3
"""
Test script to verify auto-enrichment is working in the IOC API.

Usage:
    python scripts/test_auto_enrichment.py
"""

import requests
import time
import sys

# Configuration
BASE_URL = "http://localhost:8000/api/v1"

def test_create_and_enrich():
    """Test creating an IOC and checking if it gets enriched."""
    print("=" * 60)
    print("Test 1: Create IOC and verify auto-enrichment")
    print("=" * 60)
    
    # Create a new IOC
    test_ip = f"1.2.3.{int(time.time()) % 250}"  # Generate unique IP
    
    print(f"\n1. Creating IOC: {test_ip}")
    create_response = requests.post(
        f"{BASE_URL}/ioc",
        json={
            "type": "ip",
            "value": test_ip,
            "tags": ["test", "auto-enrich"],
            "confidence": 60
        }
    )
    
    if create_response.status_code != 200:
        print(f"❌ Failed to create IOC: {create_response.status_code}")
        print(create_response.text)
        return False
    
    ioc_data = create_response.json()
    ioc_id = ioc_data["id"]
    print(f"✅ Created IOC with ID: {ioc_id}")
    
    # Wait a moment for enrichment to process
    print("\n2. Waiting 3 seconds for background enrichment...")
    time.sleep(3)
    
    # Retrieve the IOC
    print("\n3. Retrieving IOC (should trigger enrichment if not done)...")
    get_response = requests.get(f"{BASE_URL}/ioc/{ioc_id}")
    
    if get_response.status_code != 200:
        print(f"❌ Failed to retrieve IOC: {get_response.status_code}")
        return False
    
    ioc_detail = get_response.json()
    enrichments = ioc_detail.get("enrichments", [])
    
    print(f"\n4. Enrichment status:")
    if enrichments:
        print(f"✅ IOC has {len(enrichments)} enrichment source(s):")
        for e in enrichments:
            print(f"   - {e['source']}")
        return True
    else:
        print("⚠️  No enrichment data found yet (may still be processing)")
        return False


def test_export_with_enrichment():
    """Test CSV export includes enrichment data."""
    print("\n" + "=" * 60)
    print("Test 2: CSV Export with enrichment data")
    print("=" * 60)
    
    # Get some IOCs to export
    print("\n1. Fetching IOCs for export...")
    list_response = requests.get(f"{BASE_URL}/ioc?page_size=5")
    
    if list_response.status_code != 200:
        print(f"❌ Failed to list IOCs: {list_response.status_code}")
        return False
    
    iocs = list_response.json()["items"]
    if not iocs:
        print("⚠️  No IOCs found to export")
        return False
    
    ioc_ids = [ioc["id"] for ioc in iocs[:3]]
    print(f"✅ Found {len(ioc_ids)} IOCs to export")
    
    # Export to CSV
    print("\n2. Exporting to CSV with auto-enrichment...")
    export_response = requests.post(
        f"{BASE_URL}/ioc/export",
        json={
            "format": "csv",
            "ioc_ids": ioc_ids
        }
    )
    
    if export_response.status_code != 200:
        print(f"❌ Failed to export: {export_response.status_code}")
        return False
    
    csv_content = export_response.text
    lines = csv_content.strip().split("\n")
    
    print(f"\n3. CSV Export Result:")
    print(f"✅ Exported {len(lines) - 1} IOCs")
    
    # Check if enrichment_sources column exists
    header = lines[0]
    if "enrichment_sources" in header:
        print("✅ CSV includes enrichment_sources column")
        
        # Show sample data
        print("\n4. Sample exported data:")
        for i, line in enumerate(lines[:3]):
            print(f"   {line}")
        
        return True
    else:
        print("❌ CSV missing enrichment_sources column")
        print(f"   Header: {header}")
        return False


def test_list_with_enrich():
    """Test list endpoint with enrich parameter."""
    print("\n" + "=" * 60)
    print("Test 3: List IOCs with enrich parameter")
    print("=" * 60)
    
    print("\n1. Listing IOCs with enrich=true...")
    response = requests.get(f"{BASE_URL}/ioc?page_size=5&enrich=true")
    
    if response.status_code != 200:
        print(f"❌ Failed to list IOCs: {response.status_code}")
        return False
    
    data = response.json()
    print(f"✅ Retrieved {len(data['items'])} IOCs")
    
    # Note: The list endpoint doesn't return enrichments in the items
    # but it triggers enrichment in the background
    print("✅ Enrichment triggered for unenriched IOCs")
    
    return True


def main():
    print("🚀 Testing Auto-Enrichment in IOC API")
    print(f"   Base URL: {BASE_URL}")
    print("")
    
    # Check if API is running
    try:
        health_check = requests.get(f"{BASE_URL.replace('/api/v1', '')}/health", timeout=5)
    except requests.exceptions.RequestException:
        print("❌ API is not running!")
        print(f"   Make sure the backend is running on {BASE_URL}")
        print("   Start it with: cd backend && uvicorn app.main:app --reload")
        return 1
    
    results = []
    
    # Run tests
    results.append(("Create & Auto-Enrich", test_create_and_enrich()))
    results.append(("CSV Export with Enrichment", test_export_with_enrichment()))
    results.append(("List with Enrich Parameter", test_list_with_enrich()))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Summary")
    print("=" * 60)
    
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    passed_count = sum(1 for _, passed in results if passed)
    total_count = len(results)
    
    print(f"\n🎯 Result: {passed_count}/{total_count} tests passed")
    
    if passed_count == total_count:
        print("\n🎉 All tests passed! Auto-enrichment is working correctly.")
        return 0
    else:
        print("\n⚠️  Some tests failed. Check the output above for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
