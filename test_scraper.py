"""Unit tests for CISA advisory scraper.

Run with: python test_scraper.py
"""

import json
from pathlib import Path


def test_reference_advisory():
    """Test scraper on the reference page mentioned in requirements."""
    
    test_file = Path("data/test.jsonl")
    
    if not test_file.exists():
        print("❌ Test file not found. Run the scraper first:")
        print('   python scrape_cisa_advisory.py --url "https://www.cisa.gov/news-events/alerts/2026/02/03/..." --output data/test.jsonl')
        return False
    
    with open(test_file, "r", encoding="utf-8") as f:
        advisory = json.loads(f.readline())
    
    # Expected values from the reference page
    expected_title = "CISA Adds Four Known Exploited Vulnerabilities to Catalog"
    expected_type = "ALERT"
    expected_cves = {"CVE-2019-19006", "CVE-2021-39935", "CVE-2025-40551", "CVE-2025-64328"}
    expected_date_original = "February 03, 2026"
    expected_date_iso = "2026-02-03"
    
    # Validate extraction
    errors = []
    
    if advisory.get("title") != expected_title:
        errors.append(f"Title mismatch: got '{advisory.get('title')}'")
    
    if advisory.get("advisory_type") != expected_type:
        errors.append(f"Type mismatch: got '{advisory.get('advisory_type')}'")
    
    extracted_cves = {cve["id"] for cve in advisory.get("cves", [])}
    if extracted_cves != expected_cves:
        errors.append(f"CVE mismatch: got {extracted_cves}")
    
    release_date = advisory.get("release_date", {})
    if release_date.get("original") != expected_date_original:
        errors.append(f"Original date mismatch: got '{release_date.get('original')}'")
    
    if release_date.get("iso8601") != expected_date_iso:
        errors.append(f"ISO date mismatch: got '{release_date.get('iso8601')}'")
    
    # Check CVE descriptions
    for cve in advisory.get("cves", []):
        if not cve.get("description"):
            errors.append(f"Missing description for {cve['id']}")
        if not cve.get("url") or "cve.org" not in cve.get("url", ""):
            errors.append(f"Invalid CVE URL for {cve['id']}")
    
    # Check body text
    body = advisory.get("body_text", "")
    if not body or len(body) < 100:
        errors.append(f"Body text too short or missing: {len(body)} chars")
    
    if "KEV" not in body:
        errors.append("Body text missing expected 'KEV' mention")
    
    # Check outbound links
    links = advisory.get("outbound_links", [])
    if not any("bod" in link["url"].lower() or "bod" in link.get("text", "").lower() for link in links):
        errors.append("Missing BOD link in outbound_links")
    
    # Report results
    if errors:
        print("❌ Validation FAILED:")
        for error in errors:
            print(f"   - {error}")
        return False
    else:
        print("✅ All validations PASSED!")
        print(f"   - Title: {advisory['title']}")
        print(f"   - Type: {advisory['advisory_type']}")
        print(f"   - Date: {release_date['original']} ({release_date['iso8601']})")
        print(f"   - CVEs: {len(advisory['cves'])} extracted correctly")
        print(f"   - Body: {len(body)} characters")
        print(f"   - Links: {len(links)} outbound references")
        return True


if __name__ == "__main__":
    print("Testing CISA Advisory Scraper")
    print("=" * 50)
    success = test_reference_advisory()
    exit(0 if success else 1)
