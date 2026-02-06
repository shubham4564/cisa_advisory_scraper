#!/bin/bash
# Quick start commands for CISA advisory scraper

# Install dependencies
echo "Installing dependencies..."
python -m pip install -r requirements.txt

# Test on reference page
echo -e "\n1. Testing single advisory extraction..."
python scrape_cisa_advisory.py \
  --url "https://www.cisa.gov/news-events/alerts/2026/02/03/cisa-adds-four-known-exploited-vulnerabilities-catalog" \
  --validate \
  --output data/test.jsonl

# Run validation tests
echo -e "\n2. Running validation tests..."
python test_scraper.py

# Scrape small batch
echo -e "\n3. Scraping sample batch (5 advisories)..."
python scrape_cisa_advisory.py \
  --max-advisories 5 \
  --validate \
  --output data/advisories_sample.jsonl

# View results
echo -e "\n4. Sample results:"
head -1 data/advisories_sample.jsonl | python -m json.tool | head -30

echo -e "\nDone! Check data/ directory for outputs."
