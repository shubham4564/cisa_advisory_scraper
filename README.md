# CISA Cybersecurity Advisory Scraper

Scrapes cybersecurity advisories from https://www.cisa.gov for NLP analysis. Extracts prose text, CVE details, and metadata from HTML (no APIs).

## Setup

```bash
# Install dependencies
pip install -r requirements.txt
```

**Requirements**: Python 3.10+, requests, beautifulsoup4, lxml

## Usage

```bash
# Scrape recent advisories (default: 10)
python scrape_cisa_advisory.py --output data/advisories.csv

# Scrape more advisories
python scrape_cisa_advisory.py --max-advisories 50 --output data/advisories.csv

# Scrape specific URL
python scrape_cisa_advisory.py --url "https://www.cisa.gov/news-events/alerts/2026/02/03/..." --output data/single.csv

# Add delay between requests (polite scraping)
python scrape_cisa_advisory.py --max-advisories 20 --delay 2.0
```

## What It Scrapes

**Data source**: CISA cybersecurity advisories (alerts, advisories, ICS advisories)

**Why this data**: Rich cybersecurity prose text with structured metadata - ideal for NLP tasks like threat classification, entity extraction, and security text analysis. Contains technical descriptions, mitigation guidance, and vulnerability details.

**Output format**: CSV with columns:
- `url`: Advisory URL
- `title`: Advisory title
- `advisory_type`: ALERT, ADVISORY, ICS ADVISORY
- `release_date`: ISO 8601 date
- `cve_ids`: Pipe-separated CVE identifiers
- `cve_count`: Number of CVEs
- `cve_descriptions`: Pipe-separated CVE descriptions
- `body_text`: Full prose content (avg 1,200 chars/advisory)
- `fetched_at`: Scrape timestamp

**Sample output**: [data/advisories.csv](data/advisories.csv) - 9 recent advisories with 22 CVEs and 10,840 characters of prose text
- `release_date`: `{original: "...", iso8601: "YYYY-MM-DD"}`
- `cves`: `[{id: "CVE-...", url: "...", description: "..."}]`
- `body_text`: Main advisory content (paragraphs)

## Features

- **Caching**: Compressed HTML storage with ETag/Last-Modified support
- **Rate limiting**: Configurable delays (default: 1s between requests)
- **Multi-page discovery**: Crawls listing pages to find advisory URLs
- **Template resilience**: Multiple fallback strategies for date extraction
- **Deduplication**: Content-based hashing prevents duplicate processing

## Testing

```bash
# Run validation tests
python test_scraper.py
```
