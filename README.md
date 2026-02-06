# Cybersecurity + Quotes Scraper for NLP Practice

Scrapes NLP-friendly text datasets from HTML (no APIs):
- **cisa**: Cybersecurity advisories from https://www.cisa.gov/news-events/cybersecurity-advisories (titles, dates, summaries, URLs).
- **cisa-detailed**: Enhanced scraper with deep field extraction (CVEs, body text, links, JSONL output).
- **quotes**: Prose quotes + authors + tags from https://quotes.toscrape.com.

## Requirements
- Python 3.10+ (tested on Ubuntu and Windows).
- Install deps once: `python -m pip install -r requirements.txt`.

## How to run

### Basic CISA listing scraper (CSV)
```bash
python scraper.py --source cisa --max-pages 5 --output data/cisa_advisories.csv
```

### Enhanced CISA advisory scraper (JSONL with detailed extraction)
```bash
# Discover and scrape multiple advisories
python scrape_cisa_advisory.py --max-advisories 50 --output data/advisories.jsonl

# Scrape a specific advisory
python scrape_cisa_advisory.py --url "https://www.cisa.gov/news-events/alerts/2026/02/03/cisa-adds-four-known-exploited-vulnerabilities-catalog" --output data/single.jsonl

# With validation and custom delay
python scrape_cisa_advisory.py --max-advisories 20 --delay 1.5 --validate --output data/validated.jsonl
```

### Quotes scraper
```bash
python scraper.py --source quotes --max-pages 10 --output data/quotes.csv
```

Adjust politeness: add `--delay 1.0` (seconds between requests).

## Outputs

### Basic scraper (scraper.py)
- CISA CSV columns: `title,date,summary,url`
- Quotes CSV columns: `quote,author,tags,author_about` (sample: data/sample_quotes.csv)

### Enhanced CISA scraper (scrape_cisa_advisory.py)
JSONL format with one advisory per line, containing:
- `source_url`: Advisory URL
- `fetched_at`: ISO timestamp of fetch
- `content_hash`: SHA-256 of raw HTML for deduplication
- `advisory_type`: ALERT, ADVISORY, ICS ADVISORY, etc.
- `title`: H1 heading text
- `release_date`: `{original: "...", iso8601: "YYYY-MM-DD"}`
- `cves`: `[{id: "CVE-...", url: "...", description: "..."}]`
- `body_text`: Main advisory content (paragraphs)
- `outbound_links`: `[{text: "...", url: "..."}]` for KEV, BOD, guidance docs

Features:
- **Caching**: Stores compressed HTML in `data/cache/` with ETag support
- **Rate limiting**: Configurable delays, exponential backoff on 429/5xx
- **Deduplication**: By content hash
- **Validation**: Optional `--validate` flag to check for template drift
- **Normalization**: Dates converted to ISO 8601, CVE IDs uppercased

## What gets scraped

### Basic scraper
- CISA: advisory title, published date, short summary text if present, canonical URL.
- Quotes: quote text, author name, tags (comma-separated), author bio URL.

### Enhanced CISA scraper
Phase 1 (Discovery):
- Crawls listing pages at `/news-events/cybersecurity-advisories?page=N`
- Filters URLs matching pattern: `/news-events/(alerts|cybersecurity-advisories|ics-advisories)/YYYY/MM/DD/...`

Phase 2 (Extraction):
- Isolates main content block (skips nav/footer)
- Extracts structured fields: title, type, release date, CVEs with descriptions, body text, relevant outbound links
- Detects template drift (missing H1, release date, etc.)

## Reproducibility notes
- Uses only `requests`, `beautifulsoup4`, and `lxml` (see requirements.txt).
- Sets a custom User-Agent and supports a configurable delay.
- If either site changes HTML, adjust the CSS selectors in `parse_quotes`, `parse_cisa_list`, or `CISAAdvisoryScraper`.
- Cached data stored in `data/cache/` with metadata for conditional requests.

## Ethics and politeness
- Follows CISA's standard politeness practices (rate limiting, user-agent, caching).
- Keep `--delay` at or above 0.5s for classroom use (default: 1.0s for enhanced scraper).
- Avoid parallel requests; scripts are single-threaded by design.
- Uses conditional requests (ETag/If-Modified-Since) to minimize server load.
- If you only need KEV entries, prefer the official [KEV CSV/JSON](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) instead of scraping.

## Documentation deliverable
- Export this README to PDF (Print/Save as PDF) and include:
  - Screenshot of the CISA advisories listing page (or the quotes page if using that source).
  - Screenshot of your terminal after running the scraper or of the generated CSV/JSONL opened in a viewer.
  - Brief statement of why you chose the dataset and how to run the commands above.
- Note any GenAI assistance: this code and README were drafted with GitHub Copilot and reviewed manually.

## Example validation
To test the enhanced scraper on the reference page:
```bash
python scrape_cisa_advisory.py \
  --url "https://www.cisa.gov/news-events/alerts/2026/02/03/cisa-adds-four-known-exploited-vulnerabilities-catalog" \
  --validate \
  --output data/test.jsonl
```

Expected extraction:
- Title: "CISA Adds Four Known Exploited Vulnerabilities to Catalog"
- Type: "ALERT"
- CVEs: CVE-2019-19006, CVE-2021-39935, CVE-2025-40551, CVE-2025-64328
- Release date normalized to ISO 8601

