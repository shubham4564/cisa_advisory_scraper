"""Enhanced CISA cybersecurity advisory scraper with detailed field extraction.

This scraper implements a two-phase approach:
1) Discover advisory URLs from listing pages
2) Fetch and parse individual advisories for structured data extraction

Extracts: title, advisory type, release date, CVEs with descriptions, body text,
and stores in CSV format with flattened structure.

Usage:
    python scrape_cisa_advisory.py --max-advisories 50 --output data/advisories.csv
    python scrape_cisa_advisory.py --url https://www.cisa.gov/news-events/alerts/2026/02/03/... --output single.csv

Dependencies:
    pip install requests beautifulsoup4 lxml
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, Tag


# Configuration
BASE_URL_CISA = "https://www.cisa.gov"
ADVISORIES_HUB = f"{BASE_URL_CISA}/news-events/cybersecurity-advisories"
USER_AGENT = "NLP-CISA-Scraper/2.0 (educational use; respectful scraping)"

# URL allowlist pattern for advisories
ADVISORY_URL_PATTERN = re.compile(
    r"^https://www\.cisa\.gov/news-events/(alerts|cybersecurity-advisories|ics-advisories)/\d{4}/\d{2}/\d{2}/.+"
)

# CVE pattern
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

# CVE.org (MITRE) REST API
CVE_ORG_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"


class AdvisoryCache:
    """Simple file-based cache for HTML pages with ETag support."""

    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = cache_dir / "metadata.json"
        self.metadata = self._load_metadata()

    def _load_metadata(self) -> Dict[str, Any]:
        """Load cache metadata (ETags, last-modified)."""
        if self.metadata_file.exists():
            with open(self.metadata_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _save_metadata(self) -> None:
        """Persist cache metadata."""
        with open(self.metadata_file, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)

    def _get_cache_path(self, url: str) -> Path:
        """Generate cache file path from URL hash."""
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        return self.cache_dir / f"{url_hash}.html.gz"

    def get(self, url: str) -> Optional[tuple[str, Dict[str, str]]]:
        """Retrieve cached HTML and headers if available."""
        cache_path = self._get_cache_path(url)
        if not cache_path.exists():
            return None

        with gzip.open(cache_path, "rt", encoding="utf-8") as f:
            html = f.read()

        headers = self.metadata.get(url, {})
        return html, headers

    def set(self, url: str, html: str, headers: Dict[str, str]) -> None:
        """Store HTML and headers in cache."""
        cache_path = self._get_cache_path(url)
        with gzip.open(cache_path, "wt", encoding="utf-8") as f:
            f.write(html)

        # Store ETag and Last-Modified for conditional requests
        self.metadata[url] = {
            "etag": headers.get("ETag", ""),
            "last_modified": headers.get("Last-Modified", ""),
            "cached_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_metadata()


class CISAAdvisoryScraper:
    """Scrapes CISA cybersecurity advisories with detailed field extraction."""

    def __init__(
        self,
        cache_dir: Path = Path("data/cache"),
        delay: float = 1.0,
        max_retries: int = 3,
    ):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.cache = AdvisoryCache(cache_dir)
        self.delay = delay
        self.max_retries = max_retries
        self.discovered_urls: Set[str] = set()
        self._last_fetch_was_cached = False  # set by _fetch_with_cache

    def _fetch_with_cache(self, url: str) -> Optional[str]:
        """Fetch URL with caching. Returns cached content instantly if available."""
        cached = self.cache.get(url)

        # Return from cache immediately — no network roundtrip needed
        if cached:
            self._last_fetch_was_cached = True
            return cached[0]

        self._last_fetch_was_cached = False
        for attempt in range(self.max_retries):
            try:
                response = self.session.get(url, timeout=15)

                # 404 Not Found
                if response.status_code == 404:
                    return None

                # Rate limiting - back off exponentially
                if response.status_code == 429:
                    wait_time = (2 ** attempt) * self.delay
                    time.sleep(wait_time)
                    continue

                # Server errors - retry
                if 500 <= response.status_code < 600:
                    if attempt < self.max_retries - 1:
                        time.sleep(self.delay * (attempt + 1))
                        continue

                response.raise_for_status()

                # Cache successful response
                self.cache.set(url, response.text, dict(response.headers))
                return response.text

            except requests.RequestException as e:
                if attempt == self.max_retries - 1:
                    print(f"Failed to fetch {url}: {e}")
                    return None
                time.sleep(self.delay * (attempt + 1))

        return None

    def discover_advisory_urls(self, max_pages: Optional[int] = None) -> List[str]:
        """Discover advisory URLs from listing pages."""
        urls = []
        page_num = 0

        while True:
            list_url = f"{ADVISORIES_HUB}?page={page_num}"
            html = self._fetch_with_cache(list_url)

            if html is None:
                break

            soup = BeautifulSoup(html, "lxml")

            # Extract advisory links from cards
            cards = soup.select("div.views-row, article")
            found_new = False

            for card in cards:
                link = card.select_one("a[href]")
                if link and link.get("href"):
                    href = link.get("href")
                    full_url = urljoin(BASE_URL_CISA, href)

                    # Apply allowlist filter
                    if ADVISORY_URL_PATTERN.match(full_url):
                        if full_url not in self.discovered_urls:
                            self.discovered_urls.add(full_url)
                            urls.append(full_url)
                            found_new = True

            if not found_new:
                break

            # Check for next page (CISA uses numeric c-pager__item links)
            has_next = soup.select_one(
                f"li.c-pager__item a[href='?page={page_num + 1}'], "
                f"li.pager__item--next a, li.next a"
            ) is not None
            if not has_next:
                break

            if max_pages is not None and page_num + 1 >= max_pages:
                break

            page_num += 1
            # Skip delay for cached listing pages
            if not self._last_fetch_was_cached:
                time.sleep(self.delay)

        return urls

    def _extract_main_content(self, soup: BeautifulSoup) -> Optional[Tag]:
        """Isolate main content block, stripping navigation/footer."""
        # Try to find main content container
        main = soup.select_one("main, #main, article, div.main-content")
        return main if main else soup

    def _normalize_date(self, date_str: str) -> Dict[str, str]:
        """Normalize date to ISO 8601, keeping original."""
        normalized = {"original": date_str.strip(), "iso8601": ""}

        # Common CISA date formats: "February 03, 2026", "02/03/2026"
        for fmt in ["%B %d, %Y", "%m/%d/%Y", "%Y-%m-%d"]:
            try:
                dt = datetime.strptime(date_str.strip(), fmt)
                normalized["iso8601"] = dt.strftime("%Y-%m-%d")
                break
            except ValueError:
                continue

        return normalized

    def _extract_cves(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Extract CVE IDs, URLs, and descriptions from advisory."""
        cves = []
        seen_cves = set()

        # Find CVE bullets (typically in <ul> or <li> with CVE links)
        cve_links = soup.select("a[href*='cve.org'], a[href*='CVE-']")

        for link in cve_links:
            cve_id_match = CVE_PATTERN.search(link.get_text())
            if not cve_id_match:
                # Try finding CVE in href
                href = link.get("href", "")
                cve_id_match = CVE_PATTERN.search(href)

            if cve_id_match:
                cve_id = cve_id_match.group(0).upper()

                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                # Get parent list item for description
                parent_li = link.find_parent("li")
                description = ""
                if parent_li:
                    # Remove the link text and get remaining text
                    temp_li = BeautifulSoup(str(parent_li), "lxml")
                    for a in temp_li.find_all("a"):
                        a.decompose()
                    description = temp_li.get_text(strip=True)
                    # Remove CVE ID from description
                    description = re.sub(rf"{cve_id}\s*[-–—:]?\s*", "", description)

                cves.append(
                    {
                        "id": cve_id,
                        "url": link.get("href", ""),
                        "description": description.strip(),
                    }
                )

        # Fallback: search for CVEs in text without links
        if not cves:
            all_text = soup.get_text()
            for match in CVE_PATTERN.finditer(all_text):
                cve_id = match.group(0).upper()
                if cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    cves.append(
                        {
                            "id": cve_id,
                            "url": f"https://www.cve.org/CVERecord?id={cve_id}",
                            "description": "",
                        }
                    )

        return cves

    def _fetch_cve_description(self, cve_id: str) -> str:
        """Fetch the English description for a CVE from the MITRE CVE.org API."""
        url = CVE_ORG_API_URL.format(cve_id=cve_id)
        try:
            cached = self.cache.get(url)
            if cached:
                self._last_fetch_was_cached = True
                data = json.loads(cached[0])
            else:
                self._last_fetch_was_cached = False
                response = self.session.get(url, timeout=15)
                if response.status_code != 200:
                    return ""
                self.cache.set(url, response.text, dict(response.headers))
                data = response.json()

            descriptions = (
                data.get("containers", {})
                    .get("cna", {})
                    .get("descriptions", [])
            )
            # Prefer English; fall back to first available
            for desc in descriptions:
                if desc.get("lang", "").startswith("en"):
                    return desc.get("value", "").strip()
            if descriptions:
                return descriptions[0].get("value", "").strip()
        except Exception as exc:
            print(f"  Warning: could not fetch CVE.org description for {cve_id}: {exc}")
        return ""

    def _enrich_cves_with_cveorg(self, cves: List[Dict[str, str]]) -> None:
        """Add 'cveorg_description' key to each CVE dict by querying CVE.org."""
        for cve in cves:
            cve_id = cve.get("id", "")
            if not cve_id:
                cve["cveorg_description"] = ""
                continue
            cve["cveorg_description"] = self._fetch_cve_description(cve_id)
            # Only delay when we actually hit the network (not for cached CVEs)
            if not self._last_fetch_was_cached:
                time.sleep(0.2)

    def _extract_outbound_links(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Extract relevant outbound links (KEV, BOD, criteria pages)."""
        links = []
        seen_urls = set()

        # Look for links in main content
        for link in soup.select("a[href]"):
            href = link.get("href")
            text = link.get_text(strip=True)

            if not href or not text:
                continue

            full_url = urljoin(BASE_URL_CISA, href)

            # Filter for relevant links
            if any(
                keyword in full_url.lower()
                for keyword in ["kev", "bod", "binding", "criteria", "guidance", "cve.org"]
            ):
                if full_url not in seen_urls:
                    seen_urls.add(full_url)
                    links.append({"text": text, "url": full_url})

        return links

    def _extract_body_text(self, soup: BeautifulSoup, cves: List[Dict]) -> str:
        """Extract main body text, excluding CVE bullets and boilerplate."""
        # Clone soup to avoid modifying original
        soup_copy = BeautifulSoup(str(soup), "lxml")

        # Remove navigation, footer, and common boilerplate
        for selector in [
            "nav",
            "footer",
            ".breadcrumb",
            ".social-links",
            ".return-to-top",
            "script",
            "style",
            "[class*='survey']",
            "[class*='feedback']",
        ]:
            for element in soup_copy.select(selector):
                element.decompose()

        # Remove "This product is provided subject to" disclaimer
        for p in soup_copy.find_all("p"):
            if "this product is provided subject to" in p.get_text().lower():
                p.decompose()

        # Get paragraphs
        paragraphs = []
        for p in soup_copy.find_all("p"):
            text = p.get_text(strip=True)
            # Skip if it's just a CVE ID
            if text and not CVE_PATTERN.fullmatch(text):
                paragraphs.append(text)

        return "\n\n".join(paragraphs)

    def parse_advisory(self, html: str, url: str) -> Optional[Dict[str, Any]]:
        """Parse individual advisory page and extract structured fields."""
        soup = BeautifulSoup(html, "lxml")
        main = self._extract_main_content(soup)

        if main is None:
            print(f"Warning: Could not isolate main content for {url}")
            return None

        # Extract fields with template drift detection
        advisory = {
            "source_url": url,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "content_hash": hashlib.sha256(html.encode()).hexdigest(),
        }

        # Advisory type (ALERT, ADVISORY, ICS ADVISORY, etc.)
        # Look for standalone type labels before the H1
        type_elem = main.select_one(".alert-type, .advisory-type, [class*='type']")
        if type_elem:
            type_text = type_elem.get_text(strip=True).upper()
            # Filter out if it contains date text
            if "RELEASE" not in type_text and "DATE" not in type_text and len(type_text) < 30:
                advisory["advisory_type"] = type_text
            else:
                type_elem = None
        
        if not type_elem:
            # Infer from URL
            if "/alerts/" in url:
                advisory["advisory_type"] = "ALERT"
            elif "/ics-advisories/" in url:
                advisory["advisory_type"] = "ICS ADVISORY"
            else:
                advisory["advisory_type"] = "ADVISORY"

        # Title (H1)
        h1 = main.select_one("h1")
        if h1:
            advisory["title"] = h1.get_text(strip=True)
        else:
            print(f"Warning: No H1 title found for {url} - possible template drift")
            advisory["title"] = ""

        # Release Date - multiple extraction strategies
        release_date_text = ""
        
        # Strategy 1: Look for explicit release date label
        for selector in [
            "div:contains('Release Date')",
            "span:contains('Release Date')",
            "div.date",
            "span.date",
            "time"
        ]:
            date_elem = None
            if selector.startswith(("div:", "span:")):
                # Text search
                pattern = selector.split("'")[1]
                date_elem = main.find(string=re.compile(pattern, re.IGNORECASE))
                if date_elem:
                    parent = date_elem.find_parent()
                    if parent:
                        text = parent.get_text(strip=True)
                        # Extract date after the label
                        date_match = re.search(
                            r"(?:Release Date|Published|Date)\s*:?\s*([A-Za-z]+\s+\d{1,2},?\s+\d{4}|\d{1,2}/\d{1,2}/\d{4})",
                            text,
                            re.IGNORECASE,
                        )
                        if date_match:
                            release_date_text = date_match.group(1).strip()
                            break
            else:
                # CSS selector
                date_elem = main.select_one(selector)
                if date_elem:
                    release_date_text = date_elem.get_text(strip=True)
                    # Clean up if it has label prefix
                    release_date_text = re.sub(
                        r"^(?:Release Date|Published|Date)\s*:?\s*",
                        "",
                        release_date_text,
                        flags=re.IGNORECASE
                    )
                    if release_date_text:
                        break
        
        # Strategy 2: Extract from meta tags
        if not release_date_text:
            meta_date = soup.select_one(
                "meta[property='article:published_time'], meta[name='date'], meta[name='publish-date']"
            )
            if meta_date and meta_date.get("content"):
                release_date_text = meta_date.get("content")
        
        # Strategy 3: Look for standalone date in common formats near the top
        if not release_date_text:
            # Find text nodes that look like dates in the first part of main content
            text_content = main.get_text()
            date_match = re.search(
                r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b",
                text_content[:1000]  # Search first 1000 chars
            )
            if date_match:
                release_date_text = date_match.group(0)

        if not release_date_text:
            print(f"Warning: No release date found for {url} - possible template drift")

        advisory["release_date"] = self._normalize_date(release_date_text) if release_date_text else {"original": "", "iso8601": ""}

        # CVEs with descriptions
        advisory["cves"] = self._extract_cves(main)

        # Enrich CVEs with descriptions from CVE.org
        if advisory["cves"]:
            print(f"  Fetching CVE.org descriptions for {len(advisory['cves'])} CVE(s)...")
            self._enrich_cves_with_cveorg(advisory["cves"])

        # Body text
        advisory["body_text"] = self._extract_body_text(main, advisory["cves"])

        # Outbound links
        advisory["outbound_links"] = self._extract_outbound_links(main)

        return advisory

    def scrape_advisory(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch and parse a single advisory."""
        html = self._fetch_with_cache(url)
        if html is None:
            return None

        # Only sleep when we actually hit the network
        if not self._last_fetch_was_cached:
            time.sleep(self.delay)
        return self.parse_advisory(html, url)

    def scrape_advisories(
        self, urls: Optional[List[str]] = None, max_advisories: Optional[int] = None,
        max_pages: Optional[int] = None,
        output_path: Optional[Path] = None,
    ) -> List[Dict[str, Any]]:
        """Scrape multiple advisories with deduplication.
        
        If output_path is given, each advisory is written to CSV immediately
        after scraping so progress is never lost on interruption.
        """
        if urls is None:
            # Discover URLs
            print("Discovering advisory URLs...")
            urls = self.discover_advisory_urls(max_pages=max_pages)
            print(f"Discovered {len(urls)} advisory URLs")

        if max_advisories:
            urls = urls[:max_advisories]

        # Load already-scraped URLs from existing CSV to allow resume
        scraped_urls: Set[str] = set()
        if output_path and output_path.exists() and output_path.stat().st_size > 0:
            with open(output_path, newline="", encoding="utf-8") as f:
                scraped_urls = {row["url"] for row in csv.DictReader(f)}
            if scraped_urls:
                print(f"Resuming: {len(scraped_urls)} already scraped, skipping them.")

        advisories = []
        seen_hashes: Set[str] = set()

        for i, url in enumerate(urls, 1):
            if url in scraped_urls:
                continue  # already in CSV from a previous run

            print(f"Scraping {i}/{len(urls)}: {url}")
            advisory = self.scrape_advisory(url)

            if advisory:
                # Deduplicate by content hash
                content_hash = advisory["content_hash"]
                if content_hash not in seen_hashes:
                    seen_hashes.add(content_hash)
                    advisories.append(advisory)
                    # Write immediately so progress survives interruption
                    if output_path:
                        append_csv_row(advisory, output_path)
                else:
                    print(f"  Skipped duplicate content")

        return advisories


# Column order used by every CSV writer
_CSV_FIELDS = [
    "url", "title", "advisory_type", "release_date",
    "cve_ids", "cve_count", "cve_descriptions", "cve_descriptions_cveorg",
    "body_text", "fetched_at",
]


def _advisory_to_row(adv: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten one advisory dict into a CSV-ready dict."""
    cve_ids = ", ".join(cve["id"] for cve in adv.get("cves", []))
    cve_descriptions = " | ".join(
        f"{cve['id']}: {cve.get('description', '')}"
        for cve in adv.get("cves", [])
    )
    cve_descriptions_cveorg = " | ".join(
        f"{cve['id']}: {cve.get('cveorg_description', '')}"
        for cve in adv.get("cves", [])
    )
    return {
        "url": adv.get("source_url", ""),
        "title": adv.get("title", ""),
        "advisory_type": adv.get("advisory_type", ""),
        "release_date": adv.get("release_date", {}).get("iso8601", ""),
        "cve_ids": cve_ids,
        "cve_count": len(adv.get("cves", [])),
        "cve_descriptions": cve_descriptions,
        "cve_descriptions_cveorg": cve_descriptions_cveorg,
        "body_text": adv.get("body_text", ""),
        "fetched_at": adv.get("fetched_at", ""),
    }


def append_csv_row(advisory: Dict[str, Any], output_path: Path) -> None:
    """Append a single advisory to the CSV immediately (creates file+header if new)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    is_new = not output_path.exists() or output_path.stat().st_size == 0
    with open(output_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS)
        if is_new:
            writer.writeheader()
        writer.writerow(_advisory_to_row(advisory))


def write_csv(advisories: List[Dict[str, Any]], output_path: Path) -> None:
    """Write all advisories to CSV at once (used for single-URL mode)."""
    if not advisories:
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        writer.writerows(_advisory_to_row(adv) for adv in advisories)


def validate_advisory(advisory: Dict[str, Any]) -> List[str]:
    """Validate extracted fields and return list of issues."""
    issues = []

    if not advisory.get("title"):
        issues.append("Missing title")

    if not advisory.get("release_date", {}).get("original"):
        issues.append("Missing release date")

    if not advisory.get("cves") and "kev" in advisory.get("body_text", "").lower():
        issues.append("Mentions KEV but no CVEs extracted - possible parsing issue")

    return issues


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scrape CISA cybersecurity advisories with detailed field extraction."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/advisories.csv"),
        help="Output CSV file path (default: data/advisories.csv)",
    )
    parser.add_argument(
        "--max-advisories",
        type=int,
        default=None,
        help="Maximum number of advisories to scrape",
    )
    parser.add_argument(
        "--url",
        type=str,
        default=None,
        help="Scrape a single advisory URL instead of discovering",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=None,
        help="Maximum listing pages to crawl when discovering URLs (default: all)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay between requests in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("data/cache"),
        help="Cache directory for HTML pages (default: data/cache)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Run validation checks on extracted data",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    scraper = CISAAdvisoryScraper(
        cache_dir=args.cache_dir,
        delay=args.delay,
    )

    if args.url:
        # Scrape single URL
        print(f"Scraping single advisory: {args.url}")
        advisory = scraper.scrape_advisory(args.url)
        advisories = [advisory] if advisory else []
    else:
        # Discover and scrape multiple — writes each row immediately
        advisories = scraper.scrape_advisories(
            max_advisories=args.max_advisories,
            max_pages=args.max_pages,
            output_path=args.output,
        )

    if not advisories and not (args.output.exists() and args.output.stat().st_size > 0):
        print("No advisories scraped.")
        return

    # Validation
    if args.validate:
        print("\nValidating extracted data...")
        for advisory in advisories:
            issues = validate_advisory(advisory)
            if issues:
                print(f"  {advisory['source_url']}: {', '.join(issues)}")

    # For single-URL mode, write_csv is still used (batch)
    if args.url:
        write_csv(advisories, args.output)

    # Summary — count from CSV (accurate even after resume)
    total_cves = sum(len(adv.get("cves", [])) for adv in advisories)
    csv_total = sum(1 for _ in open(args.output, encoding="utf-8")) - 1 if args.output.exists() else len(advisories)
    print(f"\nScraped {len(advisories)} new advisories this run ({csv_total} total in CSV) with {total_cves} new CVEs -> {args.output}")

    # Sample output for first advisory
    if advisories:
        print("\nSample (first advisory):")
        sample = advisories[0]
        print(f"  Title: {sample.get('title', 'N/A')}")
        print(f"  Type: {sample.get('advisory_type', 'N/A')}")
        print(
            f"  Date: {sample.get('release_date', {}).get('original', 'N/A')}"
        )
        print(f"  CVEs: {len(sample.get('cves', []))}")
        if sample.get("cves"):
            for cve in sample["cves"][:3]:
                print(f"    - {cve['id']}: {cve.get('description', 'N/A')[:60]}...")


if __name__ == "__main__":
    main()
