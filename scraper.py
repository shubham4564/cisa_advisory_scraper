"""HTML scrapers for NLP-ready text datasets.

Supports two educational targets (no APIs):
1) quotes.toscrape.com – prose quotes with authors and tags.
2) CISA cybersecurity advisories – titles, dates, summaries, URLs.

Usage examples (Ubuntu or Windows PowerShell):
	python scraper.py --source quotes --max-pages 10 --output data/quotes.csv
	python scraper.py --source cisa   --max-pages 5  --delay 1.0 --output data/cisa_advisories.csv

Dependencies (install once):
	pip install requests beautifulsoup4
"""

from __future__ import annotations

import argparse
import csv
import time
from pathlib import Path
from typing import Dict, List, Tuple

import requests
from bs4 import BeautifulSoup


BASE_URL_QUOTES = "https://quotes.toscrape.com"
BASE_URL_CISA = "https://www.cisa.gov/news-events/cybersecurity-advisories"
USER_AGENT = "NLP-Scraper/1.0 (educational use)"


def fetch_quotes_page(session: requests.Session, page_num: int) -> str | None:
	"""Fetch a single page of quotes; return HTML text or None if not found."""

	url = f"{BASE_URL_QUOTES}/page/{page_num}/"
	response = session.get(url, timeout=10)

	if response.status_code == 404:
		return None

	response.raise_for_status()
	return response.text


def fetch_cisa_page(session: requests.Session, page_num: int) -> str | None:
	"""Fetch a CISA advisories index page by offset (page starts at 0)."""

	url = f"{BASE_URL_CISA}?page={page_num}"
	response = session.get(url, timeout=10)

	if response.status_code == 404:
		return None

	response.raise_for_status()
	return response.text


def parse_quotes(html: str) -> Tuple[List[Dict[str, str]], bool]:
	"""Parse quotes and indicate if a next page exists."""

	soup = BeautifulSoup(html, "html.parser")
	quotes: List[Dict[str, str]] = []

	for block in soup.select("div.quote"):
		quote_text_el = block.select_one("span.text")
		author_el = block.select_one("small.author")
		tag_els = block.select("div.tags a.tag")
		about_el = block.select_one("a[href^='/author/']")

		if not quote_text_el or not author_el:
			continue

		quotes.append(
			{
				"quote": quote_text_el.get_text(strip=True),
				"author": author_el.get_text(strip=True),
				"tags": ", ".join(tag.get_text(strip=True) for tag in tag_els),
				"author_about": f"{BASE_URL_QUOTES}{about_el['href']}" if about_el else "",
			}
		)

	has_next_page = soup.select_one("li.next a") is not None
	return quotes, has_next_page


def parse_cisa_list(html: str) -> Tuple[List[Dict[str, str]], bool]:
	"""Parse CISA advisories list page into rows.

	CISA uses paginated lists at ?page=N. We extract title, date, summary, and URL.
	The markup can change; selectors are kept broad and resilient.
	"""

	soup = BeautifulSoup(html, "html.parser")
	rows: List[Dict[str, str]] = []

	# Common structures: div.views-row or article cards
	cards = soup.select("div.views-row") or soup.select("article")
	for card in cards:
		title_el = card.select_one("a")
		date_el = card.select_one("time") or card.select_one("span.date-display-single")
		summary_el = card.select_one("p") or card.select_one("div.field--name-body")

		if not title_el or not title_el.get("href"):
			continue

		href = title_el.get("href")
		url = href if href.startswith("http") else f"https://www.cisa.gov{href}"
		rows.append(
			{
				"title": title_el.get_text(strip=True),
				"date": date_el.get_text(strip=True) if date_el else "",
				"summary": summary_el.get_text(strip=True) if summary_el else "",
				"url": url,
			}
		)

	# Pagination: look for a "next" link
	has_next_page = soup.select_one("li.pager__item--next a, li.next a") is not None
	return rows, has_next_page


def write_csv(rows: List[Dict[str, str]], output_path: Path) -> None:
	"""Persist scraped rows to CSV with UTF-8 encoding."""

	if not rows:
		raise ValueError("No rows to write; scrape returned empty dataset.")

	output_path.parent.mkdir(parents=True, exist_ok=True)

	fieldnames = list(rows[0].keys())
	with output_path.open("w", newline="", encoding="utf-8") as f:
		writer = csv.DictWriter(f, fieldnames=fieldnames)
		writer.writeheader()
		for row in rows:
			writer.writerow(row)


def scrape_quotes(max_pages: int | None, delay: float, session: requests.Session) -> List[Dict[str, str]]:
	"""Iterate through paginated quote pages until exhausted or limit hit."""

	all_rows: List[Dict[str, str]] = []
	page_num = 1

	while True:
		html = fetch_quotes_page(session, page_num)
		if html is None:
			break

		page_rows, has_next = parse_quotes(html)
		if not page_rows:
			break

		all_rows.extend(page_rows)

		if max_pages is not None and page_num >= max_pages:
			break

		if not has_next:
			break

		page_num += 1
		time.sleep(delay)

	return all_rows


def scrape_cisa(max_pages: int | None, delay: float, session: requests.Session) -> List[Dict[str, str]]:
	"""Iterate through CISA advisories pages until exhausted or limit hit."""

	all_rows: List[Dict[str, str]] = []
	page_num = 0

	while True:
		html = fetch_cisa_page(session, page_num)
		if html is None:
			break

		page_rows, has_next = parse_cisa_list(html)
		if not page_rows:
			break

		all_rows.extend(page_rows)

		if max_pages is not None and page_num + 1 >= max_pages:
			break

		if not has_next:
			break

		page_num += 1
		time.sleep(delay)

	return all_rows


def build_arg_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		description=(
			"Scrape quotes.toscrape.com (quotes) or cisa.gov advisories (cisa) "
			"for NLP-friendly text datasets."
		)
	)
	parser.add_argument(
		"--source",
		choices=["quotes", "cisa"],
		default="cisa",
		help="Target site to scrape (default: cisa)",
	)
	parser.add_argument(
		"--output",
		type=Path,
		default=Path("data/cisa_advisories.csv"),
		help="Destination CSV path (default: data/cisa_advisories.csv)",
	)
	parser.add_argument(
		"--max-pages",
		type=int,
		default=None,
		help="Optional page limit; defaults to all available pages.",
	)
	parser.add_argument(
		"--delay",
		type=float,
		default=0.6,
		help="Delay between requests in seconds to be polite (default: 0.6).",
	)
	return parser


def main() -> None:
	parser = build_arg_parser()
	args = parser.parse_args()

	session = requests.Session()
	session.headers.update({"User-Agent": USER_AGENT})

	if args.source == "quotes":
		rows = scrape_quotes(max_pages=args.max_pages, delay=args.delay, session=session)
	else:
		rows = scrape_cisa(max_pages=args.max_pages, delay=args.delay, session=session)

	write_csv(rows, args.output)

	print(f"Scraped {len(rows)} records from {args.source} -> {args.output}")


if __name__ == "__main__":
	main()
