import gzip, hashlib
from pathlib import Path
from bs4 import BeautifulSoup

url = "https://www.cisa.gov/news-events/cybersecurity-advisories?page=0"
url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
cache_file = Path("data/cache") / f"{url_hash}.html.gz"
print("cache file:", cache_file, "| exists:", cache_file.exists())

with gzip.open(cache_file, "rt", encoding="utf-8") as f:
    html = f.read()

soup = BeautifulSoup(html, "lxml")

# Test the new selector
result = soup.select_one("li.c-pager__item a[href='?page=1']")
print("c-pager next link found:", result is not None)
if result:
    print(str(result)[:120])

# How many total items per page?
cards = soup.select("div.views-row, article")
print(f"Cards on page 0: {len(cards)}")
