"""Quick data quality check for scraped advisories."""
import json

print('Data Quality Summary')
print('=' * 60)
with open('data/advisories_sample.jsonl', 'r') as f:
    advisories = [json.loads(line) for line in f]

print(f'Total advisories: {len(advisories)}')
print(f'Total CVEs: {sum(len(a.get("cves", [])) for a in advisories)}')
print(f'Advisory types: {set(a.get("advisory_type") for a in advisories)}')

dates = [a.get("release_date", {}).get("iso8601", "") for a in advisories if a.get("release_date", {}).get("iso8601")]
if dates:
    print(f'Date range: {min(dates)} to {max(dates)}')

print(f'Avg body length: {sum(len(a.get("body_text", "")) for a in advisories) // len(advisories)} chars')
print(f'Avg links per advisory: {sum(len(a.get("outbound_links", [])) for a in advisories) / len(advisories):.1f}')
print('\nSample CVEs extracted:')
for adv in advisories[:2]:
    for cve in adv.get('cves', [])[:2]:
        print(f'  {cve["id"]}: {cve.get("description", "N/A")[:60]}...')
