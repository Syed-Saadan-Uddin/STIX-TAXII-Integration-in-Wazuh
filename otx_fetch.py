import requests
import json

API_KEY = "e6f502324514f99a97d8404a15841428f18688ff47194683514ad0b00abecd88"
BASE_URL = "https://otx.alienvault.com/api/v1"
headers = {"X-OTX-API-KEY": API_KEY}

ips = []
domains = []
hashes = []

print("Fetching from OTX REST API...")

# Get subscribed pulses (page 1 only, fast)
resp = requests.get(f"{BASE_URL}/pulses/subscribed?limit=10&page=1", 
                    headers=headers, timeout=30)
data = resp.json()
pulses = data.get('results', [])
print(f"Got {len(pulses)} pulses")

for i, pulse in enumerate(pulses):
    name = pulse.get('name', 'unknown')[:40]
    indicators = pulse.get('indicators', [])
    print(f"  [{i+1}/{len(pulses)}] {name} — {len(indicators)} indicators")
    
    for ind in indicators:
        t = ind.get('type', '')
        v = ind.get('indicator', '')
        if t == 'IPv4':
            ips.append(v)
        elif t == 'domain':
            domains.append(v)
        elif t in ['FileHash-SHA256', 'FileHash-MD5']:
            hashes.append(v)

print(f"\nTotal: {len(ips)} IPs, {len(domains)} domains, {len(hashes)} hashes")

seeds = {
    "malicious_ips": list(set(ips))[:20],
    "malicious_domains": list(set(domains))[:10],
    "malicious_hashes": list(set(hashes))[:5],
    "benign_ips": ["192.168.1.10", "192.168.1.20", "10.0.0.5", "8.8.8.8", "1.1.1.1"]
}

with open('simulation/ioc_seeds.json', 'w') as f:
    json.dump(seeds, f, indent=2)

print("\nDone! ioc_seeds.json updated with real OTX data!")
print(f"Sample IPs: {seeds['malicious_ips'][:3]}")
print(f"Sample domains: {seeds['malicious_domains'][:3]}")
