# Wazuh-TI Simulation Stack

## Prerequisites
- Docker and Docker Compose
- Python 3.11+ (for running `seed_taxii_server.py` locally)
- Wazuh SIEM stack running via Docker

## Setup Steps

### 1. Generate STIX Bundle
First, generate the STIX bundle that the mock TAXII server will serve:

```bash
python simulation/seed_taxii_server.py
```

This creates `simulation/stix_bundle.json` with all IOCs from `ioc_seeds.json`.

### 2. Start the Simulation Stack
```bash
docker-compose -f simulation/docker-compose.simulation.yml up -d
```

This starts:
- **taxii-mock**: Flask TAXII server at `localhost:9000`
- **wazuh-agent**: Wazuh agent connected to your manager

### 3. Add the Feed in Wazuh-TI
Open the Wazuh-TI GUI at `http://localhost:8000`:
1. Go to **Settings** → Click **Add Feed**
2. Set TAXII URL to `http://taxii-mock:9000/taxii/`
3. Click **Test Connection** to verify
4. Save the feed

### 4. Trigger a Sync
Click **Sync Now** on the Dashboard to ingest indicators from the mock server.

### 5. Inject Simulated Logs
```bash
chmod +x simulation/inject_logs.sh
./simulation/inject_logs.sh
```

This generates 10,000 test log lines (20% malicious) and injects them into the Wazuh agent.

### 6. Verify in Wazuh Dashboard
Open `https://localhost` (Wazuh Dashboard) and check for alerts matching rule IDs 100001 and 100002.

## IOC Seeds
All test IOCs are defined in `ioc_seeds.json` — the same file is used by both the TAXII mock and the log generator to ensure consistent detection results.
