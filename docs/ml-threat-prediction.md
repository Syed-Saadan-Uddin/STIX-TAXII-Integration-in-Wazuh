# ML Threat Prediction Module

## Overview

The `Threat Prediction` module extends the existing Wazuh-TI platform from IOC enrichment into alert-level incident prediction.

It ingests Wazuh alerts, engineers security context features, enriches them with live threat-intelligence providers, and produces:

- `Threat Priority`: `Low`, `Medium`, `High`, `Critical`
- `Risk Score`: `0-100`
- `Materialization Probability`: probability the alert becomes a real incident
- `Confidence Score`
- `Recommended Action`: `Ignore`, `Monitor`, `Investigate`, `Isolate`
- `Predicted Next Attack Stage`: MITRE ATT&CK next-stage estimate

## Architecture

Backend components:

- `app/api/routes/ml.py`
  - ML prediction, ingest, overview, top-threats, retrain, and host-profile APIs
- `app/core/ml/features.py`
  - Wazuh alert normalization and feature engineering
- `app/core/ml/reputation.py`
  - Live enrichment from OTX, ThreatFox, URLhaus, AbuseIPDB, and local IOC matches
- `app/core/ml/model.py`
  - Synthetic-data-trained RandomForest wrapper with heuristic fallback
- `app/core/ml/service.py`
  - End-to-end orchestration for prediction, storage, retraining, and demo seeding
- `app/db/models.py`
  - `host_asset_profiles`, `wazuh_alerts`, and `threat_predictions`
- `app/db/ml_crud.py`
  - ML-specific persistence and aggregation helpers

Frontend components:

- `frontend/src/pages/ThreatPrediction.jsx`
  - Separate dashboard page for prediction overview, workbench, and recent alerts
- `frontend/src/api/client.js`
  - ML API bindings

## Data Flow

1. A Wazuh alert is sent to `POST /api/v1/ml/alerts/ingest`.
2. The backend normalizes the alert into a consistent schema.
3. Feature engineering derives severity, frequency, history, MITRE, time, and host-context signals.
4. The threat-intel enricher checks:
   - local active indicators already stored in the platform
   - OTX
   - ThreatFox
   - URLhaus
   - AbuseIPDB
5. The model predicts incident materialization probability.
6. The service maps model output into risk score, priority, recommended action, and next ATT&CK stage.
7. The alert and its prediction are stored in SQLite and become visible on the dashboard.

## Feature Engineering

Current feature set includes:

- Rule level / severity
- Alert frequency in the last 1 hour and 24 hours
- Same-rule recurrence
- Same-host recurrence
- Same-process recurrence
- Historical repeated behavior over 7 days
- Source IP reputation
- Threat intel matches
- Local IOC match count
- MITRE tactic risk weighting
- Host criticality
- Internet-exposed / crown-jewel flags
- Login failure signal
- Suspicious process signal
- Off-hours activity
- Weekend activity

## Model Choice

The implementation uses a hybrid design:

- Preferred path: `RandomForestClassifier` trained on synthetic incident data shaped around SOC risk heuristics
- Fallback path: deterministic heuristic scorer when `scikit-learn` is unavailable

Why Random Forest first:

- fast to train
- stable for tabular engineered features
- simple to retrain
- appropriate for an MVP before a real labeled incident dataset is available

## How Predictions Are Generated

The model produces a binary incident-materialization probability.

That probability is then combined with security weighting logic to produce:

- `risk_score`
- `threat_priority`
- `confidence_score`
- `recommended_action`
- `predicted_next_attack_stage`

`top_factors` are generated from the strongest weighted signals for explainability on the dashboard.

## API Endpoints

- `GET /api/v1/ml/status`
- `GET /api/v1/ml/overview`
- `GET /api/v1/ml/predictions`
- `GET /api/v1/ml/top-threats`
- `POST /api/v1/ml/predict`
- `POST /api/v1/ml/alerts/ingest`
- `POST /api/v1/ml/alerts/ingest/batch`
- `POST /api/v1/ml/retrain`
- `POST /api/v1/ml/demo/seed`
- `GET /api/v1/ml/host-profiles`
- `POST /api/v1/ml/host-profiles`
- `GET /api/v1/ml/wazuh/status`
- `POST /api/v1/ml/wazuh/install`

## Direct Wazuh Delivery

The project now includes a direct Wazuh manager bridge so alerts can be forwarded automatically into the ML pipeline.

Files involved:

- `wazuh-integrations/custom-wazuh-ti-ml`
  - custom Wazuh integration script
- `app/core/wazuh_ml_integration.py`
  - installs the script into `/var/ossec/integrations/` and patches `ossec.conf`
- `scripts/install_wazuh_ml_integration.py`
  - manual installer helper
- `POST /api/v1/ml/wazuh/install`
  - installs the bridge from the backend

Default target endpoint:

- `http://wazuh-ti:8000/api/v1/ml/alerts/ingest`

What the installer does:

1. copies `custom-wazuh-ti-ml` into the shared Wazuh integrations volume
2. sets executable permissions and aligns ownership with the Wazuh integrations directory
3. injects a custom `<integration>` block into `/var/ossec/etc/ossec.conf`
4. points Wazuh at the ML ingest API

After installation:

1. restart the Wazuh manager
2. generate or wait for new alerts
3. confirm new entries appear on the Threat Prediction page

Docker note:

The app container now mounts the shared `single-node_wazuh_integrations` volume so it can install the custom integration script directly.

If your Wazuh single-node deployment bootstraps the manager config from `wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf`, update that source file as well. Otherwise the manager startup sequence can overwrite the live `ossec.conf` changes on the next container restart.

## Continuous Test Alerts

The compose stack now includes a dedicated Wazuh test agent and a log generator that emits realistic SSH authentication failures every 30 seconds by default.

Services:

- `wazuh-test-agent`
  - custom container that installs the exact Wazuh agent package version needed by the current manager
  - monitors `/var/log/wazuh-test/auth.log`
- `wazuh-test-alert-generator`
  - appends synthetic SSH failure events to the shared log file on a timer

Why this is a real Wazuh path:

1. the generator writes syslog-style lines into `auth.log`
2. the Wazuh agent collects that file with `<localfile>`
3. the Wazuh manager applies its normal SSH decoders and rules
4. the custom ML bridge receives the resulting alert from Wazuh

Files involved:

- `simulation/wazuh-agent/Dockerfile`
- `simulation/wazuh-agent/entrypoint.sh`
- `simulation/wazuh-agent/ossec.conf`
- `simulation/wazuh-agent/generate_test_alerts.py`
- `docker-compose.yml`

Environment knobs:

- `WAZUH_MANAGER_SERVER`
  - defaults to `wazuh.manager`
- `WAZUH_TEST_AGENT_VERSION`
  - defaults to `4.8.0-1`
  - keep this at the same version as your Wazuh manager package
- `WAZUH_TEST_AGENT_NAME`
  - defaults to `wazuh-test-agent`
- `WAZUH_TEST_ALERT_INTERVAL_SECONDS`
  - defaults to `30`

To start it:

1. run `docker compose up -d wazuh-test-agent wazuh-test-alert-generator`
2. wait for the agent to enroll and connect
3. open the Wazuh dashboard or the Threat Prediction page to confirm new alerts arrive continuously

If your manager uses a different hostname on the shared Docker network, set `WAZUH_MANAGER_SERVER` to that hostname before starting the agent.

## Environment Variables

Configured keys:

- `OTX_API_KEY`
- `ABUSE_CH_API_KEY`
- `ABUSEIPDB_API_KEY`

Other important settings:

- `ML_MODEL_PATH`
- `ML_LIVE_ENRICHMENT_ENABLED`

## Host Criticality

Host criticality is stored in `host_asset_profiles`.

Recommended values:

- `1`: low-value workstation
- `2`: normal user endpoint
- `3`: standard server
- `4`: sensitive application server
- `5`: crown-jewel or business-critical system

Use `POST /api/v1/ml/host-profiles` to tune host context for better scoring.

## Retraining Later

Current retraining:

- uses synthetic data to rebuild the Random Forest artifact at the configured model path

Recommended production evolution:

1. label historical alerts as `incident` or `non-incident`
2. store analyst verdicts and confirmed outcomes in `wazuh_alerts`
3. export a supervised training dataset from the stored feature snapshots
4. retrain on real SOC outcomes instead of synthetic labels
5. evaluate precision/recall by priority band
6. replace or benchmark against `XGBoost` or `LightGBM`

## Recommended Next Step

Wire Wazuh custom integration or webhook delivery to `POST /api/v1/ml/alerts/ingest` so every alert entering the platform is automatically enriched and stored.
