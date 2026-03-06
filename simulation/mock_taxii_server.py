"""
Minimal Flask-based TAXII 2.1 mock server.
Serves the seeded STIX bundle from a single collection.

Endpoints:
  GET /taxii/                                         → Discovery
  GET /taxii/api-root/                                → API Root info
  GET /taxii/api-root/collections/                    → Collection list
  GET /taxii/api-root/collections/{id}/objects/       → STIX objects
"""

from flask import Flask, jsonify, request
import json
import os

app = Flask(__name__)
COLLECTION_ID = "wazuh-ti-test-collection-001"

# Load STIX bundle from file
BUNDLE_PATH = os.environ.get("STIX_BUNDLE_PATH", "/app/stix_bundle.json")
try:
    with open(BUNDLE_PATH, "r") as f:
        bundle = json.load(f)
    print(f"[+] Loaded STIX bundle with {len(bundle.get('objects', []))} objects")
except FileNotFoundError:
    print(f"[!] Bundle not found at {BUNDLE_PATH} — serving empty bundle")
    bundle = {"type": "bundle", "id": "bundle--empty", "objects": []}

TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"


@app.route("/taxii/")
def discovery():
    """TAXII Discovery endpoint."""
    return jsonify({
        "title": "Wazuh-TI Mock TAXII Server",
        "description": "A TAXII 2.1 mock server for Wazuh-TI testing",
        "default": "http://taxii-mock:9000/taxii/api-root/",
        "api_roots": ["http://taxii-mock:9000/taxii/api-root/"],
    }), 200, {"Content-Type": TAXII_CONTENT_TYPE}


@app.route("/taxii/api-root/")
def api_root():
    """API Root information endpoint."""
    return jsonify({
        "title": "Wazuh-TI Test API Root",
        "description": "API Root for Wazuh-TI test indicators",
        "versions": ["taxii-2.1"],
        "max_content_length": 104857600,
    }), 200, {"Content-Type": TAXII_CONTENT_TYPE}


@app.route("/taxii/api-root/collections/")
def collections():
    """List available collections."""
    return jsonify({
        "collections": [{
            "id": COLLECTION_ID,
            "title": "Wazuh-TI Test Indicators",
            "description": "Test collection containing seeded malicious indicators",
            "can_read": True,
            "can_write": False,
            "media_types": ["application/stix+json;version=2.1"],
        }]
    }), 200, {"Content-Type": TAXII_CONTENT_TYPE}


@app.route(f"/taxii/api-root/collections/{COLLECTION_ID}/")
def collection_info():
    """Individual collection info."""
    return jsonify({
        "id": COLLECTION_ID,
        "title": "Wazuh-TI Test Indicators",
        "can_read": True,
        "can_write": False,
    }), 200, {"Content-Type": TAXII_CONTENT_TYPE}


@app.route(f"/taxii/api-root/collections/{COLLECTION_ID}/objects/")
def get_objects():
    """Serve STIX objects from the loaded bundle."""
    return jsonify({
        "objects": bundle.get("objects", []),
        "more": False,
    }), 200, {"Content-Type": "application/stix+json;version=2.1"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 9000))
    print(f"[*] Mock TAXII server starting on port {port}")
    app.run(host="0.0.0.0", port=port)
