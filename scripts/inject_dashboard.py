import json
import requests

# Disable SSL warnings for self-signed certs
requests.packages.urllib3.disable_warnings()

OSD_URL = "https://wazuh.dashboard:5601"
AUTH = ("admin", "SecretPassword")
HEADERS = {"osd-xsrf": "true"}

def import_dashboard():
    # 1. Create the visualization (Markdown with Iframe)
    vis_id = "wazuh-ti-iframe"
    iframe_html = "<iframe src=\\\"http://localhost:8000\\\" width=\\\"100%\\\" height=\\\"800px\\\" style=\\\"border:none;\\\"></iframe>"
    
    vis_obj = {
        "attributes": {
            "title": "Wazuh-TI Analysis View",
            "visState": json.dumps({
                "title": "Wazuh-TI Analysis View",
                "type": "markdown",
                "params": {
                    "fontSize": 12,
                    "markdown": iframe_html
                },
                "aggs": []
            }),
            "uiStateJSON": "{}",
            "description": "Embedded Wazuh-TI Dashboard",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            }
        }
    }

    print(f"Creating visualization {vis_id}...")
    resp = requests.post(
        f"{OSD_URL}/api/saved_objects/visualization/{vis_id}?overwrite=true",
        auth=AUTH,
        headers=HEADERS,
        json=vis_obj,
        verify=False
    )
    print(f"Vis Response: {resp.status_code}")

    # 2. Create the dashboard
    dash_id = "wazuh-ti-dashboard"
    dash_obj = {
        "attributes": {
            "title": "Threat Intelligence Dashboard",
            "description": "Integrated Wazuh-TI platform",
            "panelsJSON": json.dumps([
                {
                    "gridData": {"x": 0, "y": 0, "w": 48, "h": 40, "i": "1"},
                    "version": "2.13.0",
                    "panelIndex": "1",
                    "type": "visualization",
                    "id": vis_id
                }
            ]),
            "optionsJSON": json.dumps({"useMargins": False, "hidePanelTitles": True}),
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            }
        }
    }

    print(f"Creating dashboard {dash_id}...")
    resp = requests.post(
        f"{OSD_URL}/api/saved_objects/dashboard/{dash_id}?overwrite=true",
        auth=AUTH,
        headers=HEADERS,
        json=dash_obj,
        verify=False
    )
    print(f"Dash Response: {resp.status_code}")
    
    if resp.status_code in [200, 201]:
        print("\nSUCCESS: Wazuh-TI Dashboard created inside Wazuh!")
        print(f"You can find it at: {OSD_URL}/app/dashboards#/view/{dash_id}")

if __name__ == "__main__":
    import_dashboard()
