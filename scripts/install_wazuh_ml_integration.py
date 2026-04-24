"""
Install the Wazuh -> Wazuh-TI ML integration into mounted Wazuh volumes.

Usage:
    python scripts/install_wazuh_ml_integration.py
    python scripts/install_wazuh_ml_integration.py --hook-url http://wazuh-ti:8000/api/v1/ml/alerts/ingest
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.config import get_config
from app.core.wazuh_ml_integration import get_wazuh_ml_integration_manager

DEFAULT_ETC_VOLUME = "single-node_wazuh_etc"
DEFAULT_INTEGRATIONS_VOLUME = "single-node_wazuh_integrations"
INTEGRATION_SCRIPT_PATH = REPO_ROOT / "wazuh-integrations" / "custom-wazuh-ti-ml"


def install_via_docker_volumes(
    *,
    hook_url: str | None,
    level: int,
    timeout: int,
    retries: int,
    api_key: str | None,
    etc_volume: str,
    integrations_volume: str,
) -> dict:
    """Install the integration by writing directly into Docker named volumes."""
    script_body = INTEGRATION_SCRIPT_PATH.read_text(encoding="utf-8")
    payload = {
        "hook_url": hook_url or "http://wazuh-ti:8000/api/v1/ml/alerts/ingest",
        "level": level,
        "timeout": timeout,
        "retries": retries,
        "api_key": api_key,
        "script_body": script_body,
    }

    bootstrap = f"""
import json
import os
import re
from pathlib import Path

payload = {repr(payload)}
block_start = "<!-- WAZUH-TI ML INTEGRATION START -->"
block_end = "<!-- WAZUH-TI ML INTEGRATION END -->"
integration_name = "custom-wazuh-ti-ml"
etc_dir = Path("/wazuh-etc")
integrations_dir = Path("/wazuh-integrations")
ossec_conf_path = etc_dir / "ossec.conf"
script_target_path = integrations_dir / integration_name

if not etc_dir.exists() or not integrations_dir.exists():
    raise FileNotFoundError("Wazuh Docker volumes are not available inside the helper container.")

script_target_path.write_text(payload["script_body"], encoding="utf-8")
os.chmod(script_target_path, 0o750)

api_key_line = f"    <api_key>{{payload['api_key']}}</api_key>\\n" if payload.get("api_key") else ""
new_block = (
    f"{{block_start}}\\n"
    f"  <integration>\\n"
    f"    <name>{{integration_name}}</name>\\n"
    f"    <hook_url>{{payload['hook_url']}}</hook_url>\\n"
    f"    <level>{{payload['level']}}</level>\\n"
    f"{{api_key_line}}"
    f"    <alert_format>json</alert_format>\\n"
    f"    <timeout>{{payload['timeout']}}</timeout>\\n"
    f"    <retries>{{payload['retries']}}</retries>\\n"
    f"  </integration>\\n"
    f"{{block_end}}\\n"
)

if ossec_conf_path.exists():
    content = ossec_conf_path.read_text(encoding="utf-8")
else:
    content = "<ossec_config>\\n</ossec_config>\\n"

if block_start in content and block_end in content:
    content = re.sub(
        rf"{{re.escape(block_start)}}.*?{{re.escape(block_end)}}\\n?",
        new_block,
        content,
        flags=re.DOTALL,
    )
else:
    if "</ossec_config>" in content:
        content = content.replace("</ossec_config>", f"{{new_block}}</ossec_config>", 1)
    else:
        content = content.rstrip() + "\\n" + new_block

ossec_conf_path.write_text(content, encoding="utf-8")

print(json.dumps({{
    "installed": True,
    "available": True,
    "script_installed": script_target_path.exists(),
    "config_installed": block_start in content and integration_name in content,
    "hook_url": payload["hook_url"],
    "restart_required": True,
    "ossec_conf_path": str(ossec_conf_path),
    "integrations_dir": str(integrations_dir),
    "etc_dir": str(etc_dir),
    "method": "docker_volume_helper",
}}))
"""

    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-i",
            "-v",
            f"{etc_volume}:/wazuh-etc",
            "-v",
            f"{integrations_volume}:/wazuh-integrations",
            "python:3.11-slim",
            "python",
            "-",
        ],
        input=bootstrap,
        text=True,
        capture_output=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Docker volume helper failed.")

    return json.loads(result.stdout.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description="Install the Wazuh ML integration")
    parser.add_argument("--hook-url", default=None, help="Override the integration hook URL")
    parser.add_argument("--level", type=int, default=3, help="Minimum Wazuh alert level to forward")
    parser.add_argument("--timeout", type=int, default=10, help="Integration timeout in seconds")
    parser.add_argument("--retries", type=int, default=2, help="Integration retry count")
    parser.add_argument("--etc-volume", default=DEFAULT_ETC_VOLUME, help="Docker volume name for Wazuh etc")
    parser.add_argument("--integrations-volume", default=DEFAULT_INTEGRATIONS_VOLUME, help="Docker volume name for Wazuh integrations")
    args = parser.parse_args()

    config = get_config()
    api_key = config.api.api_key if config.api.api_key_enabled and config.api.api_key else None
    manager = get_wazuh_ml_integration_manager()

    try:
        result = manager.install(
            hook_url=args.hook_url,
            level=args.level,
            timeout=args.timeout,
            retries=args.retries,
            api_key=api_key,
        )
    except FileNotFoundError:
        result = install_via_docker_volumes(
            hook_url=args.hook_url,
            level=args.level,
            timeout=args.timeout,
            retries=args.retries,
            api_key=api_key,
            etc_volume=args.etc_volume,
            integrations_volume=args.integrations_volume,
        )

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
