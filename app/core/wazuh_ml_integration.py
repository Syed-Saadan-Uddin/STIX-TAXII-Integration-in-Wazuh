"""
Installer and status helpers for the Wazuh -> ML threat prediction bridge.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

from app.utils.logger import get_logger

logger = get_logger(__name__)

INTEGRATION_NAME = "custom-wazuh-ti-ml"
BLOCK_START = "<!-- WAZUH-TI ML INTEGRATION START -->"
BLOCK_END = "<!-- WAZUH-TI ML INTEGRATION END -->"
DEFAULT_HOOK_URL = "http://wazuh-ti:8000/api/v1/ml/alerts/ingest"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _script_source_path() -> Path:
    return _repo_root() / "wazuh-integrations" / INTEGRATION_NAME


def _render_integration_block(hook_url: str, api_key: str | None, level: int, timeout: int, retries: int) -> str:
    api_key_line = f"    <api_key>{api_key}</api_key>\n" if api_key else ""
    return (
        f"{BLOCK_START}\n"
        f"  <integration>\n"
        f"    <name>{INTEGRATION_NAME}</name>\n"
        f"    <hook_url>{hook_url}</hook_url>\n"
        f"    <level>{level}</level>\n"
        f"{api_key_line}"
        f"    <alert_format>json</alert_format>\n"
        f"    <timeout>{timeout}</timeout>\n"
        f"    <retries>{retries}</retries>\n"
        f"  </integration>\n"
        f"{BLOCK_END}\n"
    )


class WazuhMLIntegrationManager:
    def __init__(
        self,
        *,
        etc_dir: str | None = None,
        integrations_dir: str | None = None,
    ):
        self.etc_dir = Path(etc_dir or "/var/ossec/etc")
        self.integrations_dir = Path(integrations_dir or "/var/ossec/integrations")
        self.ossec_conf_path = self.etc_dir / "ossec.conf"
        self.script_target_path = self.integrations_dir / INTEGRATION_NAME
        self.script_source_path = _script_source_path()

    def _extract_hook_url(self, content: str) -> str | None:
        match = re.search(
            rf"<name>{re.escape(INTEGRATION_NAME)}</name>.*?<hook_url>(.*?)</hook_url>",
            content,
            flags=re.DOTALL,
        )
        return match.group(1).strip() if match else None

    def status(self) -> dict:
        config_exists = self.ossec_conf_path.exists()
        content = self.ossec_conf_path.read_text(encoding="utf-8") if config_exists else ""

        return {
            "available": self.etc_dir.exists() and self.integrations_dir.exists(),
            "etc_dir": str(self.etc_dir),
            "integrations_dir": str(self.integrations_dir),
            "ossec_conf_path": str(self.ossec_conf_path),
            "script_source_exists": self.script_source_path.exists(),
            "script_installed": self.script_target_path.exists(),
            "config_installed": BLOCK_START in content and INTEGRATION_NAME in content,
            "hook_url": self._extract_hook_url(content),
            "restart_required": False,
        }

    def install(
        self,
        *,
        hook_url: str | None = None,
        level: int = 3,
        timeout: int = 10,
        retries: int = 2,
        api_key: str | None = None,
    ) -> dict:
        if not self.script_source_path.exists():
            raise FileNotFoundError(f"Integration script asset not found: {self.script_source_path}")

        if not self.etc_dir.exists() or not self.integrations_dir.exists():
            raise FileNotFoundError(
                "Wazuh etc/integrations directories are not mounted. "
                "Mount the shared Wazuh volumes before installing the bridge."
            )

        shutil.copyfile(self.script_source_path, self.script_target_path)
        os.chmod(self.script_target_path, 0o750)

        try:
            shutil.chown(self.script_target_path, user="root", group="wazuh")
        except Exception as exc:
            logger.warning(f"Could not adjust ownership for {self.script_target_path}: {exc}")
            try:
                integrations_gid = self.integrations_dir.stat().st_gid
                os.chown(self.script_target_path, 0, integrations_gid)
                logger.info(
                    "Applied fallback ownership for %s using gid %s",
                    self.script_target_path,
                    integrations_gid,
                )
            except Exception as fallback_exc:
                logger.warning(
                    "Fallback ownership update failed for %s: %s",
                    self.script_target_path,
                    fallback_exc,
                )

        desired_hook_url = (hook_url or DEFAULT_HOOK_URL).strip()
        new_block = _render_integration_block(
            hook_url=desired_hook_url,
            api_key=api_key,
            level=level,
            timeout=timeout,
            retries=retries,
        )

        if self.ossec_conf_path.exists():
            content = self.ossec_conf_path.read_text(encoding="utf-8")
        else:
            content = "<ossec_config>\n</ossec_config>\n"

        original_content = content
        if BLOCK_START in content and BLOCK_END in content:
            content = re.sub(
                rf"{re.escape(BLOCK_START)}.*?{re.escape(BLOCK_END)}\n?",
                new_block,
                content,
                flags=re.DOTALL,
            )
        else:
            if "</ossec_config>" in content:
                content = content.replace("</ossec_config>", f"{new_block}</ossec_config>", 1)
            else:
                content = content.rstrip() + "\n" + new_block

        if content != original_content:
            if self.ossec_conf_path.exists():
                backup_path = self.ossec_conf_path.with_suffix(".conf.bak")
                shutil.copyfile(self.ossec_conf_path, backup_path)
            self.ossec_conf_path.write_text(content, encoding="utf-8")

        status = self.status()
        status["restart_required"] = True
        status["installed"] = True
        return status


_manager: WazuhMLIntegrationManager | None = None


def get_wazuh_ml_integration_manager() -> WazuhMLIntegrationManager:
    global _manager
    if _manager is None:
        _manager = WazuhMLIntegrationManager()
    return _manager
