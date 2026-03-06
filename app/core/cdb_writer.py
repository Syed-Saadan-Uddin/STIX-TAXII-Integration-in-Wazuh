"""
CDB (Constant Database) list writer for Wazuh SIEM integration.

Writes threat indicator values to Wazuh's CDB list format for real-time
matching against incoming log events. Handles atomic file writes (via
temp file + rename) to prevent Wazuh from reading partial files.

CDB list format (one per line):
    185.220.101.5:malicious
    evil.com:malicious

After writing, optionally triggers a Wazuh reload so the updated
CDB list takes effect immediately.
"""

import os
import tempfile
import subprocess
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable
from app.utils.logger import get_logger

logger = get_logger(__name__)


@runtime_checkable
class IndicatorLike(Protocol):
    """Protocol for objects that have value and type attributes."""
    value: str
    type: str


class CDBWriter:
    """
    Writes indicator values to a Wazuh CDB list file and triggers reload.

    Args:
        cdb_path: Absolute path to the CDB list file
        reload_command: Shell command to reload Wazuh configuration
        log_path: Path to Wazuh-TI log file for update records
    """

    def __init__(self, cdb_path: str, reload_command: str, log_path: str):
        self.cdb_path = cdb_path
        self.reload_command = reload_command
        self.log_path = log_path

    def write(self, indicators: list) -> int:
        """
        Write all active indicators to the CDB list file.

        Steps:
        1. Build CDB content (one line per indicator: "value:malicious")
        2. Write atomically (temp file → rename)
        3. Trigger Wazuh reload
        4. Log the update

        Args:
            indicators: List of Indicator model objects with .value attribute

        Returns:
            Number of indicators written to the file.
        """
        if not indicators:
            logger.info("No indicators to write to CDB list")
            return 0

        # Build CDB content
        lines = []
        seen = set()
        for ind in indicators:
            value = ind.value
            if value not in seen:
                lines.append(f"{value}:malicious")
                seen.add(value)

        cdb_content = "\n".join(lines) + "\n"

        # Write atomically: temp file in same directory, then rename
        try:
            cdb_dir = os.path.dirname(self.cdb_path)
            os.makedirs(cdb_dir, exist_ok=True)

            # Write to temp file
            fd, tmp_path = tempfile.mkstemp(dir=cdb_dir, suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as tmp_file:
                    tmp_file.write(cdb_content)

                # Atomic rename (on same filesystem)
                os.replace(tmp_path, self.cdb_path)
            except Exception:
                # Clean up temp file on failure
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise

            count = len(lines)
            logger.info(f"CDB list written: {count} indicators to {self.cdb_path}")

            # Reload Wazuh and log the update
            self._reload_wazuh()
            self._log_update(count)

            return count

        except Exception as e:
            logger.error(f"Failed to write CDB list: {e}")
            return 0

    def _reload_wazuh(self) -> None:
        """
        Trigger Wazuh configuration reload.
        Logs success/failure — never raises an exception.
        """
        try:
            result = subprocess.run(
                self.reload_command,
                shell=True,
                timeout=30,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                logger.info("Wazuh reload triggered successfully")
            else:
                logger.warning(
                    f"Wazuh reload returned non-zero exit code: {result.returncode}. "
                    f"stderr: {result.stderr.strip()}"
                )
        except subprocess.TimeoutExpired:
            logger.warning("Wazuh reload timed out after 30 seconds")
        except FileNotFoundError:
            logger.warning(
                f"Wazuh reload command not found: {self.reload_command}. "
                "This is expected when running outside of the Wazuh container."
            )
        except Exception as e:
            logger.warning(f"Wazuh reload failed: {e}")

    def _log_update(self, count: int) -> None:
        """
        Append an update record to the Wazuh-TI log file.
        Format: [WAZUH-TI] 2024-01-10T10:00:00Z CDB list updated: 1423 indicators
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        log_line = f"[WAZUH-TI] {timestamp} CDB list updated: {count} indicators\n"

        try:
            log_dir = os.path.dirname(self.log_path)
            os.makedirs(log_dir, exist_ok=True)
            with open(self.log_path, "a") as f:
                f.write(log_line)
        except (OSError, PermissionError) as e:
            logger.warning(f"Could not write to Wazuh log: {e}")
