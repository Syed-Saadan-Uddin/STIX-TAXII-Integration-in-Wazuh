from __future__ import annotations

import itertools
import os
import random
import time
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name, str(default)).strip()
    try:
        return max(1, int(value))
    except ValueError:
        return default


LOG_PATH = Path(os.getenv("ALERT_LOG_PATH", "/var/log/wazuh-test/auth.log"))
INTERVAL_SECONDS = _env_int("ALERT_INTERVAL_SECONDS", 30)
HOSTNAME = os.getenv("ALERT_HOSTNAME", "wazuh-test-agent").strip() or "wazuh-test-agent"

PATTERNS = (
    {
        "ip": "185.220.101.12",
        "user": "admin",
        "message": "Failed password for invalid user {user} from {ip} port {port} ssh2",
    },
    {
        "ip": "91.240.118.172",
        "user": "backup",
        "message": "Failed password for root from {ip} port {port} ssh2",
    },
    {
        "ip": "45.95.147.44",
        "user": "deploy",
        "message": "Invalid user {user} from {ip} port {port}",
    },
    {
        "ip": "103.15.53.231",
        "user": "oracle",
        "message": "Failed password for invalid user {user} from {ip} port {port} ssh2",
    },
)


def build_line(event: dict, sequence: int) -> str:
    timestamp = time.strftime("%b %d %H:%M:%S", time.localtime())
    pid = 1000 + (sequence % 8000)
    port = random.randint(20000, 65000)
    message = event["message"].format(user=event["user"], ip=event["ip"], port=port)
    return f"{timestamp} {HOSTNAME} sshd[{pid}]: {message}"


def main() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    sequence = 1

    with LOG_PATH.open("a", encoding="utf-8") as handle:
        for event in itertools.cycle(PATTERNS):
            line = build_line(event, sequence)
            handle.write(line + "\n")
            handle.flush()
            print(f"[generator] wrote alert #{sequence}: {line}", flush=True)
            sequence += 1
            time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
