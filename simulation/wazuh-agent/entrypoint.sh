#!/bin/sh
set -eu

TEMPLATE_PATH="/etc/wazuh-test-agent/ossec.conf.template"
TARGET_PATH="/var/ossec/etc/ossec.conf"
MANAGER_HOST="${WAZUH_MANAGER_SERVER:-wazuh.manager}"

if [ -f "$TEMPLATE_PATH" ]; then
  sed "s/__WAZUH_MANAGER_SERVER__/${MANAGER_HOST}/g" "$TEMPLATE_PATH" > "$TARGET_PATH"
fi

/var/ossec/bin/wazuh-control start

cleanup() {
  /var/ossec/bin/wazuh-control stop || true
  exit 0
}

trap cleanup INT TERM

touch /var/ossec/logs/ossec.log
tail -F /var/ossec/logs/ossec.log &
wait $!
