#!/bin/sh
set -e
# Drop the removed unit from systemd's view (also harmless after an upgrade).
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
