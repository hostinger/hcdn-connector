#!/bin/sh
set -e
# No running systemd in a container build or chroot.
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl try-restart hcdn-connector || true
fi
if [ ! -f /etc/hcdn-connector/credentials.json ]; then
    echo "hcdn-connector: install /etc/hcdn-connector/credentials.json (mode 0600, owner hcdn-connector)"
    echo "hcdn-connector: edit /etc/hcdn-connector/config.yml, then: sudo -u hcdn-connector hcdn-connector check && systemctl enable --now hcdn-connector"
fi
