#!/bin/sh
set -e
# Stop only on removal. deb prerm: $1 = remove | upgrade | ...; rpm %preun: $1 = 0 erase, 1 upgrade.
# On upgrade, postinstall of the new package restarts the unit.
case "$1" in
    remove|0) ;;
    *) exit 0 ;;
esac
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop hcdn-connector || true
    systemctl disable hcdn-connector || true
fi
