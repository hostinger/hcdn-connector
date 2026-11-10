#!/bin/sh
set -e
if ! getent group hcdn-connector >/dev/null 2>&1; then
    groupadd --system hcdn-connector
fi
if ! getent passwd hcdn-connector >/dev/null 2>&1; then
    useradd --system --gid hcdn-connector --home-dir /nonexistent --no-create-home \
        --shell /usr/sbin/nologin --comment "Hostinger CDN tunnel connector" hcdn-connector
fi
