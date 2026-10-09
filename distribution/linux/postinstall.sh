#!/bin/sh
set -eu
systemd-sysusers /usr/lib/sysusers.d/sibuna.conf
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
# Never enable/start a daemon or create console credentials during installation.
