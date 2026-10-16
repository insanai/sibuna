#!/bin/sh
set -eu
systemd-sysusers /usr/lib/sysusers.d/sibuna.conf
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
# Never enable or start the daemon, and never create console credentials, on installation.
