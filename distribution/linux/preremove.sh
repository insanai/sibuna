#!/bin/sh
set -eu
# Debian upgrade supplies "upgrade"; RPM upgrade supplies a positive count.
# Arch pre_upgrade is distinct from pre_remove.
case "${1:-}" in
    upgrade) exit 0 ;;
    ''|*[!0-9]*) ;;
    *) if [ "$1" -gt 0 ]; then exit 0; fi ;;
esac
if [ -d /run/systemd/system ]; then
    systemctl stop sibuna.service || true
    systemctl disable sibuna.service || true
fi
# Keep state and the service identity on removal/purge to protect owned data.
