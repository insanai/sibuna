#!/bin/sh
set -eu
# A Debian upgrade passes "upgrade"; an RPM upgrade passes a positive count.
# Arch runs pre_upgrade instead of pre_remove.
case "${1:-}" in
    upgrade) exit 0 ;;
    ''|*[!0-9]*) ;;
    *) if [ "$1" -gt 0 ]; then exit 0; fi ;;
esac
if [ -d /run/systemd/system ]; then
    systemctl stop sibuna.service || true
    systemctl disable sibuna.service || true
fi
# State, the admission seed and the service account are kept on removal and purge.
