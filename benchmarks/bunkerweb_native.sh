#!/bin/sh
# Called inside `sudo unshare --mount --propagation private`. Every mount belongs to that
# namespace and disappears when its processes exit. No host service or host mount changes.
set -eu
benchmark_root=$1
benchmark_uid=$2
benchmark_gid=$3
shift 3
case "$benchmark_root" in
    /*) ;;
    *) echo 'Expected an absolute isolated image path' >&2; exit 1 ;;
esac
test -f "$benchmark_root/usr/share/bunkerweb/VERSION"
mkdir -p "$benchmark_root/dev/shm" "$benchmark_root/proc"
for device in null zero random urandom; do
    touch "$benchmark_root/dev/$device"
    mount --bind "/dev/$device" "$benchmark_root/dev/$device"
done
mount -t tmpfs -o nosuid,nodev,size=64m tmpfs "$benchmark_root/dev/shm"
mount -t proc -o nosuid,nodev,noexec proc "$benchmark_root/proc"
exec /usr/sbin/chroot --userspec="$benchmark_uid:$benchmark_gid" "$benchmark_root" "$@"
