#!/bin/sh
set -eu

# Scan Zig source code files across the repository.
# Note: docs/ is deliberately excluded per guidelines so documentation formatting is preserved.
roots=""
for root in build.zig apps libs tools; do
    if [ -e "$root" ]; then
        roots="$roots $root"
    fi
done

failed=0
files=$(find $roots \
    -type d \( -name .zig-cache -o -name zig-out -o -name target -o -name docs \) -prune -o \
    -type f -name '*.zig' -print | sort)

for source in $files; do
    if ! awk -f tools/check-style.awk "$source"; then
        failed=1
    fi
done

if [ "$failed" -ne 0 ]; then
    echo "check-style: violations found" >&2
    exit 1
fi
echo "check-style: all files passed"
