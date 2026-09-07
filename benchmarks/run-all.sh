#!/bin/sh
# Runs the Sibuna vs Anubis benchmark suite, captures system metadata,
# and writes machine-readable results under benchmarks/results/.
set -eu

cd "$(dirname "$0")/.."

stamp=$(date +%Y%m%d)
host=$(hostname -s)
out_dir="benchmarks/results"
out_file="$out_dir/$stamp-$host.json"
mkdir -p "$out_dir"

dirty=false
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    dirty=true
fi

git_rev=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
zig_ver=$(zig version 2>/dev/null || echo "0.16.0")

cpu="unknown"
if command -v sysctl >/dev/null 2>&1; then
    cpu=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)
fi
if [ "$cpu" = "unknown" ] && [ -r /proc/cpuinfo ]; then
    cpu=$(awk -F': ' '/model name/ { print $2; exit }' /proc/cpuinfo)
fi

os=$(uname -s -r 2>/dev/null || echo "unknown")

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

echo "Compiling and running Sibuna benchmark suite (ReleaseFast)..." >&2
zig build -Doptimize=ReleaseFast benchmark-zig >"$tmp_dir/bench.out" 2>&1 || {
    cat "$tmp_dir/bench.out" >&2
    exit 1
}

# Display human summary table to stdout
grep -A 20 "=== Sibuna vs Anubis Benchmark Summary ===" "$tmp_dir/bench.out" || true

# Extract JSON block and inject full system metadata
python3 -c "
import json, sys

with open('$tmp_dir/bench.out') as f:
    text = f.read()

start = text.find('{\"meta\":')
if start != -1:
    end = text.find(']}', start) + 2
    data = json.loads(text[start:end])
    data['meta']['host'] = '$host'
    data['meta']['cpu'] = '$cpu'
    data['meta']['os'] = '$os'
    data['meta']['git'] = '$git_rev'
    data['meta']['dirty'] = ('$dirty' == 'true')
    data['meta']['zig'] = '$zig_ver'
    with open('$out_file', 'w') as out_f:
        json.dump(data, out_f, indent=2)
    with open('$out_dir/latest.json', 'w') as out_f:
        json.dump(data, out_f, indent=2)
    print('Benchmark results written to:')
    print('  - $out_file')
    print('  - $out_dir/latest.json')
else:
    sys.exit('Warning: Could not find JSON block in benchmark output')
"
