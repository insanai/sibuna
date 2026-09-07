#!/bin/sh
# Runs the Sibuna benchmark suite in ReleaseFast, records the host, binary
# size, and idle resident memory, and writes machine-readable results under
# benchmarks/results/. The book renders its figures from latest.json.
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
zig_ver=$(zig version 2>/dev/null || echo "unknown")

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

echo "Building ReleaseFast daemon and benchmark suite..." >&2
zig build -Doptimize=ReleaseFast >"$tmp_dir/build.out" 2>&1 || {
    cat "$tmp_dir/build.out" >&2
    exit 1
}
binary_bytes=$(wc -c <zig-out/bin/sibuna | tr -d ' ')
wasm_bytes=$(wc -c <zig-out/web/wasm/sibuna-pow.wasm | tr -d ' ')

# Idle resident set: start the daemon on an unused port for two seconds.
idle_rss_kb=0
if command -v ps >/dev/null 2>&1; then
    ./zig-out/bin/sibuna --port 18480 --workers 2 >/dev/null 2>&1 &
    daemon_pid=$!
    sleep 2
    idle_rss_kb=$(ps -o rss= -p "$daemon_pid" 2>/dev/null | tr -d ' ' || echo 0)
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
fi

echo "Running benchmark suite..." >&2
./zig-out/bin/sibuna-benchmark >"$tmp_dir/bench.out" 2>"$tmp_dir/bench.err" || {
    cat "$tmp_dir/bench.err" >&2
    exit 1
}
cat "$tmp_dir/bench.err"

python3 - "$tmp_dir/bench.out" "$out_file" "$out_dir/latest.json" <<PY
import json, sys, datetime
text = open(sys.argv[1]).read()
start = text.find('{"meta":')
end = text.rfind(']}') + 2
data = json.loads(text[start:end])
data['meta'].update({
    'date': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    'host': '$host', 'cpu': '$cpu', 'os': '$os', 'git': '$git_rev',
    'dirty': '$dirty' == 'true', 'zig': '$zig_ver',
    'binary_bytes': int('$binary_bytes'), 'wasm_bytes': int('$wasm_bytes'),
    'idle_rss_kb': int('${idle_rss_kb:-0}' or 0),
    'note': 'sibuna rows are measured on this host; anubis-model rows are fixed reference models, not measurements',
})
for path in (sys.argv[2], sys.argv[3]):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
print('Benchmark results written to:', sys.argv[2], 'and', sys.argv[3])
PY
