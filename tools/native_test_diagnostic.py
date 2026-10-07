#!/usr/bin/env python3
"""Retain macOS call stacks for owned native tests; never inspect memory contents."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def owned_rows(rows, root):
    owned = {root}
    while True:
        found = {pid for pid, parent, *_ in rows if parent in owned}
        if found <= owned:
            return [row for row in rows if row[0] in owned]
        owned.update(found)


def processes():
    text = subprocess.check_output(
        ["ps", "-axo", "pid=,ppid=,rss=,etime=,comm="], text=True)
    rows = []
    for line in text.splitlines():
        fields = line.split(None, 4)
        if len(fields) == 5:
            rows.append((int(fields[0]), int(fields[1]), *fields[2:]))
    return rows


def observe(process, destination, first_seen, last_sample):
    now = time.monotonic()
    for log in Path(".zig-cache").glob("tunnel-diagnostic-*.log"):
        (destination / log.name).write_bytes(log.read_bytes())
    rows = owned_rows(processes(), process.pid)
    with (destination / "processes.log").open("a") as output:
        for pid, parent, rss, elapsed, command in rows:
            output.write(f"{time.time():.0f} pid={pid} parent={parent} rss_kib={rss} "
                         f"elapsed={elapsed} executable={command}\n")
            if Path(command).name != "test":
                continue
            first_seen.setdefault(pid, now)
            if now - first_seen[pid] < 120 or now - last_sample.get(pid, 0) < 300:
                continue
            # Recheck identity and ancestry immediately before sampling. The profiler
            # records symbol stacks/statistics, not registers, variables or heap bytes.
            current = owned_rows(processes(), process.pid)
            if (pid, parent, rss, elapsed, command)[:2] not in [r[:2] for r in current]:
                continue
            if not any(r[0] == pid and r[4] == command for r in current):
                continue
            path = destination / f"test-{pid}-{int(now)}.sample.txt"
            result = subprocess.run(["sample", str(pid), "1", "10", "-file", str(path)],
                                    capture_output=True, text=True, timeout=15)
            last_sample[pid] = now
            print(f"Owned test sample: pid={pid}, executable={command}, "
                  f"status={result.returncode}", flush=True)
            if path.exists():
                print(path.read_text(errors="replace"), flush=True)


def stop_owned_group(process):
    if process.poll() is not None:
        return
    assert os.getpgid(process.pid) == process.pid
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def run(command, destination):
    destination.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    first_seen, last_sample = {}, {}
    with (destination / "build.log").open("wb") as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            while process.poll() is None:
                observe(process, destination, first_seen, last_sample)
                # A stricter diagnostic deadline leaves five minutes to retain artifacts
                # inside the unchanged 45-minute job cap. Timeout is always a failure.
                if time.monotonic() - started >= 2400:
                    (destination / "timeout.txt").write_text("40-minute diagnostic deadline\n")
                    stop_owned_group(process)
                    return 124
                time.sleep(20)
            return process.returncode
        finally:
            stop_owned_group(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    assert command, "Expected a native qualification command"
    return run(command, args.log_dir)


if __name__ == "__main__":
    sys.exit(main())
