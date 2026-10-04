#!/usr/bin/env python3
"""Linux process-tree accounting; never linked into a measured product.

Sum user/system ticks of live processes, excluding child-time fields to avoid double
counting. Summed RSS counts shared pages more than once; it is not proportional memory.
"""
import os
from pathlib import Path
import threading


def parse_stat(text):
    fields = text[text.rindex(")") + 2:].split()
    return {"parent": int(fields[1]), "cpu_ticks": int(fields[11]) + int(fields[12]),
            "rss_pages": int(fields[21])}


def snapshot(root_pid):
    processes = {}
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            processes[int(directory.name)] = parse_stat((directory / "stat").read_text())
        except (FileNotFoundError, ProcessLookupError):
            continue  # A process exited between directory listing and stat.
    if root_pid not in processes:
        raise ProcessLookupError("measured process exited during accounting")
    members = {root_pid}
    while True:
        children = {pid for pid, row in processes.items() if row["parent"] in members}
        if children <= members:
            break
        members |= children
    rows = {pid: processes[pid] for pid in members if pid in processes}
    return {"pids": sorted(rows),
            "cpu_seconds": sum(row["cpu_ticks"] for row in rows.values())
                           / os.sysconf("SC_CLK_TCK"),
            "rss_kib": sum(row["rss_pages"] for row in rows.values())
                       * os.sysconf("SC_PAGE_SIZE") / 1024}


class PeakRss(threading.Thread):
    def __init__(self, pid):
        super().__init__(daemon=True)
        self.pid, self.peak, self.stopping = pid, 0, threading.Event()
        self.error = None

    def run(self):
        try:
            while not self.stopping.is_set():
                self.peak = max(self.peak, snapshot(self.pid)["rss_kib"])
                self.stopping.wait(0.1)
        except Exception as error:
            self.error = error

    def finish(self):
        self.stopping.set()
        self.join()
        if self.error:
            raise self.error
        return self.peak
