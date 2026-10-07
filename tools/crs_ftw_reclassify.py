#!/usr/bin/env python3
"""Replay strict FTW qualification over a retained measurement without sending traffic.

The original file and its process exit remain unchanged. New oracle evidence is
recorded separately from the source and binary provenance of the measured daemon.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from crs_ftw_check import source_bytes
from crs_ftw_daemon_check import corpus, engine_rows, representation_rows
from crs_ftw_daemon_verdict import classify, failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measurement", type=Path, required=True)
    parser.add_argument("--measurement-exit", type=int, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--albedo", type=Path, required=True)
    parser.add_argument("--engine-report", type=Path, action="append", required=True)
    parser.add_argument("--reference-report", type=Path, action="append", required=True)
    parser.add_argument("--representation-report", type=Path, action="append", default=[])
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.resolve() == args.measurement.resolve():
        parser.error("the derived receipt must not overwrite its measurement")
    with args.measurement.open("rb") as source:
        raw = source.read(64 * 1024 * 1024 + 1)
    if len(raw) > 64 * 1024 * 1024:
        parser.error("measurement exceeds the report bound")
    report = json.loads(raw)
    tests = corpus(source_bytes(args.source_dir, False))
    if not report["full_inventory"] or report["inventory"] != len(tests):
        parser.error("qualification requires the full pinned measurement inventory")
    classes = classify(tests, report["rows"], engine_rows(args.engine_report),
        engine_rows(args.reference_report, reference=True), report["work_budget"],
        report["mode"], representation_rows(args.representation_report, args.albedo))
    report["classes"] = dict(classes)
    report["passed"] = classes["passed"]
    report["qualified"] = not failures(report["rows"]) and report["dropped_incidents"] == 0
    report["measurement_exit"] = args.measurement_exit
    files = [Path(__file__), Path(__file__).with_name("crs_ftw_daemon_verdict.py"),
             Path(__file__).with_name("crs_ftw_daemon_check.py")]
    report["classification_provenance"] = {
        "date": datetime.now(timezone.utc).isoformat(),
        "raw_measurement_sha256": hashlib.sha256(raw).hexdigest(),
        "tools": [digest(path) for path in files],
        "input_proofs": [digest(path) for path in args.engine_report + args.reference_report +
                         args.representation_report],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=1) + "\n")
    print(report["mode"], "qualified", report["qualified"], "classes", dict(classes))
    raise SystemExit(0 if report["qualified"] else 1)


def digest(path):
    return dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
