#!/usr/bin/env python3
"""Check native phase evidence against pinned CRS FTW rule-ID assertions.

Transport, omitted response fixtures, regex logs and multi-stage state are reported
as coverage gaps. They are never counted as passing this evidence check.
"""
import argparse
from collections import Counter
import hashlib
import http.client
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
from urllib.parse import quote_plus, unquote_to_bytes, urlsplit
from urllib.request import urlopen

import yaml

from crs_signature_check import archive_bytes, SIGNED_TIME

COMMIT = "e03a4f6dabc7a30ebd8c52c97d28a154f590a48f"
SOURCE_DIGEST = "bdd0dec65d47fcae5aaa48aa681e0f4c151a8c1d9eb3040f6f65ebb8b2273c75"
SOURCE_LIMIT = 32 * 1024 * 1024


def source_bytes(directory, download):
    path = directory / "crs-full-4.30.0.tar.gz"
    if not path.exists() and download:
        with urlopen(f"https://codeload.github.com/coreruleset/coreruleset/tar.gz/{COMMIT}",
                     timeout=60) as response:
            data = response.read(SOURCE_LIMIT + 1)
        if len(data) > SOURCE_LIMIT or hashlib.sha256(data).hexdigest() != SOURCE_DIGEST:
            raise ValueError("pinned FTW source download mismatch")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    with path.open("rb") as file:
        data = file.read(SOURCE_LIMIT + 1)
    if len(data) > SOURCE_LIMIT or hashlib.sha256(data).hexdigest() != SOURCE_DIGEST:
        raise ValueError("pinned FTW source mismatch")
    return data


def form_bytes(text):
    # go-ftw v2.6.0/ftwhttp/request.go: encode key/value pairs only when
    # QueryUnescape would leave the input unchanged. Invalid '%' stays literal.
    data = text.encode()
    if re.search(r"%(?![0-9a-fA-F]{2})", text):
        return text
    if unquote_to_bytes(text.replace("+", " ")) != data:
        return text
    tokens = text.split("&")
    if tokens and tokens[-1] == "":
        tokens.pop()
    result = []
    for token in tokens:
        key, separator, value = token.partition("=")
        encoded = quote_plus(key, safe="")
        if separator:
            encoded += "=" + quote_plus(value, safe="")
        result.append(encoded)
    return "&".join(result)


def normalize(source, identifier):
    method = source.get("method", "GET")
    target = source.get("uri", "/")
    protocol = source.get("version", "HTTP/1.1")
    headers = [{"name": key, "value": header_value(value)}
               for key, value in sorted(source.get("headers", {}).items())]
    body = source.get("data") or ""
    autocomplete = source.get("autocomplete_headers", True)

    def values(name):
        return [header["value"] for header in headers if header["name"].lower() == name]

    if body and autocomplete:
        if not values("content-type"):
            headers.append({"name": "Content-Type", "value": "application/x-www-form-urlencoded"})
        if "application/x-www-form-urlencoded" in [value.lower() for value in values("content-type")]:
            body = form_bytes(body)
    if any("multipart/form-data;" in value.lower() for value in values("content-type")):
        body = body.replace("\n", "\r\n")
    if autocomplete:
        if not values("connection"):
            headers.append({"name": "Connection", "value": "close"})
        if not values("content-length") and (body or re.search(r"^POST|PUT|PATCH|DELETE$", method)):
            headers.append({"name": "Content-Length", "value": str(len(body.encode()))})
    return dict(id=identifier, method=method, target=target, protocol=protocol,
                line=f"{method} {target} {protocol}", headers=headers, body=body)


def header_value(value):
    # The upstream YAML string schema accepts decimal scalar headers; the HTTP
    # serializer writes their textual bytes, never JSON numeric tokens.
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    raise ValueError("unsupported FTW header scalar")


def collect(data, include_responses=False, responses_only=False):
    requests, contracts, gaps = [], {}, []
    files = 0
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = sorted(archive.getmembers(), key=lambda entry: entry.name)
        for member in members:
            if "/tests/regression/tests/" not in member.name or not member.name.endswith(".yaml"):
                continue
            if not member.isfile() or member.size > 2 * 1024 * 1024:
                raise ValueError("invalid FTW fixture member")
            files += 1
            document = yaml.safe_load(archive.extractfile(member)) or {}
            for test in document.get("tests", []) or []:
                total += 1
                name = f'{document["rule_id"]}-{test["test_id"]}'
                response_case = "/RESPONSE-" in member.name
                if responses_only and not response_case:
                    continue
                stages = test["stages"]
                reason = None
                if len(stages) != 1:
                    reason = "multi-stage state"
                elif response_case and not include_responses:
                    reason = "origin-response fixture"
                else:
                    source, output = stages[0]["input"], stages[0]["output"]
                    log = output.get("log", {})
                    if "encoded_request" in source:
                        reason = "encoded wire request"
                    elif not log.get("expect_ids") and not log.get("no_expect_ids"):
                        reason = "wire/status/regex assertion"
                    elif set(log) - {"expect_ids", "no_expect_ids"}:
                        reason = "regex log assertion"
                    elif set(output) - {"log", "retry_once"}:
                        reason = "additional wire/status assertion"
                if reason:
                    gaps.append(dict(test=name, reason=reason))
                    continue
                identifier = len(requests)
                requests.append(normalize(source, identifier))
                requests[-1]["response_case"] = response_case
                contracts[identifier] = dict(test=name, expected=log.get("expect_ids", []),
                                             forbidden=log.get("no_expect_ids", []))
    if files != 326 or total != 5193 or not requests:
        raise ValueError("FTW inventory drift")
    return requests, contracts, gaps


def origin_reply(case, address):
    connection = http.client.HTTPConnection(address.hostname, address.port, timeout=5)
    try:
        connection.putrequest(case["method"], case["target"], skip_host=True,
                              skip_accept_encoding=True)
        for header in case["headers"]:
            connection.putheader(header["name"], header["value"])
        connection.endheaders(case["body"].encode())
        response = connection.getresponse()
        body = response.read(1024 * 1024 + 1)
        headers = [{"name": name, "value": value} for name, value in response.getheaders()]
        if len(body) > 1024 * 1024 or len(headers) > 128:
            raise ValueError("origin fixture exceeds native response bounds")
        return dict(status=response.status, headers=headers, body_hex=body.hex())
    finally:
        connection.close()


def fixture_origin(value, responses_only, parser):
    origin = urlsplit(value) if value else None
    if origin and (origin.scheme != "http" or origin.hostname != "127.0.0.1" or
                   not origin.port or origin.username or origin.password or
                   origin.path or origin.query or origin.fragment):
        parser.error("--origin requires http://127.0.0.1:<port>")
    if responses_only and not origin:
        parser.error("--responses-only requires --origin")
    return origin


def compare(rows, contracts):
    failures = []
    seen = set()
    for row in rows:
        identifier = row["id"]
        if identifier in seen or identifier not in contracts:
            raise ValueError("duplicate or unrecognized native case result")
        seen.add(identifier)
        contract = contracts[identifier]
        actual = set(row["ids"])
        missing = sorted(set(contract["expected"]) - actual)
        unexpected = sorted(set(contract["forbidden"]) & actual)
        if row["error"] or missing or unexpected:
            failures.append(dict(test=contract["test"], error=row["error"], missing=missing,
                                 unexpected=unexpected, actual=sorted(actual)))
    if seen != set(contracts):
        raise ValueError("native result coverage mismatch")
    return failures


def reference_differences(path, failures):
    if path is None:
        return []
    reference = json.loads(path.read_text())
    if (reference.get("commit") != COMMIT or reference.get("source_sha256") != SOURCE_DIGEST or
            not re.search(r"\bv3\.0\.14\b", reference.get("reference", ""))):
        raise ValueError("reference report provenance mismatch")
    rows = {row["test"]: row for row in reference["rows"]}
    if len(rows) != len(reference["rows"]):
        raise ValueError("reference report duplicates a test")
    # Keep every mismatch in the main failure list. This annotation documents
    # independent agreement; it never silently rewrites an upstream assertion.
    return [failure["test"] for failure in failures if not failure["error"] and
            failure["test"] in rows and not rows[failure["test"]]["error"] and
            set(failure["actual"]) == set(rows[failure["test"]]["ids"])]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--source-dir", type=Path, default=Path(".zig-cache/crs-review"))
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--report", type=Path, default=Path(".zig-cache/crs-review/ftw-report.json"))
    parser.add_argument("--origin", help="loopback Albedo 0.3.0 fixture URL")
    parser.add_argument("--responses-only", action="store_true")
    parser.add_argument("--reference-report", type=Path)
    args = parser.parse_args()
    origin = fixture_origin(args.origin, args.responses_only, parser)
    manifest = json.loads(Path("vendor/crs/provenance.json").read_text())
    release = archive_bytes(args.source_dir, manifest, args.download)
    requests, contracts, gaps = collect(source_bytes(args.source_dir, args.download),
                                      bool(origin), args.responses_only)
    for case in requests:
        if case.pop("response_case"):
            case["response"] = origin_reply(case, origin)
    with tempfile.TemporaryDirectory(prefix="sibuna-crs-ftw-") as temporary:
        directory = Path(temporary)
        archive, cases = directory / "release.tar.gz", directory / "cases.json"
        archive.write_bytes(release)
        cases.write_text(json.dumps(requests, ensure_ascii=True, separators=(",", ":")))
        result = subprocess.run([str(args.binary.resolve()), str(archive),
                                 "vendor/crs/release.tar.gz.asc", str(cases), str(SIGNED_TIME)],
                                capture_output=True, text=True, timeout=600)
        if result.returncode:
            raise RuntimeError(f"native FTW probe failed: {result.stderr}\n{result.stdout[-2000:]}")
        rows = [json.loads(line) for line in result.stdout.splitlines()]
    failures = compare(rows, contracts)
    report = dict(commit=COMMIT, source_sha256=SOURCE_DIGEST, inventory=5193,
                  evaluated=len(requests), passed=len(requests) - len(failures),
                  failures=failures, coverage_gaps=gaps,
                  work_peak=max(row["work"] for row in rows),
                  work_over_default=sum(row["work"] > 16_000_000 for row in rows),
                  diagnostic_work_limit=128_000_000, production_default_work_limit=16_000_000,
                  confirmed_reference_differences=reference_differences(args.reference_report,
                                                                        failures),
                  rows=[dict(row, test=contracts[row["id"]]["test"]) for row in rows])
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"FTW phase evidence: {report['passed']}/{len(requests)}; "
          f"{len(failures)} mismatches; {len(gaps)} separate coverage gaps.")
    print("Gap classes:", dict(Counter(gap["reason"] for gap in gaps)))
    print("Independently reproduced reference differences:",
          len(report["confirmed_reference_differences"]))
    print("Report:", args.report)
    if failures:
        print("First mismatches:", json.dumps(failures[:12], indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
