#!/usr/bin/env python3
"""Run pinned phase fixtures through a separately supplied ModSecurity 3.0.14.

This diagnostic never changes FTW expectations or declares mismatches passed. The
reference library is a test dependency, not part of Sibuna or its request path.
"""
import argparse
import ctypes
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import tempfile

from crs_ftw_check import (collect, compare, source_bytes, origin_reply, fixture_origin,
                           COMMIT, SOURCE_DIGEST)
from crs_signature_check import archive_bytes


SETUP = r'''
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyLimit 1048576
SecResponseBodyMimeType text/plain text/html text/xml application/json
SecRequestBodyLimit 4194304
SecRequestBodyNoFilesLimit 4194304
SecRequestBodyJsonDepthLimit 64
SecArgumentsLimit 4096
SecPcreMatchLimit 100000
SecAuditEngine Off
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
 "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" \
 "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecAction "id:900005,phase:1,nolog,pass,ctl:ruleRemoveById=910000,\
 setvar:tx.blocking_paranoia_level=4,setvar:tx.detection_paranoia_level=4,\
 setvar:tx.crs_validate_utf8_encoding=1,setvar:tx.arg_name_length=100,\
 setvar:tx.arg_length=400,setvar:tx.total_arg_length=64000,\
 setvar:tx.max_num_args=255,setvar:tx.max_file_size=64100,\
 setvar:tx.combined_file_sizes=65535,setvar:tx.reporting_level=4"
'''


class Reference:
    def __init__(self, path):
        self.lib = ctypes.CDLL(str(path.resolve()))
        self.messages = []
        self.callback_error = False
        pointer, text, integer = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int
        size = ctypes.c_size_t
        callback_type = ctypes.CFUNCTYPE(None, pointer, pointer)
        functions = {
            "msc_init": (pointer, []),
            "msc_who_am_i": (text, [pointer]),
            "msc_cleanup": (None, [pointer]),
            "msc_set_log_cb": (None, [pointer, callback_type]),
            "msc_create_rules_set": (pointer, []),
            "msc_rules_cleanup": (integer, [pointer]),
            "msc_rules_add": (integer, [pointer, text, ctypes.POINTER(text)]),
            "msc_rules_add_file": (integer, [pointer, text, ctypes.POINTER(text)]),
            "msc_new_transaction_with_id": (pointer, [pointer, pointer, text, pointer]),
            "msc_transaction_cleanup": (None, [pointer]),
            "msc_process_connection": (integer, [pointer, text, integer, text, integer]),
            "msc_process_uri": (integer, [pointer, text, text, text]),
            "msc_add_n_request_header": (integer, [pointer, text, size, text, size]),
            "msc_process_request_headers": (integer, [pointer]),
            "msc_append_request_body": (integer, [pointer, text, size]),
            "msc_process_request_body": (integer, [pointer]),
            "msc_add_n_response_header": (integer, [pointer, text, size, text, size]),
            "msc_process_response_headers": (integer, [pointer, integer, text]),
            "msc_append_response_body": (integer, [pointer, text, size]),
            "msc_process_response_body": (integer, [pointer]),
            "msc_process_logging": (integer, [pointer]),
        }
        for name, (result, arguments) in functions.items():
            function = getattr(self.lib, name)
            function.restype, function.argtypes = result, arguments
        self.callback = callback_type(self.log)
        self.engine = self.lib.msc_init()
        self.rules = None
        if not self.engine:
            raise MemoryError("reference initialization failed")
        try:
            self.identity = self.lib.msc_who_am_i(self.engine).decode()
            if not re.search(r"\bv3\.0\.14\b", self.identity):
                raise ValueError(f"unexpected reference: {self.identity}")
            self.lib.msc_set_log_cb(self.engine, self.callback)
            self.rules = self.lib.msc_create_rules_set()
            if not self.rules:
                raise MemoryError("reference rules allocation failed")
        except BaseException:
            self.close()
            raise

    def log(self, _data, message):
        # Never raise through a C callback. Report capacity failures afterwards.
        try:
            text = ctypes.string_at(message).decode(errors="replace")
            if len(self.messages) >= 8192 or len(text) > 65536:
                self.callback_error = True
            else:
                self.messages.append(text)
        except BaseException:
            self.callback_error = True

    def close(self):
        if self.rules:
            self.lib.msc_rules_cleanup(self.rules)
            self.rules = None
        if self.engine:
            self.lib.msc_cleanup(self.engine)
            self.engine = None

    def add(self, text=None, path=None):
        error = ctypes.c_char_p()
        if path is None:
            result = self.lib.msc_rules_add(self.rules, text.encode(), ctypes.byref(error))
        else:
            result = self.lib.msc_rules_add_file(self.rules, str(path).encode(),
                                                 ctypes.byref(error))
        if result < 0:
            raise ValueError(f"reference configuration refused: {error.value!r}")

    def evaluate(self, case):
        self.messages.clear()
        self.callback_error = False
        transaction = self.lib.msc_new_transaction_with_id(
            self.engine, self.rules, b"ftw-request", None)
        if not transaction:
            raise MemoryError("reference transaction allocation failed")
        try:
            checked(self.lib.msc_process_connection(transaction, b"127.0.0.1", 12345,
                                                     b"127.0.0.1", 80))
            checked(self.lib.msc_process_uri(transaction, case["target"].encode(),
                                             case["method"].encode(),
                                             case["protocol"].removeprefix("HTTP/").encode()))
            for header in case["headers"]:
                name, value = header["name"].encode(), header["value"].encode()
                checked(self.lib.msc_add_n_request_header(transaction, name, len(name),
                                                           value, len(value)))
            checked(self.lib.msc_process_request_headers(transaction))
            body = case["body"].encode()
            checked(self.lib.msc_append_request_body(transaction, body, len(body)))
            checked(self.lib.msc_process_request_body(transaction))
            if case.get("response"):
                self.response(transaction, case["response"])
            checked(self.lib.msc_process_logging(transaction))
            if self.callback_error:
                raise ValueError("reference log capacity or callback failure")
            ids = sorted({int(value) for message in self.messages
                          for value in re.findall(r'\[id "(\d+)"\]', message)})
            return dict(id=case["id"], error=None, ids=ids)
        finally:
            self.lib.msc_transaction_cleanup(transaction)

    def response(self, transaction, reply):
        for header in reply["headers"]:
            name, value = header["name"].encode(), header["value"].encode()
            checked(self.lib.msc_add_n_response_header(transaction, name, len(name),
                                                       value, len(value)))
        checked(self.lib.msc_process_response_headers(transaction, reply["status"], b"HTTP/1.1"))
        body = bytes.fromhex(reply["body_hex"])
        checked(self.lib.msc_append_response_body(transaction, body, len(body)))
        checked(self.lib.msc_process_response_body(transaction))


def checked(result):
    if result < 0:
        raise ValueError(f"reference transaction failed: {result}")


def materialize(data, manifest, root):
    wanted = {entry["path"]: entry for entry in manifest["files"]
              if entry["path"] == "crs-setup.conf.example" or
              (entry["path"].startswith("rules/") and
               entry["path"].endswith((".conf", ".data")))}
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            path = member.name.removeprefix("coreruleset-4.30.0/")
            if path not in wanted:
                continue
            entry = wanted[path]
            if not member.isfile() or member.size != entry["bytes"] or path in seen:
                raise ValueError("reference source member mismatch")
            content = archive.extractfile(member).read(member.size + 1)
            if hashlib.sha256(content).hexdigest() != entry["sha256"]:
                raise ValueError("reference source digest mismatch")
            target = root / path
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(content)
            seen.add(path)
    if seen != set(wanted):
        raise ValueError("reference source inventory mismatch")
    return sorted(root.glob("rules/*.conf"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--source-dir", type=Path, default=Path(".zig-cache/crs-review"))
    parser.add_argument("--select-failures", type=Path)
    parser.add_argument("--origin", help="loopback Albedo 0.3.0 fixture URL")
    parser.add_argument("--responses-only", action="store_true")
    parser.add_argument("--report", type=Path,
                        default=Path(".zig-cache/crs-review/ftw-reference.json"))
    args = parser.parse_args()
    origin = fixture_origin(args.origin, args.responses_only, parser)
    manifest = json.loads(Path("vendor/crs/provenance.json").read_text())
    cases, contracts, gaps = collect(source_bytes(args.source_dir, False),
                                    bool(origin), args.responses_only)
    if args.select_failures:
        selected = {item["test"] for item in json.loads(args.select_failures.read_text())["failures"]}
        cases = [case for case in cases if contracts[case["id"]]["test"] in selected]
        contracts = {case["id"]: contracts[case["id"]] for case in cases}
    for case in cases:
        if case.pop("response_case"):
            case["response"] = origin_reply(case, origin)
    reference = Reference(args.library)
    try:
        with tempfile.TemporaryDirectory(prefix="sibuna-crs-reference-") as temporary:
            root = Path(temporary)
            paths = materialize(archive_bytes(args.source_dir, manifest, False), manifest, root)
            reference.add(text=SETUP)
            reference.add(path=root / "crs-setup.conf.example")
            for path in paths:
                reference.add(path=path)
            rows = [dict(reference.evaluate(case), test=contracts[case["id"]]["test"])
                    for case in cases]
        report = dict(reference=reference.identity,
                      commit=COMMIT, source_sha256=SOURCE_DIGEST,
                      library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
                      evaluated=len(rows), failures=compare(rows, contracts), rows=rows,
                      coverage_gaps=gaps)
    finally:
        reference.close()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['reference']}: {len(rows)} evaluated, "
          f"{len(report['failures'])} upstream expectation mismatches. Report: {args.report}")


if __name__ == "__main__":
    main()
