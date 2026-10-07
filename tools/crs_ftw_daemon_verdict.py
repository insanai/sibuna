"""Explicit compatibility exceptions for the pinned actual-daemon FTW qualification.

An exception must explain this transaction, not merely its rule family or HTTP status.
Unknown failures, missing oracle evidence, and work exhaustion fail qualification.
"""
from collections import Counter

ACQUISITION_ERRORS = {"InvalidPercentEscape", "InvalidMime", "MultipartHeadLimit",
                      "AmbiguousBodyParameter", "InvalidXml", "InvalidMultipartHead",
                      "AcquisitionEntryLimit", "InvalidJson", "MultipartMissingClose"}


def connector_refusal(test, result):
    if len(test["stages"]) != 1 or result["ids"] or result["origin_bytes"]:
        return False
    if result["stages"][0]["status"] != 400:
        return False
    payload = test["stages"][0]["payload"]
    line = payload.partition(b"\r\n")[0]
    shapes = {
        "920100-4": line == b"CONNECT 1.2.3.4:80 HTTP/1.1",
        "920100-16": line == b"GET http://localhost HTTP/1.1",
        "920181-1": b"\r\nContent-Length: 7\r\n" in payload and
            b"\r\nTransfer-Encoding: chunked\r\n" in payload,
        "920430-5": line == b"GET / ",
        "920430-8": line == b"GET / HTTP/4.0",
    }
    return shapes.get(test["test"], False)


def request_refused(result):
    return all(stage["status"] == 403 and stage["origin_bytes"] == 0 and
               stage["request_denial"] for stage in result["stages"])


def semantic_refusal(test, result):
    # This fixture requires two conflicting representation declarations to pass.
    # Our enforcing profile refuses ambiguous acquisition before forwarding it.
    if test["test"] != "920620-1" or len(test["stages"]) != 1:
        return False
    payload = test["stages"][0]["payload"]
    return b"\r\nContent-Type: application/json\r\nContent-Type: application/xml\r\n" \
        in payload and not result["ids"] and result["origin_bytes"] == 0 and \
        result["stages"][0]["status"] == 403


def status_errors_only(result):
    return all(error.startswith("status 403 not in [") for error in result["errors"])


def verdict(test, result, engine, independent, budget, mode):
    if result["leaked"]:
        return "origin boundary"
    reference = engine.get(result["test"])
    if reference is not None and (reference["work"] > budget or
                                  reference["error"] == "WorkLimit"):
        return "work budget"
    if result["passed"]:
        return "log coverage gap" if result["gaps"] else "passed"
    if connector_refusal(test, result):
        return "deliberate connector refusal"
    if mode == "enforce" and not result["unexpected"] and status_errors_only(result):
        if test["response"] and request_refused(result):
            return "response preempted by request denial"
        if semantic_refusal(test, result):
            return "deliberate acquisition refusal"
    if reference is None:
        return "missing engine evidence"
    if reference["error"] in ACQUISITION_ERRORS and not result["ids"]:
        if not result["errors"] and mode == "audit":
            return "engine refusal"
        if mode == "enforce" and status_errors_only(result) and all(
                row["status"] == 403 and row["origin_bytes"] == 0
                for row in result["stages"]):
            return "engine refusal"
    oracle = independent.get(result["test"])
    if oracle is None:
        return "missing independent evidence"
    ids = sorted(reference["ids"])
    if reference["error"] is None and oracle["error"] is None and \
            ids == sorted(oracle["ids"]) == result["ids"]:
        if not result["errors"]:
            return "reference agrees"
        if mode == "enforce" and not result["missing"] and not result["unexpected"] and \
                status_errors_only(result) and request_refused(result):
            return "enforce disruption"
    return "connector difference"


def classify(tests, results, engine, independent, budget, mode):
    if len(tests) != len(results):
        raise ValueError("daemon result inventory mismatch")
    for test, result in zip(tests, results):
        if test["test"] != result["test"]:
            raise ValueError("daemon result order mismatch")
        result["class"] = verdict(test, result, engine, independent, budget, mode)
    return Counter(result["class"] for result in results)


def failures(results):
    accepted = {"passed", "log coverage gap", "deliberate connector refusal",
                "deliberate acquisition refusal", "response preempted by request denial",
                "engine refusal", "reference agrees", "enforce disruption"}
    return [row for row in results if row["class"] not in accepted]
