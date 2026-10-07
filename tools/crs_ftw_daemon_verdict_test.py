#!/usr/bin/env python3
"""Check daemon corpus verdicts and transaction attribution without starting a daemon."""
import unittest
from copy import deepcopy

from crs_ftw_daemon_check import evaluate
from crs_ftw_daemon_verdict import CRS_ARCHIVE_SHA256, verdict, failures


def test_case(name="942100-1", payload=b"GET / HTTP/1.1\r\n\r\n", response=False):
    stage = dict(payload=payload, expected=[942100], forbidden=[], status=None,
                 regex=False, expect_error=False)
    return dict(test=name, response=response, stages=[stage])


def result(name="942100-1", ids=None, status=200, origin=20, inbound=False):
    return dict(test=name, ids=ids or [], passed=False, leaked=False, gaps=[],
                missing=[942100], unexpected=[], errors=[], origin_bytes=origin,
                stages=[dict(status=status, origin_bytes=origin, request_denial=inbound)])


def work_fixture(mode="audit"):
    payload = (b"POST /post HTTP/1.1\r\n"
               b"Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,"
               b"text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
               b"Accept-Encoding: gzip,deflate\r\nAccept-Language: en-us,en;q=0.5\r\n"
               b"Content-Length: 64005\r\nContent-Type: application/x-www-form-urlencoded\r\n"
               b"Host: localhost\r\nKeep-Alive: 300\r\nProxy-Connection: keep-alive\r\n"
               b"User-Agent: OWASP CRS test agent\r\nConnection: close\r\n\r\n"
               b"foo=" + b"1" * 64001)
    test = test_case("920390-1", payload)
    test["stages"][0]["expected"] = [920390]
    enforcing = mode == "enforce"
    origin = 0 if enforcing else len(payload) + 82
    row = result(test["test"], [920370, 920390], 403 if enforcing else 200, origin)
    row.update(missing=[], passed=True)
    row["stages"][0]["findings"] = [dict(rule_id=identifier, phase=2,
        coverage="incomplete", enforcing=enforcing, denied=False, would_deny=False,
        selected_status=0, blocking_paranoia=4, detection_paranoia=4,
        source_digest=CRS_ARCHIVE_SHA256) for identifier in row["ids"]]
    engine = {test["test"]: dict(error="WorkLimit", work=127_864_803, ids=row["ids"])}
    return test, row, engine


def acquisition_fixture(mode="audit", ids=None):
    identifiers = [920470] if ids is None else ids
    test = test_case("920470-1")
    enforcing = mode == "enforce"
    row = result(test["test"], identifiers, 403 if enforcing else 200,
                 0 if enforcing else 100)
    row.update(missing=[], passed=True)
    row["stages"][0]["findings"] = [dict(rule_id=identifier, phase=1,
        coverage="incomplete", enforcing=enforcing, denied=False, would_deny=False,
        selected_status=0, blocking_paranoia=4, detection_paranoia=4,
        source_digest=CRS_ARCHIVE_SHA256) for identifier in identifiers]
    engine = {test["test"]: dict(error="InvalidMime", work=100, ids=identifiers)}
    return test, row, engine


class VerdictTest(unittest.TestCase):
    def decision(self, test, row, engine=None, independent=None, mode="audit"):
        return verdict(test, row, engine or {}, independent or {}, 128_000_000, mode)

    def test_missing_reference_and_work_exhaustion_fail(self):
        row = result()
        self.assertEqual(self.decision(test_case(), row), "missing engine evidence")
        engine = {row["test"]: dict(error="WorkLimit", work=128_000_001, ids=[])}
        self.assertEqual(self.decision(test_case(), row, engine), "work budget")
        self.assertEqual(self.decision(test_case(), dict(row, passed=True), engine), "work budget")
        for value in ("missing engine evidence", "work budget", "connector difference"):
            self.assertEqual(len(failures([dict(row, **{"class": value})])), 1)

    def test_independent_ids_must_match(self):
        row = result(ids=[942110])
        engine = {row["test"]: dict(error=None, work=20, ids=[942110])}
        self.assertEqual(self.decision(test_case(), row, engine), "missing independent evidence")
        independent = {row["test"]: dict(error=None, ids=[942120])}
        self.assertEqual(self.decision(test_case(), row, engine, independent),
                         "connector difference")
        independent[row["test"]]["ids"] = [942110]
        self.assertEqual(self.decision(test_case(), row, engine, independent), "reference agrees")

    def test_deliberate_refusal_requires_shape_status_and_empty_origin(self):
        test = test_case("920100-4", b"CONNECT 1.2.3.4:80 HTTP/1.1\r\n\r\n")
        row = result(test["test"], status=400, origin=0)
        self.assertEqual(self.decision(test, row), "deliberate connector refusal")
        self.assertEqual(self.decision(test, dict(row, origin_bytes=1)), "missing engine evidence")
        self.assertEqual(self.decision(test_case("920100-4"), row), "missing engine evidence")
        self.assertEqual(self.decision(test, result(test["test"], status=200, origin=0)),
                         "missing engine evidence")

    def test_response_preemption_requires_request_denial_and_no_origin(self):
        test = test_case(response=True)
        row = result(status=403, origin=0, inbound=True)
        self.assertEqual(self.decision(test, row, mode="enforce"),
                         "response preempted by request denial")
        row["stages"][0]["origin_bytes"] = 1
        self.assertEqual(self.decision(test, row, mode="enforce"), "missing engine evidence")

    def test_regex_gap_is_not_a_complete_contract(self):
        row = dict(result(), passed=True, gaps=["regex log assertion"])
        self.assertEqual(self.decision(test_case(), row), "log coverage gap")

    def test_findings_do_not_cross_stage_boundaries(self):
        test = test_case()
        test["stages"].append(dict(test["stages"][0], expected=[942110]))
        row = dict(test="942100-1", origin_bytes=40, stages=[
            dict(status=200, error=None, origin_bytes=20),
            dict(status=200, error=None, origin_bytes=20)])
        finding = dict(rule_id=942100, phase=2, would_deny=False)
        observed = [[finding, dict(finding, rule_id=942110)], []]
        self.assertEqual(evaluate(test, row, observed)["missing"], [942110])

    def test_response_finding_cannot_mask_request_leak(self):
        test = test_case()
        row = dict(test="942100-1", origin_bytes=20,
                   stages=[dict(status=403, error=None, origin_bytes=20)])
        observed = [[dict(rule_id=942100, phase=2, would_deny=True),
                     dict(rule_id=950100, phase=4, would_deny=True)]]
        self.assertTrue(evaluate(test, row, observed)["leaked"])

    def test_exact_audit_work_refusal_is_visible_and_not_a_complete_contract(self):
        test, row, engine = work_fixture()
        self.assertEqual(self.decision(test, row, engine), "bounded work refusal")
        self.assertEqual(failures([dict(row, **{"class": "bounded work refusal"})]), [])

    def test_exact_enforcing_work_refusal_delivers_nothing(self):
        test, row, engine = work_fixture("enforce")
        self.assertEqual(self.decision(test, row, engine, mode="enforce"), "bounded work refusal")

    def test_work_refusal_never_accepts_changed_payload_or_ambiguous_headers(self):
        test, row, engine = work_fixture()
        payload = test["stages"][0]["payload"]
        for changed in (payload[:-1] + b"2", payload.replace(b"64005", b"64004"),
                        payload.replace(b"Host:", b"Content-Length: 64005\r\nHost:")):
            altered = deepcopy(test)
            altered["stages"][0]["payload"] = changed
            self.assertEqual(self.decision(altered, row, engine), "work budget")

    def test_work_refusal_requires_the_actual_mode_status(self):
        for mode in ("audit", "enforce"):
            test, row, engine = work_fixture(mode)
            row["stages"][0]["status"] = 403 if mode == "audit" else 200
            self.assertEqual(self.decision(test, row, engine, mode=mode), "work budget")

    def test_complete_coverage_cannot_hide_a_work_refusal(self):
        test, row, engine = work_fixture()
        row["stages"][0]["findings"][0]["coverage"] = "inspected"
        self.assertEqual(self.decision(test, row, engine), "work budget")

    def test_work_refusal_cannot_waive_an_enforcing_origin_leak(self):
        test, row, engine = work_fixture("enforce")
        row.update(leaked=True, origin_bytes=1)
        row["stages"][0]["origin_bytes"] = 1
        self.assertEqual(self.decision(test, row, engine, mode="enforce"), "origin boundary")

    def test_work_refusal_requires_all_findings_and_the_reviewed_profile(self):
        test, original, engine = work_fixture()
        for field, value in (("missing", [920390]), ("unexpected", [942100]),
                             ("errors", ["console evidence page unavailable"]),
                             ("gaps", ["regex log assertion"])):
            row = dict(original, **{field: value})
            self.assertEqual(self.decision(test, row, engine), "work budget")
        for field, value in (("blocking_paranoia", 1), ("enforcing", True),
                             ("source_digest", "00" * 32), ("denied", True)):
            row = deepcopy(original)
            row["stages"][0]["findings"][0][field] = value
            self.assertEqual(self.decision(test, row, engine), "work budget")
        self.assertEqual(verdict(test, original, engine, {}, 16_000_000, "audit"), "work budget")
        changed = deepcopy(test)
        changed["test"] = "920390-2"
        row = dict(original, test=changed["test"])
        self.assertEqual(self.decision(changed, row, {row["test"]: engine[test["test"]]}),
                         "work budget")

    def test_matching_ids_do_not_hide_incomplete_acquisition(self):
        for mode in ("audit", "enforce"):
            test, row, engine = acquisition_fixture(mode)
            self.assertEqual(self.decision(test, row, engine, mode=mode), "engine refusal")

    def test_empty_findings_do_not_complete_native_acquisition_refusal(self):
        for mode in ("audit", "enforce"):
            test, row, engine = acquisition_fixture(mode, [])
            self.assertEqual(self.decision(test, row, engine, mode=mode), "engine refusal")

    def test_unknown_incomplete_inspection_is_not_a_pass(self):
        test, row, engine = acquisition_fixture()
        engine[test["test"]]["error"] = None
        self.assertEqual(self.decision(test, row, engine), "incomplete inspection")
        self.assertEqual(len(failures([dict(row, **{"class": "incomplete inspection"})])), 1)

    def test_acquisition_refusal_requires_identical_native_ids(self):
        test, row, engine = acquisition_fixture()
        engine[test["test"]]["ids"] = []
        self.assertEqual(self.decision(test, row, engine), "incomplete inspection")

    def test_acquisition_refusal_preserves_enforcing_delivery_boundary(self):
        test, original, engine = acquisition_fixture("enforce")
        for status, origin in ((200, 0), (403, 1)):
            row = deepcopy(original)
            row["origin_bytes"] = origin
            row["stages"][0].update(status=status, origin_bytes=origin)
            self.assertEqual(self.decision(test, row, engine, mode="enforce"),
                             "incomplete inspection")

    def test_acquisition_refusal_requires_honest_finding_state(self):
        test, original, engine = acquisition_fixture()
        for field, value in (("enforcing", True), ("denied", True), ("would_deny", True),
                             ("selected_status", 403), ("blocking_paranoia", 1),
                             ("source_digest", "00" * 32)):
            row = deepcopy(original)
            row["stages"][0]["findings"][0][field] = value
            self.assertEqual(self.decision(test, row, engine), "incomplete inspection")

    def test_complete_early_denial_is_not_an_acquisition_refusal(self):
        test, row, engine = acquisition_fixture("enforce")
        row["stages"][0]["findings"][0].update(coverage="local_response", denied=True,
                                                 would_deny=True, selected_status=403)
        self.assertEqual(self.decision(test, row, engine, mode="enforce"), "passed")


if __name__ == "__main__":
    unittest.main()
