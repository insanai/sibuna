#!/usr/bin/env python3
"""Check daemon corpus verdicts and transaction attribution without starting a daemon."""
import unittest

from crs_ftw_daemon_check import evaluate
from crs_ftw_daemon_verdict import verdict, failures


def test_case(name="942100-1", payload=b"GET / HTTP/1.1\r\n\r\n", response=False):
    stage = dict(payload=payload, expected=[942100], forbidden=[], status=None,
                 regex=False, expect_error=False)
    return dict(test=name, response=response, stages=[stage])


def result(name="942100-1", ids=None, status=200, origin=20, inbound=False):
    return dict(test=name, ids=ids or [], passed=False, leaked=False, gaps=[],
                missing=[942100], unexpected=[], errors=[], origin_bytes=origin,
                stages=[dict(status=status, origin_bytes=origin, request_denial=inbound)])


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


if __name__ == "__main__":
    unittest.main()
