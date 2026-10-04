#!/usr/bin/env python3
"""Benchmark validation must distinguish expected denials from invalid measurements."""
import copy
import unittest

from bunkerweb import validate_measured
from process_accounting import parse_stat


class ValidationTests(unittest.TestCase):
    def test_expected_denial_is_valid_but_mixed_or_empty_responses_are_not(self):
        result = {"requests": 100, "statuses": {"403": 100},
                  "errors": {"connect": 0, "read": 0, "write": 0,
                             "status": 100, "timeout": 0}}
        validate_measured(result, 403)
        for statuses, requests in (({"403": 99, "200": 1}, 100), ({}, 0),
                                    ({"403": 99}, 100)):
            with self.assertRaises(ValueError):
                validate_measured({**result, "statuses": statuses, "requests": requests}, 403)
        failed = copy.deepcopy(result)
        failed["errors"]["read"] = 1
        with self.assertRaises(ValueError):
            validate_measured(failed, 403)

    def test_cpu_accounting_excludes_child_time_and_handles_parentheses_in_names(self):
        # Fields 14/15 are own ticks, 16/17 child ticks; field 24 is resident pages.
        fields = ["S", "7", *(["0"] * 9), "21", "13", "900", "800",
                  *(["0"] * 6), "42"]
        self.assertEqual(parse_stat("123 (nginx (worker)) " + " ".join(fields)),
                         {"parent": 7, "cpu_ticks": 34, "rss_pages": 42})


if __name__ == "__main__":
    unittest.main()
