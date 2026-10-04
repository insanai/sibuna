#!/usr/bin/env python3
"""Benchmark validation must distinguish expected denials from invalid measurements."""
import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bunkerweb import validate_measured
from process_accounting import parse_stat, snapshot
from bunkerweb_image import Registry, digest


class ValidationTests(unittest.TestCase):
    def test_cached_image_blobs_still_require_a_valid_digest_and_declared_size(self):
        registry = object.__new__(Registry)
        registry.open = lambda kind, reference: io.BytesIO(b"abcd")
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            with self.assertRaises(ValueError):
                registry.blob({"digest": "sha256:" + "g" * 64, "size": 4}, directory)
            reference = digest(b"abcd")
            (directory / reference[7:]).write_bytes(b"abcd")
            registry.blob({"digest": reference, "size": 4}, directory)
            with self.assertRaises(ValueError):
                registry.blob({"digest": reference, "size": 3}, directory)
            self.assertFalse(list(directory.glob("*.partial")))

    def test_expected_denial_is_valid_but_mixed_or_empty_responses_are_not(self):
        result = {"requests": 100, "statuses": {"403": 100},
                  "errors": {"connect": 0, "read": 0, "write": 0,
                             "status": 100, "timeout": 0}}
        validate_measured(result, 403)
        for statuses, requests in (({"403": 99, "200": 1}, 100), ({}, 0),
                                    ({"403": 99}, 100)):
            with self.assertRaises(ValueError):
                validate_measured({**result, "statuses": statuses, "requests": requests}, 403)
        for key, value in (("read", 1), ("status", 99)):
            failed = copy.deepcopy(result)
            failed["errors"][key] = value
            with self.assertRaises(ValueError):
                validate_measured(failed, 403)

    def test_proc_reader_tolerates_a_process_exiting_during_stat_read(self):
        fields = ["S", "7", *(["0"] * 9), "21", "13", "900", "800",
                  *(["0"] * 6), "42"]
        text = "100 (product) " + " ".join(fields)
        with patch.object(Path, "iterdir", return_value=[Path("/proc/100"), Path("/proc/900")]):
            with patch.object(Path, "read_text", side_effect=[text, ProcessLookupError()]):
                self.assertEqual(snapshot(100)["pids"], [100])
        with patch.object(Path, "iterdir", return_value=[]):
            with self.assertRaises(ProcessLookupError):
                snapshot(100)

    def test_cpu_accounting_excludes_child_time_and_handles_parentheses_in_names(self):
        # Fields 14/15 are own ticks, 16/17 child ticks; field 24 is resident pages.
        fields = ["S", "7", *(["0"] * 9), "21", "13", "900", "800",
                  *(["0"] * 6), "42"]
        self.assertEqual(parse_stat("123 (nginx (worker)) " + " ".join(fields)),
                         {"parent": 7, "cpu_ticks": 34, "rss_pages": 42})


if __name__ == "__main__":
    unittest.main()
