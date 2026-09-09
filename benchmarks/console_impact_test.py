"""Acceptance math must reject missing subscribers and uncertain latency evidence."""
import unittest
import hashlib
from pathlib import Path
import tempfile
from unittest.mock import patch
from console_impact import summarize, verdict
from console_dashboard import covered, difference
from run import metadata


def samples(rates, latencies):
    return [{"requests_per_second": rate, "latency_us": {"p99": latency},
             "peak_rss_kib": 1, "errors": {}, "wall_seconds": 15, "dashboards": []}
            for rate, latency in zip(rates, latencies)]


class Acceptance(unittest.TestCase):
    def test_provenance_hashes_the_measured_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "measured"
            binary.write_bytes(b"actual measured artifact")
            with (patch("run.source_paths", return_value=[]),
                  patch("run.command", return_value="test")):
                result = metadata(binary)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            self.assertEqual(result["daemon_sha256"], digest)

    def test_both_confidence_intervals_must_pass(self):
        baseline = summarize(samples([1000] * 7, [100] * 7))
        passing = summarize(samples([995] * 7, [105] * 7))
        self.assertEqual(verdict(baseline, passing)["verdict"], "pass")
        failing = summarize(samples([995] * 7, [120] * 7))
        self.assertEqual(verdict(baseline, failing)["verdict"], "fail")
        uncertain = summarize(samples([995] * 7, [90, 90, 105, 105, 105, 120, 120]))
        result = verdict(baseline, uncertain)
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertGreater(result["bootstrap_ci_95_p99_increase"][1], 0.1)

    def test_short_or_noisy_runs_do_not_pass(self):
        short = summarize(samples([1000] * 2, [100] * 2))
        self.assertEqual(verdict(short, short)["verdict"], "inconclusive")
        noisy = summarize(samples([900, 1100, 1000, 1000, 1000], [100] * 5))
        self.assertEqual(verdict(noisy, noisy)["verdict"], "inconclusive")

    def test_coverage_is_checked_for_every_client(self):
        client = {"frames": 15, "rankings": 1, "timeline": 1,
                  "http_errors": 0, "stream_errors": 0}
        entry = {"wall_seconds": 15, "dashboards": [dict(client) for _ in range(8)]}
        self.assertTrue(covered([entry], 8))
        entry["dashboards"][0]["frames"] = 120
        entry["dashboards"][1]["frames"] = 0
        self.assertFalse(covered([entry], 8))
        entry["dashboards"][1]["frames"] = 15
        entry["dashboards"][7]["timeline"] = 0
        self.assertFalse(covered([entry], 8))
        self.assertEqual(difference([{"frames": 4}], [{"frames": 9}]), [{"frames": 5}])

    def test_transport_errors_cannot_pass(self):
        baseline = summarize(samples([1000] * 7, [100] * 7))
        entries = samples([1000] * 7, [100] * 7)
        for entry in entries:
            entry["errors"] = {"status": 100, "timeout": 0}
        self.assertEqual(verdict(baseline, summarize(entries))["verdict"], "pass")
        entries[2]["errors"]["timeout"] = 1
        self.assertEqual(verdict(baseline, summarize(entries))["verdict"], "inconclusive")

    def test_missing_measurements_are_inconclusive_without_dividing_by_zero(self):
        valid = summarize(samples([1000] * 7, [100] * 7))
        for rates, latency in (([0] * 7, [100] * 7), ([1000] * 7, [0] * 7),
                               ([float("nan")] * 7, [100] * 7)):
            invalid = summarize(samples(rates, latency))
            self.assertEqual(verdict(invalid, valid)["verdict"], "inconclusive")
            self.assertEqual(verdict(valid, invalid)["verdict"], "inconclusive")
        invalid = samples([1000] * 7, [100] * 7)
        invalid[0]["wall_seconds"] = 0
        self.assertEqual(verdict(valid, summarize(invalid))["verdict"], "inconclusive")
        self.assertFalse(covered(invalid, 8))


if __name__ == "__main__":
    unittest.main()
