#!/usr/bin/env python3
"""A recovery must fail closed for a missing, repeated or unsuccessful original gate."""
import unittest

from check_release_recovery import require_gates
from release_targets import PLATFORMS


class RecoveryGateTest(unittest.TestCase):
    def setUp(self):
        names = ['distribution-source', 'crs-conformance', 'crs-console', 'container-and-chart',
                 'bsd-freebsd', 'bsd-openbsd']
        names += [f'build ({p["runner"]}, {p["package"]}, {p["target"]})' for p in PLATFORMS]
        names += [f'native-packages ({p["runner"]}, {p["package"]}, {p["target"]})'
                  for p in PLATFORMS if p['package'].startswith('linux-')]
        self.jobs = [{'name': name, 'conclusion': 'success'} for name in names]

    def test_every_original_gate_is_required(self):
        require_gates(self.jobs)
        for index in range(len(self.jobs)):
            with self.subTest(gate=self.jobs[index]['name']):
                with self.assertRaises(ValueError):
                    require_gates(self.jobs[:index] + self.jobs[index + 1:])
                for outcome in ('failure', 'cancelled', 'skipped', None):
                    altered = [dict(j) for j in self.jobs]
                    altered[index]['conclusion'] = outcome
                    with self.assertRaises(ValueError):
                        require_gates(altered)

    def test_duplicate_gate_is_rejected(self):
        with self.assertRaises(ValueError):
            require_gates(self.jobs + [self.jobs[0]])

    def test_source_only_never_accepts_failed_source(self):
        require_gates([self.jobs[0]], source_only=True)
        with self.assertRaises(ValueError):
            require_gates([], source_only=True)


if __name__ == '__main__':
    unittest.main()
