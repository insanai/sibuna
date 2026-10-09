#!/usr/bin/env python3
"""Prevent native OpenBSD archives from being indexed as Helm charts."""
import unittest
from build_chart_repository import chart_names


def release(tag, *names):
    return {'tag_name': tag, 'assets': [{'name': name} for name in names]}


class ChartSelectionTests(unittest.TestCase):
    def test_native_archive_and_helm_chart_have_separate_roles(self):
        self.assertEqual(chart_names(release('v0.3.5', 'sibuna-0.3.5.tgz',
                                            'helm-sibuna-0.3.5.tgz')),
                         ['helm-sibuna-0.3.5.tgz'])
        with self.assertRaises(ValueError):
            chart_names(release('v0.3.5', 'sibuna-0.3.5.tgz'))

    def test_legacy_chart_releases_are_retained(self):
        self.assertEqual(chart_names(release('helm-v0.3.3', 'sibuna-0.3.3.tgz')),
                         ['sibuna-0.3.3.tgz'])
        self.assertEqual(chart_names(release('v0.3.3', 'sibuna-linux-amd64.tar.gz')), [])

    def test_ambiguous_chart_release_is_refused(self):
        with self.assertRaises(ValueError):
            chart_names(release('helm-v0.3.5', 'sibuna-0.3.5.tgz',
                                'helm-sibuna-0.3.5.tgz'))


if __name__ == '__main__':
    unittest.main()
