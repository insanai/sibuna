"""Verify diagnostic ancestry excludes unrelated processes."""
import unittest
from native_test_diagnostic import owned_rows


class Ownership(unittest.TestCase):
    def test_unsorted_descendants_exclude_unrelated_tests(self):
        rows = [(13, 12, "1", "00:01", "/owned/test"),
                (41, 40, "1", "00:01", "/unrelated/test"),
                (12, 10, "1", "00:01", "/owned/maker"),
                (40, 1, "1", "00:01", "/unrelated/zig"),
                (10, 1, "1", "00:01", "/owned/zig")]
        self.assertEqual({r[0] for r in owned_rows(rows, 10)}, {10, 12, 13})

    def test_absent_root_does_not_adopt_an_unrelated_tree(self):
        rows = [(41, 40, "1", "00:01", "/unrelated/test"),
                (40, 1, "1", "00:01", "/unrelated/zig")]
        self.assertEqual(owned_rows(rows, 10), [])


if __name__ == "__main__":
    unittest.main()
