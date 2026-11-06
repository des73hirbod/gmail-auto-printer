"""The accepted print command cannot grow through fuzzy or ignored tokens."""
import importlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    handler = importlib.import_module('attachment_handler')
except ImportError:
    handler = None


class SubjectTests(unittest.TestCase):
    def test_exact_commands_and_defaults(self):
        self.assertIsNotNone(handler, 'PDF handler must import without conversion dependencies')
        for subject, expected in [
            ('print', {'copies': 1, 'duplex': False}),
            ('PRINT 2 copies duplex', {'copies': 2, 'duplex': True}),
            (' print 3 simplex ', {'copies': 3, 'duplex': False}),
            ('print duplex', {'copies': 1, 'duplex': True}),
        ]:
            with self.subTest(subject=subject):
                self.assertEqual(handler.parse_print_subject(subject, max_copies=3), expected)

    def test_invalid_commands_never_fall_back(self):
        self.assertIsNotNone(handler, 'PDF handler must import without conversion dependencies')
        for subject in ['', None, 'please print', 'prnt', 'print now', 'print 0',
                        'print 4', 'print -1', 'print 2 3', 'print two', 'print 2copies',
                        'print copies', 'print 2 copies copies', 'print duplex duplex',
                        'print simplex duplex', 'print duplex 2', 'print 2!',
                        'print\n2', 'print ٢', 'prınt', 'prİnt', 'print ſimplex',
                        'print 9999999999999999999999999999999']:
            with self.subTest(subject=subject):
                self.assertIn('error', handler.parse_print_subject(subject, max_copies=3))

    def test_default_copy_count_is_one_even_with_legacy_default(self):
        self.assertIsNotNone(handler, 'PDF handler must import without conversion dependencies')
        self.assertEqual(handler.parse_print_subject('print', default_copies=5)['copies'], 1)
