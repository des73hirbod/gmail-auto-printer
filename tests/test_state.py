"""Durable claim and crash recovery must prevent a second submission."""
import importlib
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    state = importlib.import_module('state_store')
except ImportError:
    state = None


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / 'state.sqlite3'
        self.addCleanup(self.temp.cleanup)

    def require_state(self):
        self.assertIsNotNone(state, 'durable state store is required')

    def test_unique_claim_is_atomic_and_survives_restart(self):
        self.require_state()
        with state.StateStore(self.db) as store:
            self.assertTrue(store.claim('message', 'root.0'))
            self.assertFalse(store.claim('message', 'root.0'))
            store.transition('message', 'root.0', 'VALIDATED')
            store.transition('message', 'root.0', 'READY')
            store.transition('message', 'root.0', 'SUBMISSION_ATTEMPTED')
            store.transition('message', 'root.0', 'SUBMITTED')
        with state.StateStore(self.db) as store:
            self.assertFalse(store.claim('message', 'root.0'))
            self.assertEqual(store.get('message', 'root.0')['status'], 'SUBMITTED')

    def test_only_pre_submission_states_resume_after_restart(self):
        self.require_state()
        with state.StateStore(self.db) as store:
            for part, terminal in [('a', 'QUEUED'), ('b', 'VALIDATED'), ('c', 'READY')]:
                store.claim('m', part)
                if terminal != 'QUEUED':
                    store.transition('m', part, 'VALIDATED')
                if terminal == 'READY':
                    store.transition('m', part, 'READY')
        with state.StateStore(self.db) as store:
            for part in ['a', 'b', 'c']:
                self.assertTrue(store.claim('m', part))
                self.assertEqual(store.get('m', part)['status'], 'QUEUED')

    def test_crash_after_durable_attempt_becomes_unknown(self):
        self.require_state()
        with state.StateStore(self.db) as store:
            store.claim('m', 'a')
            store.transition('m', 'a', 'VALIDATED')
            store.transition('m', 'a', 'READY')
            store.transition('m', 'a', 'SUBMISSION_ATTEMPTED')
        with state.StateStore(self.db) as store:
            self.assertEqual(store.get('m', 'a')['status'], 'UNKNOWN')
            self.assertFalse(store.claim('m', 'a'))

    def test_process_death_preserves_durable_attempt_and_releases_os_lock(self):
        self.require_state()
        code = ('import os,sys; from state_store import StateStore\n'
                's=StateStore(sys.argv[1]); s.claim("m","a")\n'
                's.transition("m","a","VALIDATED")\n'
                's.transition("m","a","READY")\n'
                's.transition("m","a","SUBMISSION_ATTEMPTED")\n'
                'os._exit(19)')
        result = subprocess.run([sys.executable, '-c', code, str(self.db)],
                                cwd=Path(__file__).resolve().parents[1], capture_output=True)
        self.assertEqual(result.returncode, 19, result.stderr.decode())
        with state.StateStore(self.db) as store:
            self.assertEqual(store.get('m', 'a')['status'], 'UNKNOWN')
            self.assertFalse(store.claim('m', 'a'))

    def test_invalid_transition_cannot_erase_submission(self):
        self.require_state()
        with state.StateStore(self.db) as store:
            store.claim('m', 'a')
            with self.assertRaises(state.StateStoreError):
                store.transition('m', 'a', 'SUBMITTED')

    def test_corrupt_state_fails_closed_without_overwriting(self):
        self.require_state()
        self.db.write_bytes(b'not a sqlite database')
        with self.assertRaises(state.StateStoreError):
            state.StateStore(self.db)
        self.assertEqual(self.db.read_bytes(), b'not a sqlite database')

    def test_state_and_lock_reparse_points_are_rejected_before_open(self):
        self.require_state()
        # lstat is the OS boundary: Windows marks junctions and file links using
        # REPARSE_POINT even when is_symlink alone does not recognize them.
        real_lstat = Path.lstat
        for blocked in (self.db, self.db.with_name(self.db.name + '.lock')):
            def reparse(path, *args, **kwargs):
                if path == blocked:
                    return type('Attributes', (), {'st_mode': stat.S_IFREG,
                        'st_file_attributes': getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024)})()
                return real_lstat(path, *args, **kwargs)
            with self.subTest(path=blocked.name), mock.patch.object(Path, 'lstat', reparse):
                with self.assertRaises(state.StateStoreError):
                    with state.StateStore(self.db):
                        pass

    def test_actual_database_symlink_is_rejected_and_target_unchanged(self):
        self.require_state()
        target = Path(self.temp.name) / 'target.sqlite3'
        with state.StateStore(target):
            pass
        original = target.read_bytes()
        try:
            os.symlink(target, self.db)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('OS does not permit symlink creation: ' + type(exc).__name__)
        with self.assertRaises(state.StateStoreError):
            with state.StateStore(self.db):
                pass
        self.assertEqual(target.read_bytes(), original)

    def test_second_process_cannot_recover_active_operation(self):
        self.require_state()
        with state.StateStore(self.db) as store:
            store.claim('m', 'a')
            store.transition('m', 'a', 'VALIDATED')
            store.transition('m', 'a', 'READY')
            store.transition('m', 'a', 'SUBMISSION_ATTEMPTED')
            code = ('import sys; from state_store import StateStore, StateStoreError\n'
                    'try:\n StateStore(sys.argv[1])\n'
                    'except StateStoreError:\n sys.exit(17)\n'
                    'sys.exit(0)')
            result = subprocess.run([sys.executable, '-c', code, str(self.db)],
                                    cwd=Path(__file__).resolve().parents[1], capture_output=True)
            self.assertEqual(result.returncode, 17, result.stderr.decode())
            self.assertEqual(store.get('m', 'a')['status'], 'SUBMISSION_ATTEMPTED')
