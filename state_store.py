"""Single-owner durable per-MIME-part ledger; interrupted attempts are UNKNOWN."""
import os
import sqlite3
import stat
import threading
from pathlib import Path


class StateStoreError(RuntimeError):
    """Untrusted or unavailable state must stop processing."""


class StateStore:
    SAFE_TO_RESUME = {'QUEUED', 'VALIDATED', 'READY'}
    TERMINAL = {'SUBMITTED', 'UNKNOWN', 'FAILED', 'SKIPPED'}
    TRANSITIONS = {
        'QUEUED': {'VALIDATED', 'FAILED', 'SKIPPED'},
        'VALIDATED': {'READY', 'FAILED', 'SKIPPED'},
        'READY': {'SUBMISSION_ATTEMPTED', 'FAILED', 'SKIPPED'},
        'SUBMISSION_ATTEMPTED': {'SUBMITTED', 'UNKNOWN', 'FAILED'},
    }

    def __init__(self, database_path):
        # abspath does not follow an existing database/ancestor symlink.
        self.path = Path(os.path.abspath(database_path))
        self._lock_file = self._connection = None
        self._mutex = threading.RLock()
        self._claimed = set()
        self._closed = False
        try:
            self._reject_links(self.path)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._reject_links(self.path)
            self._acquire_lock()
            existed = self.path.exists()
            if existed and self.path.stat().st_size == 0:
                raise StateStoreError('Existing state is empty; manual recovery required')
            self._connection = sqlite3.connect(self.path, timeout=0, check_same_thread=False)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute('PRAGMA synchronous=FULL')
            if self._connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise StateStoreError('State integrity check failed')
            version = self._connection.execute('PRAGMA user_version').fetchone()[0]
            if not existed:
                with self._connection:
                    self._connection.execute('''CREATE TABLE operations (
                        message_id TEXT NOT NULL, part_id TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (status IN ('QUEUED','VALIDATED','READY',
                        'SUBMISSION_ATTEMPTED','SUBMITTED','UNKNOWN','FAILED','SKIPPED')),
                        detail TEXT NOT NULL DEFAULT '',
                        artifact_path TEXT NOT NULL DEFAULT '',
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (message_id, part_id))''')
                    self._connection.execute('PRAGMA user_version=1')
            elif version != 1:
                raise StateStoreError('Unsupported schema; manual migration required')
            columns = {r['name'] for r in self._connection.execute('PRAGMA table_info(operations)')}
            if columns != {'message_id', 'part_id', 'status', 'detail', 'artifact_path', 'updated_at'}:
                raise StateStoreError('Invalid state schema')
            valid = self.SAFE_TO_RESUME | self.TERMINAL | {'SUBMISSION_ATTEMPTED'}
            for row in self._connection.execute('SELECT message_id, part_id, status FROM operations'):
                self._identity(row['message_id'], row['part_id'])
                if row['status'] not in valid:
                    raise StateStoreError('Invalid state record')
            # Recovery is permitted only after acquiring the lifetime OS lock.
            with self._connection:
                self._connection.execute("UPDATE operations SET status='UNKNOWN', "
                    "detail='interrupted_submission_requires_reconciliation', updated_at=CURRENT_TIMESTAMP "
                    "WHERE status='SUBMISSION_ATTEMPTED'")
                self._connection.execute("UPDATE operations SET status='QUEUED', "
                    "updated_at=CURRENT_TIMESTAMP WHERE status IN ('VALIDATED','READY')")
        except Exception as exc:
            self.close()
            if isinstance(exc, StateStoreError):
                raise
            raise StateStoreError('State initialization failed; processing disabled') from exc

    def _acquire_lock(self):
        lock_path = self.path.with_name(self.path.name + '.lock')
        self._reject_links(lock_path)
        self._lock_file = open(lock_path, 'a+b')
        self._reject_links(lock_path)
        self._lock_file.seek(0, os.SEEK_END)
        if not self._lock_file.tell():
            self._lock_file.write(b'\0')
            self._lock_file.flush()
        self._lock_file.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise StateStoreError('State is already owned by another process') from exc

    @staticmethod
    def _reject_links(path):
        for candidate in (path, *path.parents):
            try:
                attributes = candidate.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(attributes.st_mode) or getattr(attributes, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024):
                raise StateStoreError('State paths must not contain links or reparse points')
        if path.exists() and not path.is_file():
            raise StateStoreError('State and lock paths must be regular files')

    @staticmethod
    def _identity(message_id, part_id):
        if any(not isinstance(v, str) or not v or len(v) > 1024 for v in (message_id, part_id)):
            raise StateStoreError('Invalid operation identity')

    def _ensure_open(self):
        if self._closed or self._connection is None:
            raise StateStoreError('State store is closed')

    def claim(self, message_id, part_id):
        """Claim once in this process; only never-attempted rows can resume."""
        self._identity(message_id, part_id)
        with self._mutex:
            self._ensure_open()
            key = (message_id, part_id)
            if key in self._claimed:
                return False
            try:
                with self._connection:
                    self._connection.execute('INSERT OR IGNORE INTO operations '
                        '(message_id,part_id,status) VALUES (?, ?, ?)', (*key, 'QUEUED'))
                    row = self._connection.execute('SELECT status FROM operations '
                        'WHERE message_id=? AND part_id=?', key).fetchone()
                    if row['status'] not in self.SAFE_TO_RESUME:
                        return False
                self._claimed.add(key)
                return True
            except sqlite3.Error as exc:
                raise StateStoreError('Durable claim failed') from exc

    def get(self, message_id, part_id):
        self._identity(message_id, part_id)
        with self._mutex:
            self._ensure_open()
            try:
                row = self._connection.execute('SELECT * FROM operations WHERE '
                    'message_id=? AND part_id=?', (message_id, part_id)).fetchone()
                return dict(row) if row is not None else None
            except sqlite3.Error as exc:
                raise StateStoreError('State read failed') from exc

    def transition(self, message_id, part_id, status, detail='', artifact_path=None):
        with self._mutex:
            row = self.get(message_id, part_id)
            if row is None or status not in self.TRANSITIONS.get(row['status'], set()):
                raise StateStoreError('Unsafe state transition rejected')
            try:
                with self._connection:
                    result = self._connection.execute('UPDATE operations SET status=?, detail=?, '
                        'artifact_path=COALESCE(?, artifact_path), '
                        'updated_at=CURRENT_TIMESTAMP WHERE message_id=? AND part_id=? AND status=?',
                        (status, str(detail)[:512], artifact_path, message_id, part_id, row['status']))
                    if result.rowcount != 1:
                        raise StateStoreError('Concurrent state modification')
            except sqlite3.Error as exc:
                raise StateStoreError('Durable state transition failed') from exc

    def close(self):
        with self._mutex:
            if self._closed:
                return
            self._closed = True
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            if self._lock_file is not None:
                self._lock_file.close()
                self._lock_file = None

    def __enter__(self):
        self._ensure_open()
        return self

    def __exit__(self, *_):
        self.close()
