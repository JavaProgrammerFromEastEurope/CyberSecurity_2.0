"""Regression guards against leaked SQLite handles on normal/error paths."""
from __future__ import annotations

import sqlite3
import pytest

from cybersec.db import connect


def test_sqlite_connection_closed_after_success(tmp_path):
    with connect(tmp_path / 'closed.sqlite') as db:
        db.execute('CREATE TABLE ready (id INTEGER PRIMARY KEY)')
    with pytest.raises(sqlite3.ProgrammingError, match='closed'):
        db.execute('SELECT * FROM ready')


def test_sqlite_connection_closed_after_rollback(tmp_path):
    with pytest.raises(LookupError):
        with connect(tmp_path / 'rolledback.sqlite') as db:
            db.execute('CREATE TABLE ready (id INTEGER PRIMARY KEY)')
            raise LookupError('fixture error')
    with pytest.raises(sqlite3.ProgrammingError, match='closed'):
        db.execute('SELECT 1')
