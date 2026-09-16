"""Database access layer supporting SQLite (fallback) and PostgreSQL (via DATABASE_URL).

The application code always talks to a small unified interface (execute/executescript,
lastrowid, dict-like rows). When DATABASE_URL is set we connect to PostgreSQL with
psycopg2; otherwise we fall back to the local SQLite file.
"""
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import psycopg2
import psycopg2.extras

_ID_TABLES = {"organizations", "users", "campaigns", "donations", "campaign_items", "participations"}

PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS organizations (
    id SERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL,
    organization_id INTEGER REFERENCES organizations(id)
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS campaigns (
    id SERIAL PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL,
    goal_cents INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    organization_id INTEGER REFERENCES organizations(id),
    created_by INTEGER REFERENCES users(id), created_at TEXT,
    category TEXT NOT NULL DEFAULT 'Solidariedade', location TEXT NOT NULL DEFAULT '',
    instructions TEXT NOT NULL DEFAULT '', funding_type TEXT NOT NULL DEFAULT 'money'
);
CREATE TABLE IF NOT EXISTS donations (
    id SERIAL PRIMARY KEY, campaign_id INTEGER NOT NULL, donor TEXT NOT NULL,
    amount_cents INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
    email TEXT PRIMARY KEY, attempts INTEGER NOT NULL, reset_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS campaign_items (
    id SERIAL PRIMARY KEY, campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
    name TEXT NOT NULL, unit TEXT NOT NULL, target_quantity INTEGER NOT NULL,
    received_quantity INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS participations (
    id SERIAL PRIMARY KEY, campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
    kind TEXT NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL, message TEXT NOT NULL,
    amount_cents INTEGER, item_id INTEGER REFERENCES campaign_items(id), quantity INTEGER,
    status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL,
    reviewed_by INTEGER REFERENCES users(id), reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS participation_campaign ON participations(campaign_id);
CREATE INDEX IF NOT EXISTS participation_contact ON participations(email,created_at);
CREATE INDEX IF NOT EXISTS items_campaign ON campaign_items(campaign_id);
"""


class DBIntegrityError(Exception):
    """Unique/not-null constraint violation, mirroring sqlite3.IntegrityError."""


class Row(dict):
    """Dictionary row that also supports integer (column-order) indexing."""

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            names = list(self)
            return dict.__getitem__(self, names[key])
        return dict.__getitem__(self, key)


class PGResult:
    def __init__(self, cursor: Any, lastrowid: int | None = None):
        self._cursor = cursor
        self._lastrowid = lastrowid

    @property
    def lastrowid(self) -> int | None:
        return self._lastrowid

    def rowcount(self) -> int:
        return self._cursor.rowcount

    def fetchone(self) -> Row | None:
        row = self._cursor.fetchone()
        return Row(row) if row is not None else None

    def fetchall(self) -> list[Row]:
        return [Row(row) for row in self._cursor.fetchall()]

    def __iter__(self):
        for row in self._cursor:
            yield Row(row)


def _translate(sql: str) -> str:
    sql = sql.replace(
        "INSERT OR REPLACE INTO login_attempts VALUES (?,?,?)",
        "INSERT INTO login_attempts VALUES (%s,%s,%s) ON CONFLICT (email) "
        "DO UPDATE SET attempts=EXCLUDED.attempts, reset_at=EXCLUDED.reset_at",
    )
    sql = sql.replace("BEGIN IMMEDIATE", "BEGIN")
    return sql.replace("?", "%s")


class PGConnection:
    def __init__(self, url: str):
        self.conn = psycopg2.connect(url)
        self.conn.autocommit = False

    def execute(self, sql: str, params: tuple = ()) -> PGResult:
        sql = _translate(sql)
        insert = sql.lstrip().upper().startswith("INSERT")
        target = re.match(r"INSERT\s+INTO\s+(\w+)", sql, re.IGNORECASE)
        wants_lastrowid = (
            insert
            and target is not None
            and target.group(1) in _ID_TABLES
            and sql.rstrip().endswith(")")
            and " RETURNING " not in sql.upper()
        )
        if insert and wants_lastrowid and " RETURNING " not in sql.upper():
            sql = sql.rstrip() + " RETURNING id"
        cursor = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cursor.execute(sql, list(params))
        except psycopg2.IntegrityError:
            raise DBIntegrityError() from None
        if insert and " RETURNING " in sql.upper():
            row = cursor.fetchone()
            return PGResult(cursor, lastrowid=row["id"] if row else None)
        return PGResult(cursor)

    def executescript(self, script: str) -> None:
        for statement in (part.strip() for part in script.split(";")):
            if statement:
                self.execute(statement)

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "PGConnection":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self.close()


class SqliteDatabase:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def execute(self, sql: str, params: tuple = ()):
        try:
            return self.conn.execute(sql, params)
        except sqlite3.IntegrityError:
            raise DBIntegrityError() from None

    def executescript(self, script: str):
        return self.conn.executescript(script)

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "SqliteDatabase":
        self.conn.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.conn.__exit__(exc_type, exc, tb)


def uses_postgres() -> bool:
    return bool(os.getenv("DATABASE_URL"))


@contextmanager
def database(db_path: Path):
    url = os.getenv("DATABASE_URL")
    if url:
        with PGConnection(url) as db:
            yield db
    else:
        connection = sqlite3.connect(db_path)
        connection.row_factory = sqlite3.Row
        try:
            with SqliteDatabase(connection) as db:
                yield db
        finally:
            connection.close()