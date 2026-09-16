"""Migrate the current SQLite database to the PostgreSQL database in DATABASE_URL.

Run with the app environment loaded (.venv/bin/python -m migrate_db).
"""
import os
import sqlite3
import sys
from pathlib import Path

from dotenv import load_dotenv
import psycopg2

from app.database.connection import PG_SCHEMA

load_dotenv()

TABLES = [
    "organizations",
    "users",
    "campaigns",
    "campaign_items",
    "sessions",
    "donations",
    "participations",
    "login_attempts",
]
SERIAL_PK = ("organizations", "users", "campaigns", "campaign_items", "donations", "participations")
CONFLICT_TARGET = {
    "organizations": "id",
    "users": "id",
    "campaigns": "id",
    "campaign_items": "id",
    "sessions": "token_hash",
    "donations": "id",
    "participations": "id",
    "login_attempts": "email",
}


def main() -> None:
    source = Path(os.getenv("DOAMAIS_DB", "doamais.sqlite3")).resolve()
    url = os.getenv("DATABASE_URL")
    if not url:
        sys.exit("Defina DATABASE_URL apontando para o PostgreSQL de destino.")
    if not source.is_file():
        sys.exit(f"Banco SQLite de origem não encontrado: {source}")

    src = sqlite3.connect(source)
    src.row_factory = sqlite3.Row
    dst = psycopg2.connect(url)
    dst.autocommit = False

    try:
        cursor = dst.cursor()
        for statement in (part.strip() for part in PG_SCHEMA.split(";")):
            if statement:
                cursor.execute(statement)
        dst.commit()

        counts = {}
        for table in TABLES:
            rows = src.execute(f"SELECT * FROM {table}").fetchall()
            if not rows:
                counts[table] = 0
                continue
            columns = list(rows[0].keys())
            column_sql = ",".join(columns)
            placeholders = ",".join(["%s"] * len(columns))
            conflict = CONFLICT_TARGET[table]
            insert_sql = (f"INSERT INTO {table} ({column_sql}) VALUES ({placeholders}) "
                          f"ON CONFLICT ({conflict}) DO NOTHING")
            cursor = dst.cursor()
            cursor.executemany(insert_sql, (tuple(row[c] for c in columns) for row in rows))
            counts[table] = len(rows)

        for table in SERIAL_PK:
            sequence = f"pg_get_serial_sequence('public.{table}','id')"
            cursor = dst.cursor()
            cursor.execute(
                f"SELECT setval({sequence}, COALESCE((SELECT MAX(id) FROM {table}), 0) + 1, false)"
            )
        dst.commit()
    except Exception:
        dst.rollback()
        raise
    finally:
        src.close()
        dst.close()

    print(f"Migrado de {source} para {url}")
    for table, count in counts.items():
        print(f"  {table}: {count} registros")


if __name__ == "__main__":
    main()