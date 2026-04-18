from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from config import settings


SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    sha256 TEXT,
    artifact_type TEXT,
    mime_type TEXT,
    status TEXT NOT NULL,
    error_message TEXT,
    report_path TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trust_cache (
    sha256 TEXT NOT NULL,
    provider TEXT NOT NULL,
    artifact_type TEXT,
    response_json TEXT NOT NULL,
    cached_at TEXT NOT NULL,
    expires_at TEXT,
    PRIMARY KEY (sha256, provider)
);

CREATE TABLE IF NOT EXISTS report_chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_report_chat_messages_job_id_created_at
ON report_chat_messages(job_id, created_at, id);
"""


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(SCHEMA)

        columns = {row["name"] for row in conn.execute("PRAGMA table_info(jobs)").fetchall()}

        if "risk_score" not in columns:
            conn.execute("ALTER TABLE jobs ADD COLUMN risk_score INTEGER")

        if "risk_level" not in columns:
            conn.execute("ALTER TABLE jobs ADD COLUMN risk_level TEXT")


def insert_job(*, job_id: str, original_filename: str, stored_filename: str, stored_path: str, status: str) -> None:
    now = utcnow_iso()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO jobs (id, original_filename, stored_filename, stored_path, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (job_id, original_filename, stored_filename, stored_path, status, now, now),
        )


def update_job(job_id: str, **fields: Any) -> None:
    if not fields:
        return

    fields["updated_at"] = utcnow_iso()
    assignments = ", ".join(f"{key} = ?" for key in fields.keys())
    values = list(fields.values()) + [job_id]

    with get_conn() as conn:
        conn.execute(f"UPDATE jobs SET {assignments} WHERE id = ?", values)


def get_job(job_id: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return dict(row) if row else None


def list_recent_jobs(limit: int = 10) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM jobs
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def delete_job(job_id: str) -> bool:
    with get_conn() as conn:
        conn.execute("DELETE FROM report_chat_messages WHERE job_id = ?", (job_id,))
        cur = conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        return cur.rowcount > 0


def get_trust_cache(sha256: str, provider: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM trust_cache WHERE sha256 = ? AND provider = ?",
            (sha256, provider),
        ).fetchone()
        if not row:
            return None
        payload = dict(row)
        try:
            payload["response_json"] = json.loads(payload.get("response_json") or "{}")
        except Exception:
            payload["response_json"] = {}
        return payload


def upsert_trust_cache(
    *,
    sha256: str,
    provider: str,
    artifact_type: str | None,
    response_json: dict[str, Any],
    cached_at: str,
    expires_at: str | None,
) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO trust_cache (sha256, provider, artifact_type, response_json, cached_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(sha256, provider)
            DO UPDATE SET
                artifact_type = excluded.artifact_type,
                response_json = excluded.response_json,
                cached_at = excluded.cached_at,
                expires_at = excluded.expires_at
            """,
            (sha256, provider, artifact_type, json.dumps(response_json), cached_at, expires_at),
        )


def add_report_chat_message(*, job_id: str, role: str, content: str) -> dict[str, Any]:
    if role not in {"user", "assistant"}:
        raise ValueError("role must be 'user' or 'assistant'")

    created_at = utcnow_iso()

    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO report_chat_messages (job_id, role, content, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (job_id, role, content, created_at),
        )
        message_id = cur.lastrowid

    return {
        "id": message_id,
        "job_id": job_id,
        "role": role,
        "content": content,
        "created_at": created_at,
    }


def list_report_chat_messages(job_id: str, limit: int = 100) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, job_id, role, content, created_at
            FROM report_chat_messages
            WHERE job_id = ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (job_id, limit),
        ).fetchall()
        return [dict(row) for row in rows]


def list_report_chat_messages_for_context(job_id: str, limit: int = 16) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, job_id, role, content, created_at
            FROM report_chat_messages
            WHERE job_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (job_id, limit),
        ).fetchall()

    items = [dict(row) for row in rows]
    items.reverse()
    return items


def clear_report_chat_messages(job_id: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM report_chat_messages WHERE job_id = ?",
            (job_id,),
        )
        return cur.rowcount