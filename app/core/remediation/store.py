"""Persisted user state for remediation actions.

The user's own marks — "I completed this", "I dismissed this" — are stored
separately from scan findings, in their own SQLite database next to the scan
history. Keeping them apart is deliberate: a mark is the user's statement, and
the application must never present it as a technical verification.

State survives restarts, is per action key (stable across re-scans), and can
be cleared by the user.
"""

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from app.core.history.store import HistoryStoreError, default_data_dir, utc_now_iso
from app.core.remediation.models import ACTION_STATES, PENDING

SCHEMA_VERSION = 1


def default_db_path() -> Path:
    """Location of the action-state database."""
    override = os.environ.get("DFA_ACTIONS_DB")
    if override:
        return Path(override).expanduser()
    return default_data_dir() / "actions.db"


class ActionStateStore:
    """SQLite-backed action state. One row per action key."""

    def __init__(self, db_path: Optional[os.PathLike | str] = None):
        self.db_path = Path(db_path) if db_path is not None else default_db_path()
        self._ensure_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(str(self.db_path), timeout=5.0)
        except (sqlite3.Error, OSError) as exc:
            raise HistoryStoreError(
                f"Cannot open remediation state: {exc}") from exc
        try:
            connection.row_factory = sqlite3.Row
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise HistoryStoreError(
                f"Remediation state operation failed: {exc}") from exc
        finally:
            connection.close()

    def _ensure_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS action_states (
                    action_key TEXT PRIMARY KEY,
                    state TEXT NOT NULL DEFAULT 'pending',
                    title TEXT NOT NULL DEFAULT '',
                    priority TEXT NOT NULL DEFAULT '',
                    module TEXT NOT NULL DEFAULT '',
                    first_seen_at TEXT NOT NULL DEFAULT '',
                    last_seen_at TEXT NOT NULL DEFAULT '',
                    marked_at TEXT NOT NULL DEFAULT ''
                )
                """
            )
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # -- writes ---------------------------------------------------------

    def sync(self, actions) -> int:
        """Record that these actions were just seen, without touching state."""
        now = utc_now_iso()
        written = 0
        with self._connect() as connection:
            for action in actions or []:
                connection.execute(
                    """
                    INSERT INTO action_states
                        (action_key, state, title, priority, module,
                         first_seen_at, last_seen_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(action_key) DO UPDATE SET
                        title = excluded.title,
                        priority = excluded.priority,
                        module = excluded.module,
                        last_seen_at = excluded.last_seen_at
                    """,
                    (action.action_key, PENDING, action.title, action.priority,
                     action.module, now, now),
                )
                written += 1
        return written

    def set_state(self, action_key: str, state: str, title: str = "",
                  priority: str = "", module: str = "") -> str:
        """Set the user's state for one action and return the stored value."""
        normalized = str(state or "").strip().lower()
        if normalized not in ACTION_STATES:
            raise ValueError(f"Unknown action state: {state!r}")

        now = utc_now_iso()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO action_states
                    (action_key, state, title, priority, module,
                     first_seen_at, last_seen_at, marked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(action_key) DO UPDATE SET
                    state = excluded.state,
                    title = CASE WHEN excluded.title != '' THEN excluded.title
                                 ELSE title END,
                    priority = CASE WHEN excluded.priority != ''
                                    THEN excluded.priority ELSE priority END,
                    module = CASE WHEN excluded.module != ''
                                  THEN excluded.module ELSE module END,
                    marked_at = excluded.marked_at
                """,
                (action_key, normalized, title, priority, module, now, now, now),
            )
        return normalized

    def clear_state(self, action_key: str) -> bool:
        """Return one action to pending. Returns True when a row changed."""
        now = utc_now_iso()
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE action_states SET state = ?, marked_at = ? "
                "WHERE action_key = ? AND state != ?",
                (PENDING, now, str(action_key), PENDING))
            return cursor.rowcount > 0

    def forget(self, action_key: str) -> bool:
        """Remove the row entirely. Returns True when a row was deleted."""
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM action_states WHERE action_key = ?", (str(action_key),))
            return cursor.rowcount > 0

    def clear(self) -> int:
        """Delete all state. Returns how many rows were removed."""
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM action_states")
            return int(cursor.rowcount or 0)

    # -- reads ----------------------------------------------------------

    def get_state(self, action_key: str) -> str:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state FROM action_states WHERE action_key = ?",
                (str(action_key),)).fetchone()
        return str(row["state"]) if row else PENDING

    def all_states(self) -> Dict[str, Dict[str, str]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM action_states").fetchall()
        return {
            str(row["action_key"]): {
                "state": str(row["state"]),
                "title": str(row["title"]),
                "priority": str(row["priority"]),
                "module": str(row["module"]),
                "first_seen_at": str(row["first_seen_at"]),
                "last_seen_at": str(row["last_seen_at"]),
                "marked_at": str(row["marked_at"]),
            }
            for row in rows
        }

    def count(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS n FROM action_states").fetchone()
        return int(row["n"] if row else 0)

    def list_completed_keys(self) -> List[str]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT action_key FROM action_states WHERE state = 'completed'"
            ).fetchall()
        return [str(row["action_key"]) for row in rows]
