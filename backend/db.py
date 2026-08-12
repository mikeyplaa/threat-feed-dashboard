"""
db.py — SQLite persistence for feed snapshots.

Stores one row per feed refresh. Prunes rows older than HISTORY_DAYS on each
save. On startup, app.py calls load_latest_snapshot to warm the in-memory
cache so the dashboard isn't blank after a container restart.
"""

import json
import os

import aiosqlite

DB_PATH = os.environ.get("DB_PATH", "./feeds.db")
HISTORY_DAYS = 7

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS feed_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_key    TEXT    NOT NULL,
    fetched_at  TEXT    NOT NULL,
    item_count  INTEGER NOT NULL DEFAULT 0,
    items_json  TEXT    NOT NULL,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_feed_key_fetched
    ON feed_snapshots(feed_key, fetched_at DESC);
"""


async def init_db() -> None:
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(_CREATE_SQL)
        await db.commit()


async def save_snapshot(feed_key: str, items: list, fetched_at: str) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO feed_snapshots (feed_key, fetched_at, item_count, items_json) VALUES (?, ?, ?, ?)",
            (feed_key, fetched_at, len(items), json.dumps(items)),
        )
        await db.execute(
            "DELETE FROM feed_snapshots WHERE feed_key = ? AND fetched_at < datetime('now', ?)",
            (feed_key, f"-{HISTORY_DAYS} days"),
        )
        await db.commit()


async def load_latest_snapshot(feed_key: str) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT items_json, fetched_at FROM feed_snapshots "
            "WHERE feed_key = ? ORDER BY fetched_at DESC LIMIT 1",
            (feed_key,),
        ) as cur:
            row = await cur.fetchone()
    if row:
        return {"items": json.loads(row[0]), "updated": row[1]}
    return None


async def get_daily_counts(feed_key: str, days: int = HISTORY_DAYS) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            """SELECT date(fetched_at) AS day,
                      CAST(AVG(item_count) AS INTEGER) AS avg_items,
                      MAX(item_count) AS max_items,
                      COUNT(*) AS snapshots
               FROM feed_snapshots
               WHERE feed_key = ? AND fetched_at >= datetime('now', ?)
               GROUP BY day
               ORDER BY day""",
            (feed_key, f"-{days} days"),
        ) as cur:
            rows = await cur.fetchall()
    return [
        {"date": r[0], "avg_items": r[1], "max_items": r[2], "snapshots": r[3]}
        for r in rows
    ]
