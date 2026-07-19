from __future__ import annotations

import sqlite3
import threading
import time
from collections import deque
from contextlib import closing


class ReplayStore:
    def __init__(self, db_path: str, ttl_seconds: int) -> None:
        self._db_path = db_path
        self._ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_requests (
                    request_id TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_seen_requests_created_at ON seen_requests(created_at)"
            )
            conn.commit()

    def mark_seen(self, request_id: str) -> bool:
        now = int(time.time())
        cutoff = now - self._ttl_seconds
        with self._lock:
            with closing(self._connect()) as conn:
                conn.execute("DELETE FROM seen_requests WHERE created_at < ?", (cutoff,))
                cur = conn.execute(
                    "INSERT OR IGNORE INTO seen_requests(request_id, created_at) VALUES(?, ?)",
                    (request_id, now),
                )
                conn.commit()
                return cur.rowcount == 1


class RateLimiter:
    def __init__(self, limit_per_minute: int) -> None:
        self._limit = limit_per_minute
        self._lock = threading.Lock()
        self._buckets: dict[str, deque[float]] = {}

    def allow(self, bucket_key: str) -> bool:
        now = time.time()
        cutoff = now - 60.0
        with self._lock:
            bucket = self._buckets.setdefault(bucket_key, deque())
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self._limit:
                return False
            bucket.append(now)
            return True
