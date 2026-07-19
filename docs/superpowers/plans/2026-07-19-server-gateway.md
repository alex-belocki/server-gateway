# Server Gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a minimal FastAPI server gateway at `/Users/alex/dev/personalPre/server-gateway` by copying the security and deployment patterns from `hermes-automation-gateway` and removing all Hermes/Kanban-specific logic.

**Architecture:** A single FastAPI app with a shared auth/state layer. The only exposed endpoint is `GET /health`. Protected routes can be added later by reusing `authenticate_request` and the auth dependency. Deployment uses `uv` + `systemd --user` + Caddy, identical to the reference project.

**Tech Stack:** Python >=3.11, FastAPI, Pydantic, Uvicorn, SQLite (for replay store), systemd, Caddy.

## Global Constraints

- Project path: `/Users/alex/dev/personalPre/server-gateway`
- Package name: `server_gateway`
- Source layout: `src/server_gateway/`
- Environment variable prefix: `SERVER_GATEWAY_*`
- Default bind: `127.0.0.1:8787`
- Default auth mode: `hmac`
- No Hermes/Kanban code or references may remain in the final project.
- Do not commit real secrets or populated env files.
- Follow the reference project's Python style: 4-space indentation, type hints, dataclasses/Pydantic for structured data, `snake_case` for functions/modules, `PascalCase` for classes.

---

### Task 1: Project Skeleton and `pyproject.toml`

**Files:**
- Create: `pyproject.toml`
- Create: `src/server_gateway/__init__.py`
- Create: `.gitignore`

**Interfaces:**
- Produces: `server_gateway.__version__` = `"0.1.0"`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[project]
name = "server-gateway"
version = "0.1.0"
description = "Minimal secure automation gateway server."
readme = "README.md"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.115,<1.0",
    "pydantic>=2.7,<3.0",
    "uvicorn>=0.30,<1.0",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/server_gateway"]
```

- [ ] **Step 2: Create `src/server_gateway/__init__.py`**

```python
"""Server gateway package."""

__all__ = ["__version__"]

__version__ = "0.1.0"
```

- [ ] **Step 3: Create `.gitignore`**

```gitignore
.venv/
venv/
*.pyc
__pycache__/
.pytest_cache/
.mypy_cache/
*.egg-info/
*.env
state.db
state.db-*
.DS_Store
```

- [ ] **Step 4: Verify directory layout**

Run: `ls -R /Users/alex/dev/personalPre/server-gateway`
Expected: `pyproject.toml`, `src/server_gateway/__init__.py`, `.gitignore` visible.

- [ ] **Step 5: Commit**

```bash
git -C /Users/alex/dev/personalPre/server-gateway init
git -C /Users/alex/dev/personalPre/server-gateway add pyproject.toml src/server_gateway/__init__.py .gitignore
git -C /Users/alex/dev/personalPre/server-gateway commit -m "chore: project skeleton and dependencies"
```

---

### Task 2: Environment Configuration Module

**Files:**
- Create: `src/server_gateway/config.py`

**Interfaces:**
- Produces: `Settings.load()` returning a `Settings` dataclass with fields: `host`, `port`, `log_level`, `auth_mode`, `bearer_token`, `hmac_keys`, `request_ttl_seconds`, `request_id_ttl_seconds`, `rate_limit_per_minute`, `state_db_path`, `service_name`, `allowed_ips`, `trusted_proxies`, `require_idempotency_key`.
- Produces: helpers `_env_bool`, `_env_int`, `_parse_hmac_keys`, `_parse_csv`.

- [ ] **Step 1: Create `src/server_gateway/config.py`**

```python
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

APP_ROOT = Path(__file__).resolve().parents[2]


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def _parse_hmac_keys(raw: str) -> dict[str, str]:
    keys: dict[str, str] = {}
    for chunk in raw.split(","):
        item = chunk.strip()
        if not item:
            continue
        key_id, sep, secret = item.partition(":")
        if not sep or not key_id.strip() or not secret.strip():
            raise ValueError(
                "SERVER_GATEWAY_HMAC_KEYS must be key_id:secret pairs separated by commas"
            )
        keys[key_id.strip()] = secret.strip()
    return keys


def _parse_csv(raw: str) -> Tuple[str, ...]:
    return tuple(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    log_level: str
    auth_mode: str
    bearer_token: str
    hmac_keys: dict[str, str]
    request_ttl_seconds: int
    request_id_ttl_seconds: int
    rate_limit_per_minute: int
    state_db_path: Path
    service_name: str
    allowed_ips: tuple[str, ...]
    trusted_proxies: tuple[str, ...]
    require_idempotency_key: bool

    @classmethod
    def load(cls) -> "Settings":
        auth_mode = os.getenv("SERVER_GATEWAY_AUTH_MODE", "hmac").strip().lower()
        if auth_mode not in {"bearer", "hmac", "either"}:
            raise ValueError("SERVER_GATEWAY_AUTH_MODE must be bearer, hmac, or either")

        bearer_token = os.getenv("SERVER_GATEWAY_BEARER_TOKEN", "").strip()
        hmac_keys = _parse_hmac_keys(os.getenv("SERVER_GATEWAY_HMAC_KEYS", "").strip())
        if auth_mode in {"bearer", "either"} and not bearer_token:
            raise ValueError("SERVER_GATEWAY_BEARER_TOKEN is required for bearer/either mode")
        if auth_mode in {"hmac", "either"} and not hmac_keys:
            raise ValueError("SERVER_GATEWAY_HMAC_KEYS is required for hmac/either mode")

        allowed_ips = _parse_csv(os.getenv("SERVER_GATEWAY_ALLOWED_IPS", ""))
        trusted_proxies = _parse_csv(
            os.getenv("SERVER_GATEWAY_TRUSTED_PROXIES", "127.0.0.1,::1")
        )

        if auth_mode in {"bearer", "either"} and not allowed_ips:
            raise ValueError(
                "SERVER_GATEWAY_ALLOWED_IPS is required when bearer auth is enabled"
            )

        return cls(
            host=os.getenv("SERVER_GATEWAY_HOST", "127.0.0.1").strip(),
            port=_env_int("SERVER_GATEWAY_PORT", 8787),
            log_level=os.getenv("SERVER_GATEWAY_LOG_LEVEL", "info").strip().lower(),
            auth_mode=auth_mode,
            bearer_token=bearer_token,
            hmac_keys=hmac_keys,
            request_ttl_seconds=_env_int("SERVER_GATEWAY_REQUEST_TTL_SECONDS", 300),
            request_id_ttl_seconds=_env_int("SERVER_GATEWAY_REQUEST_ID_TTL_SECONDS", 86400),
            rate_limit_per_minute=_env_int("SERVER_GATEWAY_RATE_LIMIT_PER_MINUTE", 60),
            state_db_path=Path(
                os.getenv(
                    "SERVER_GATEWAY_STATE_DB",
                    str(APP_ROOT / "state.db"),
                ).strip()
            ),
            service_name=os.getenv("SERVER_GATEWAY_SERVICE_NAME", "server-gateway").strip(),
            allowed_ips=allowed_ips,
            trusted_proxies=trusted_proxies,
            require_idempotency_key=_env_bool("SERVER_GATEWAY_REQUIRE_IDEMPOTENCY_KEY", True),
        )
```

- [ ] **Step 2: Verify configuration loading**

Run:
```bash
cd /Users/alex/dev/personalPre/server-gateway
PYTHONPATH=src SERVER_GATEWAY_HMAC_KEYS=default:test uv run python - <<'PY'
from server_gateway.config import Settings
s = Settings.load()
assert s.auth_mode == "hmac"
assert s.port == 8787
assert s.hmac_keys == {"default": "test"}
print("OK")
PY
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git -C /Users/alex/dev/personalPre/server-gateway add src/server_gateway/config.py
git -C /Users/alex/dev/personalPre/server-gateway commit -m "feat: add environment configuration module"
```

---

### Task 3: State Module (Replay Store + Rate Limiter)

**Files:**
- Create: `src/server_gateway/state.py`

**Interfaces:**
- Produces: `ReplayStore(db_path, ttl_seconds)` with method `mark_seen(request_id: str) -> bool`
- Produces: `RateLimiter(limit_per_minute: int)` with method `allow(bucket_key: str) -> bool`

- [ ] **Step 1: Create `src/server_gateway/state.py`**

```python
from __future__ import annotations

import sqlite3
import threading
import time
from collections import deque


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
        with self._connect() as conn:
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

    def mark_seen(self, request_id: str) -> bool:
        now = int(time.time())
        cutoff = now - self._ttl_seconds
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM seen_requests WHERE created_at < ?", (cutoff,))
            cur = conn.execute(
                "INSERT OR IGNORE INTO seen_requests(request_id, created_at) VALUES(?, ?)",
                (request_id, now),
            )
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
```

- [ ] **Step 2: Verify state classes**

Run:
```bash
cd /Users/alex/dev/personalPre/server-gateway
PYTHONPATH=src uv run python - <<'PY'
import tempfile
from server_gateway.state import RateLimiter, ReplayStore

rl = RateLimiter(2)
assert rl.allow("a")
assert rl.allow("a")
assert not rl.allow("a")
assert rl.allow("b")

with tempfile.NamedTemporaryFile(suffix=".db") as f:
    rs = ReplayStore(f.name, 60)
    assert rs.mark_seen("r1")
    assert not rs.mark_seen("r1")
    assert rs.mark_seen("r2")
print("OK")
PY
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git -C /Users/alex/dev/personalPre/server-gateway add src/server_gateway/state.py
git -C /Users/alex/dev/personalPre/server-gateway commit -m "feat: add replay store and rate limiter"
```

---

### Task 4: Authentication Module

**Files:**
- Create: `src/server_gateway/auth.py`

**Interfaces:**
- Consumes: `Settings` from `src/server_gateway.config`
- Consumes: `ReplayStore`, `RateLimiter` from `src/server_gateway.state`
- Produces: `AuthContext(method, principal, client_ip, request_id)`
- Produces: `authenticate_request(request, settings, replay_store, rate_limiter) -> AuthContext`

- [ ] **Step 1: Create `src/server_gateway/auth.py`**

```python
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import time
from dataclasses import dataclass

from fastapi import HTTPException, Request, status

from .config import Settings
from .state import RateLimiter, ReplayStore


@dataclass(frozen=True)
class AuthContext:
    method: str
    principal: str
    client_ip: str
    request_id: str


def _is_trusted_proxy(client_ip: str, trusted_proxies: tuple[str, ...]) -> bool:
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for raw in trusted_proxies:
        candidate = raw.strip()
        try:
            if "/" in candidate:
                if ip in ipaddress.ip_network(candidate, strict=False):
                    return True
            elif ip == ipaddress.ip_address(candidate):
                return True
        except ValueError:
            continue
    return False


def _extract_forwarded_ip(forwarded_for: str, trusted_proxies: tuple[str, ...]) -> str | None:
    chain = [item.strip() for item in forwarded_for.split(",") if item.strip()]
    if not chain:
        return None
    for candidate in reversed(chain):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return None
        if not _is_trusted_proxy(candidate, trusted_proxies):
            return candidate
    return chain[0]


def _client_ip(request: Request, trusted_proxies: tuple[str, ...]) -> str:
    peer_ip = request.client.host if request.client else ""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded and peer_ip and _is_trusted_proxy(peer_ip, trusted_proxies):
        forwarded_ip = _extract_forwarded_ip(forwarded, trusted_proxies)
        if forwarded_ip:
            return forwarded_ip
    return peer_ip


def _check_ip_allowed(client_ip: str, allowed_ips: tuple[str, ...]) -> None:
    if not allowed_ips:
        return
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid client IP") from exc
    for raw in allowed_ips:
        candidate = raw.strip()
        try:
            if "/" in candidate:
                if ip in ipaddress.ip_network(candidate, strict=False):
                    return
            elif ip == ipaddress.ip_address(candidate):
                return
        except ValueError:
            continue
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Client IP is not allowed")


def _canonical_string(method: str, path: str, timestamp: str, body_bytes: bytes) -> str:
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    return "\n".join([method.upper(), path, timestamp, body_hash])


async def authenticate_request(
    request: Request,
    settings: Settings,
    replay_store: ReplayStore,
    rate_limiter: RateLimiter,
) -> AuthContext:
    client_ip = _client_ip(request, settings.trusted_proxies)
    _check_ip_allowed(client_ip, settings.allowed_ips)

    request_id = request.headers.get("x-request-id", "").strip()
    if not request_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing X-Request-Id")

    if not rate_limiter.allow(f"{client_ip}:{request.url.path}"):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")

    authorization = request.headers.get("authorization", "").strip()
    token = ""
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()

    key_id = request.headers.get("x-key-id", "").strip()
    timestamp = request.headers.get("x-timestamp", "").strip()
    signature = request.headers.get("x-signature", "").strip()

    if settings.auth_mode in {"bearer", "either"} and token and token == settings.bearer_token:
        if not replay_store.mark_seen(request_id):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Duplicate X-Request-Id")
        return AuthContext(
            method="bearer",
            principal="bearer",
            client_ip=client_ip,
            request_id=request_id,
        )

    if settings.auth_mode in {"hmac", "either"} and key_id and timestamp and signature:
        secret = settings.hmac_keys.get(key_id)
        if not secret:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown HMAC key")
        try:
            ts = int(timestamp)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid X-Timestamp") from exc
        if abs(int(time.time()) - ts) > settings.request_ttl_seconds:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Expired request timestamp")
        body = await request.body()
        expected = hmac.new(
            secret.encode("utf-8"),
            _canonical_string(request.method, request.url.path, timestamp, body).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid HMAC signature")
        if not replay_store.mark_seen(request_id):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Duplicate X-Request-Id")
        return AuthContext(
            method="hmac",
            principal=key_id,
            client_ip=client_ip,
            request_id=request_id,
        )

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
```

- [ ] **Step 2: Verify auth module imports**

Run:
```bash
cd /Users/alex/dev/personalPre/server-gateway
PYTHONPATH=src SERVER_GATEWAY_HMAC_KEYS=default:test uv run python - <<'PY'
from server_gateway.auth import AuthContext, authenticate_request
from server_gateway.config import Settings
from server_gateway.state import ReplayStore, RateLimiter
print("imports OK")
PY
```

Expected: `imports OK`

- [ ] **Step 3: Commit**

```bash
git -C /Users/alex/dev/personalPre/server-gateway add src/server_gateway/auth.py
git -C /Users/alex/dev/personalPre/server-gateway commit -m "feat: add HMAC/bearer authentication and request guardrails"
```

---

### Task 5: FastAPI Application with `/health`

**Files:**
- Create: `src/server_gateway/main.py`

**Interfaces:**
- Consumes: `Settings`, `AuthContext`, `authenticate_request`, `ReplayStore`, `RateLimiter`
- Produces: `app: FastAPI` with `GET /health`
- Produces: `_auth_dependency` for future protected routes

- [ ] **Step 1: Create `src/server_gateway/main.py`**

```python
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import __version__
from .auth import AuthContext, authenticate_request
from .config import Settings
from .state import RateLimiter, ReplayStore

log = logging.getLogger("server_gateway")


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    auth_mode: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings.load()
    settings.state_db_path.parent.mkdir(parents=True, exist_ok=True)
    app.state.settings = settings
    app.state.replay_store = ReplayStore(str(settings.state_db_path), settings.request_id_ttl_seconds)
    app.state.rate_limiter = RateLimiter(settings.rate_limit_per_minute)
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    yield


app = FastAPI(
    title="Server Gateway",
    version=__version__,
    lifespan=lifespan,
)


def _settings(request: Request) -> Settings:
    return request.app.state.settings


async def _auth_dependency(request: Request) -> AuthContext:
    return await authenticate_request(
        request,
        request.app.state.settings,
        request.app.state.replay_store,
        request.app.state.rate_limiter,
    )


@app.get("/health", response_model=HealthResponse)
async def health(request: Request):
    settings = _settings(request)
    return {
        "status": "ok",
        "service": settings.service_name,
        "version": __version__,
        "auth_mode": settings.auth_mode,
    }
```

- [ ] **Step 2: Run `/health` smoke test**

Run:
```bash
cd /Users/alex/dev/personalPre/server-gateway
SERVER_GATEWAY_HMAC_KEYS=default:test uv run python -m uvicorn server_gateway.main:app --app-dir src --host 127.0.0.1 --port 8787 &
PID=$!
sleep 2
curl -s http://127.0.0.1:8787/health
kill $PID
```

Expected JSON:
```json
{"status":"ok","service":"server-gateway","version":"0.1.0","auth_mode":"hmac"}
```

- [ ] **Step 3: Commit**

```bash
git -C /Users/alex/dev/personalPre/server-gateway add src/server_gateway/main.py
git -C /Users/alex/dev/personalPre/server-gateway commit -m "feat: add FastAPI app with health endpoint"
```

---

### Task 6: Deployment Assets

**Files:**
- Create: `config/server-gateway.env.example`
- Create: `config/server-gateway.service`
- Create: `config/Caddyfile.example`
- Create: `scripts/install_local.sh`

**Interfaces:**
- Produces: env template, systemd unit, Caddy example, install script for `~/.local/share/server-gateway`.

- [ ] **Step 1: Create `config/server-gateway.env.example`**

```bash
SERVER_GATEWAY_HOST=127.0.0.1
SERVER_GATEWAY_PORT=8787
SERVER_GATEWAY_LOG_LEVEL=info

# bearer | hmac | either
SERVER_GATEWAY_AUTH_MODE=hmac

# Generate with:
# python3 - <<'PY'
# import secrets
# print(secrets.token_urlsafe(48))
# PY
SERVER_GATEWAY_BEARER_TOKEN=replace-me

# Comma-separated key_id:secret pairs. Example:
# SERVER_GATEWAY_HMAC_KEYS=default:replace-me
SERVER_GATEWAY_HMAC_KEYS=default:replace-me

# Required when bearer auth is enabled. Recommended for all deployments.
SERVER_GATEWAY_ALLOWED_IPS=
# Reverse proxies allowed to supply X-Forwarded-For. Keep this tight.
SERVER_GATEWAY_TRUSTED_PROXIES=127.0.0.1,::1
SERVER_GATEWAY_REQUEST_TTL_SECONDS=300
SERVER_GATEWAY_REQUEST_ID_TTL_SECONDS=86400
SERVER_GATEWAY_RATE_LIMIT_PER_MINUTE=60
SERVER_GATEWAY_REQUIRE_IDEMPOTENCY_KEY=true
SERVER_GATEWAY_SERVICE_NAME=server-gateway
```

- [ ] **Step 2: Create `config/server-gateway.service`**

```ini
[Unit]
Description=Server Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%h/.local/share/server-gateway
EnvironmentFile=-%h/.config/server-gateway/server-gateway.env
Environment=PYTHONPATH=%h/.local/share/server-gateway/src
ExecStart=%h/.local/share/server-gateway/.venv/bin/python -m uvicorn server_gateway.main:app --host 127.0.0.1 --port 8787
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
```

- [ ] **Step 3: Create `config/Caddyfile.example`**

```caddyfile
# Replace with your actual domain
gateway.example.com {
    encode zstd gzip

    reverse_proxy 127.0.0.1:8787

    header {
        -Server
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy no-referrer
    }

    log {
        output file /var/log/caddy/server-gateway.access.log
        format json
    }
}
```

- [ ] **Step 4: Create `scripts/install_local.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="${HOME}/.local/share/server-gateway"
ENV_PATH="${HOME}/.config/server-gateway/server-gateway.env"
UNIT_PATH="${HOME}/.config/systemd/user/server-gateway.service"
CREATED_ENV=0

mkdir -p "${HOME}/.local/share" "${HOME}/.config/server-gateway" "${HOME}/.config/systemd/user"
rm -rf "${APP_ROOT}"
cp -R "$(cd "$(dirname "$0")/.." && pwd)" "${APP_ROOT}"

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required but was not found in PATH" >&2
  exit 1
fi

if [[ ! -f "${ENV_PATH}" ]]; then
  cp "${APP_ROOT}/config/server-gateway.env.example" "${ENV_PATH}"
  chmod 600 "${ENV_PATH}"
  CREATED_ENV=1
fi

set -a
. "${ENV_PATH}"
set +a

(
  cd "${APP_ROOT}"
  uv sync
)

cp "${APP_ROOT}/config/server-gateway.service" "${UNIT_PATH}"

systemctl --user daemon-reload
if [[ "${CREATED_ENV}" -eq 1 ]]; then
  systemctl --user enable server-gateway.service
  echo "Created ${ENV_PATH}. Edit it, then start the service with:" >&2
  echo "  systemctl --user start server-gateway.service" >&2
else
  systemctl --user enable --now server-gateway.service
fi
```

- [ ] **Step 5: Make install script executable**

Run:
```bash
chmod +x /Users/alex/dev/personalPre/server-gateway/scripts/install_local.sh
```

- [ ] **Step 6: Commit**

```bash
git -C /Users/alex/dev/personalPre/server-gateway add config/server-gateway.env.example config/server-gateway.service config/Caddyfile.example scripts/install_local.sh
git -C /Users/alex/dev/personalPre/server-gateway commit -m "chore: add deployment assets"
```

---

### Task 7: Documentation

**Files:**
- Create: `README.md`
- Create: `AGENTS.md`

**Interfaces:**
- Produces: user-facing README and agent guidelines.

- [ ] **Step 1: Create `README.md`**

```markdown
# Server Gateway

Minimal secure automation gateway server. Accepts authenticated HTTP requests from trusted external systems and forwards them to business logic you add later.

## What This Service Does

- Runs a small FastAPI app on localhost.
- Enforces HMAC or bearer authentication, IP allowlisting, replay protection, and rate limiting.
- Exposes a `/health` endpoint for monitoring.
- Provides a secure foundation for adding custom automation endpoints.

## Architecture

```
external client -> HTTPS -> Caddy -> 127.0.0.1:8787 -> FastAPI app
```

## Endpoints

- `GET /health` — unauthenticated health probe.

## Authentication Modes

Configured through `SERVER_GATEWAY_AUTH_MODE`:

- `hmac` (recommended)
- `bearer`
- `either`

All authenticated requests must include:

- `X-Request-Id` (required)
- HMAC headers: `X-Key-Id`, `X-Timestamp`, `X-Signature` (HMAC mode)
- Or `Authorization: Bearer <token>` (bearer mode)

## Configuration

Copy the example environment file:

```bash
cp config/server-gateway.env.example ~/.config/server-gateway/server-gateway.env
chmod 600 ~/.config/server-gateway/server-gateway.env
```

Fill in at least the auth settings and any IP restrictions.

## Local Development

```bash
uv sync
SERVER_GATEWAY_HMAC_KEYS=default:replace-me uv run python -m uvicorn server_gateway.main:app --app-dir src --host 127.0.0.1 --port 8787
```

Health check:

```bash
curl http://127.0.0.1:8787/health
```

## Deployment

Run the installer on the target server:

```bash
./scripts/install_local.sh
```

The installer:

- copies the repo to `~/.local/share/server-gateway`
- creates `~/.config/server-gateway/server-gateway.env` from the example if missing
- installs a systemd user unit
- runs `uv sync`

On first install, edit the env file and start the service manually:

```bash
systemctl --user start server-gateway.service
```

Configure Caddy or another reverse proxy to terminate HTTPS and proxy to `127.0.0.1:8787`.

## Adding Business Logic

Add protected routes in `src/server_gateway/main.py` using the existing auth dependency:

```python
from fastapi import Depends

@app.post("/v1/custom-action")
async def custom_action(auth: AuthContext = Depends(_auth_dependency)):
    ...
```
```

- [ ] **Step 2: Create `AGENTS.md`**

```markdown
# Repository Guidelines

## Project Structure

Core application code lives in `src/server_gateway/`:

- `main.py` — FastAPI app and HTTP routes
- `auth.py` — HMAC/bearer authentication and request guardrails
- `config.py` — environment-based settings loader
- `state.py` — replay store and in-memory rate limiter

Deployment assets live in `config/` (`Caddyfile.example`, env template, and systemd unit). `scripts/install_local.sh` installs the repo into `~/.local/share/server-gateway`.

## Build and Run Commands

- `uv sync` — install dependencies
- `SERVER_GATEWAY_HMAC_KEYS=default:test uv run python -m uvicorn server_gateway.main:app --app-dir src --host 127.0.0.1 --port 8787` — run locally
- `curl http://127.0.0.1:8787/health` — smoke test
- `./scripts/install_local.sh` — install/redeploy on a server

## Coding Style

Follow existing Python style: 4-space indentation, type hints, dataclasses or Pydantic models for structured data, `snake_case` for functions/modules, `PascalCase` for classes. Keep endpoint handlers thin and validation close to request models.

## Security

Do not commit real bearer tokens, HMAC secrets, or populated env files. Keep the gateway bound to localhost behind a reverse proxy. Update `config/server-gateway.env.example` whenever adding or renaming required settings.
```

- [ ] **Step 3: Commit**

```bash
git -C /Users/alex/dev/personalPre/server-gateway add README.md AGENTS.md
git -C /Users/alex/dev/personalPre/server-gateway commit -m "docs: add README and agent guidelines"
```

---

### Task 8: Final Verification

**Files:**
- Verify: all source files compile
- Verify: `/health` responds correctly
- Verify: no Hermes/Kanban references remain

- [ ] **Step 1: Check for leftover references**

Run:
```bash
rg -i "hermes|kanban|automation_gateway" /Users/alex/dev/personalPre/server-gateway/src /Users/alex/dev/personalPre/server-gateway/config /Users/alex/dev/personalPre/server-gateway/scripts /Users/alex/dev/personalPre/server-gateway/README.md /Users/alex/dev/personalPre/server-gateway/AGENTS.md || true
```

Expected: no matches (exit code may be 1 from `rg` if nothing found, which is fine).

- [ ] **Step 2: Final `/health` run**

Run:
```bash
cd /Users/alex/dev/personalPre/server-gateway
SERVER_GATEWAY_HMAC_KEYS=default:test uv run python -m uvicorn server_gateway.main:app --app-dir src --host 127.0.0.1 --port 8787 &
PID=$!
sleep 2
RESPONSE=$(curl -s http://127.0.0.1:8787/health)
kill $PID
wait $PID 2>/dev/null || true
echo "${RESPONSE}"
[[ "${RESPONSE}" == *'"status":"ok"'* ]]
```

Expected: JSON with `"status":"ok"` and exit code 0.

- [ ] **Step 3: Final commit**

```bash
git -C /Users/alex/dev/personalPre/server-gateway add -A
git -C /Users/alex/dev/personalPre/server-gateway diff --cached --quiet || git -C /Users/alex/dev/personalPre/server-gateway commit -m "chore: final verification"
```

---

## Self-Review Checklist

- **Spec coverage:** All sections from the design doc are implemented.
- **Placeholder scan:** No TBD, TODO, or vague steps.
- **Type consistency:** Settings fields, auth signatures, and state methods match across tasks.
