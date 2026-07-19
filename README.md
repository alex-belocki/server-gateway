# Server Gateway

Minimal secure automation gateway server. Accepts authenticated HTTP requests from trusted external systems and forwards them to business logic you add later.

## What This Service Does

- Runs a small FastAPI app on localhost.
- Enforces HMAC or bearer authentication, IP allowlisting, replay protection, and rate limiting.
- Exposes a `/health` endpoint for monitoring.
- Provides a secure foundation for adding custom automation endpoints.

## Architecture

`external client -> HTTPS -> Caddy -> 127.0.0.1:8787 -> FastAPI app`

## Endpoints

- `GET /health` - unauthenticated health probe.

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

Copy the example environment file to the project root:

```bash
cp config/server-gateway.env.example .env
chmod 600 .env
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

The installer, run from the project root directory:

- creates `.env` from the example if missing
- reuses the existing `.env` if present
- generates only missing auth secrets when placeholder values remain
- enables linger for the current user so the service survives logout and reboot
- installs a systemd user unit that runs the app in place
- runs `uv sync`
- enables and starts `server-gateway.service` automatically

Configure Caddy or another reverse proxy to terminate HTTPS and proxy to `127.0.0.1:8787`.

## Adding Business Logic

Add protected routes in `src/server_gateway/main.py` using the existing auth dependency:

```python
from fastapi import Depends

@app.post("/v1/custom-action")
async def custom_action(auth: AuthContext = Depends(_auth_dependency)):
    ...
```
