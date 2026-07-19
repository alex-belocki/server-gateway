# Server Gateway Design

## Overview

Create a minimal FastAPI-based server gateway at `/Users/alex/dev/personalPre/server-gateway`. The project is derived from `hermes-automation-gateway`, with all Hermes- and Kanban-specific logic removed, while preserving the security and deployment patterns.

## Purpose

The gateway runs on a host and accepts authenticated HTTP requests from trusted external applications. It exposes a narrow, secure API surface. Business logic will be added later by the user.

## Design Decisions

- **Approach A (minimal copy)** from the brainstorming session was selected.
- Only `/health` is exposed initially. Future business logic will be added as new routes.
- All security guardrails from the reference project are retained: HMAC/bearer auth, IP allowlisting, trusted proxy handling, replay protection via `X-Request-Id`, and per-IP rate limiting.
- The deployment model is `systemd --user` + Caddy reverse proxy, same as the reference.

## Architecture

```
external client -> HTTPS -> Caddy -> 127.0.0.1:8787 -> FastAPI app
```

## Components

### `src/server_gateway/main.py`

- Creates the FastAPI app
- Defines a single public route: `GET /health`
- Wires settings, replay store, and rate limiter into app state via lifespan
- Keeps the auth dependency ready for future protected routes

### `src/server_gateway/config.py`

- Loads settings from environment variables prefixed with `SERVER_GATEWAY_*`
- Auth mode: `hmac` (default), `bearer`, or `either`
- Validates that required tokens/keys are present for the selected mode
- IP allowlist and trusted proxy configuration

### `src/server_gateway/auth.py`

- Client IP extraction with trusted proxy handling
- IP allowlist enforcement
- Mandatory `X-Request-Id`
- Rate limiting
- Bearer token validation
- HMAC signature validation with timestamp freshness
- Replay protection via `ReplayStore`

### `src/server_gateway/state.py`

- `ReplayStore`: SQLite-backed request ID deduplication with TTL
- `RateLimiter`: in-memory per-key sliding window rate limiter

### Deployment Assets

- `config/server-gateway.env.example`: environment variable template
- `config/server-gateway.service`: user-level systemd unit
- `config/Caddyfile.example`: Caddy reverse proxy config with placeholder domain
- `scripts/install_local.sh`: local install/redeploy helper

## Configuration Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `SERVER_GATEWAY_HOST` | `127.0.0.1` | Bind host |
| `SERVER_GATEWAY_PORT` | `8787` | Bind port |
| `SERVER_GATEWAY_LOG_LEVEL` | `info` | Logging level |
| `SERVER_GATEWAY_AUTH_MODE` | `hmac` | Auth mode: `hmac`, `bearer`, `either` |
| `SERVER_GATEWAY_BEARER_TOKEN` | — | Bearer token (required if bearer enabled) |
| `SERVER_GATEWAY_HMAC_KEYS` | — | `key_id:secret` pairs (required if HMAC enabled) |
| `SERVER_GATEWAY_ALLOWED_IPS` | — | Comma-separated allowed IPs/CIDRs |
| `SERVER_GATEWAY_TRUSTED_PROXIES` | `127.0.0.1,::1` | Trusted reverse proxies |
| `SERVER_GATEWAY_REQUEST_TTL_SECONDS` | `300` | HMAC timestamp window |
| `SERVER_GATEWAY_REQUEST_ID_TTL_SECONDS` | `86400` | Replay store TTL |
| `SERVER_GATEWAY_RATE_LIMIT_PER_MINUTE` | `60` | Rate limit per IP/route |
| `SERVER_GATEWAY_STATE_DB` | `state.db` | SQLite replay store path |
| `SERVER_GATEWAY_SERVICE_NAME` | `server-gateway` | Service name in health response |

## API

### `GET /health`

Unauthenticated. Returns service status, name, version, and auth mode.

```json
{
  "status": "ok",
  "service": "server-gateway",
  "version": "0.1.0",
  "auth_mode": "hmac"
}
```

## Testing

- Run locally: `uv sync` + `uvicorn server_gateway.main:app --app-dir src --host 127.0.0.1 --port 8787`
- Smoke test: `curl http://127.0.0.1:8787/health`

## Future Extensions

- Add protected routes under `/v1/` with `Depends(auth_dependency)`
- Add business-logic adapters in `src/server_gateway/adapters/`
- Keep auth and state modules unchanged unless security requirements evolve

## References

- Source template: `https://github.com/alex-belocki/hermes-automation-gateway`
