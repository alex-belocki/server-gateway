# Repository Guidelines

## Project Structure

Core application code lives in `src/server_gateway/`:

- `main.py` - FastAPI app and HTTP routes
- `auth.py` - HMAC/bearer authentication and request guardrails
- `config.py` - environment-based settings loader
- `state.py` - replay store and in-memory rate limiter

Deployment assets live in `config/` (`Caddyfile.example`, env template, and systemd unit). `scripts/install_local.sh` installs the repo into `~/.local/share/server-gateway`.

## Build and Run Commands

- `uv sync` - install dependencies
- `SERVER_GATEWAY_HMAC_KEYS=default:test uv run python -m uvicorn server_gateway.main:app --app-dir src --host 127.0.0.1 --port 8787` - run locally
- `curl http://127.0.0.1:8787/health` - smoke test
- `./scripts/install_local.sh` - install/redeploy on a server

## Coding Style

Follow existing Python style: 4-space indentation, type hints, dataclasses or Pydantic models for structured data, `snake_case` for functions/modules, `PascalCase` for classes. Keep endpoint handlers thin and validation close to request models.

## Security

Do not commit real bearer tokens, HMAC secrets, or populated env files. Keep the gateway bound to localhost behind a reverse proxy. Update `config/server-gateway.env.example` whenever adding or renaming required settings.
