#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="$(pwd)"
ENV_PATH="${APP_ROOT}/.env"
RUNTIME_ENV_PATH="${APP_ROOT}/.env.runtime"
UNIT_PATH="${HOME}/.config/systemd/user/server-gateway.service"
PYTHON_BIN="$(command -v python3 || command -v python)"
CURRENT_USER="${USER:-$(id -un)}"

if [[ ! -f "${APP_ROOT}/pyproject.toml" ]] || [[ ! -d "${APP_ROOT}/src/server_gateway" ]]; then
  echo "This script must be run from the project root directory." >&2
  exit 1
fi

mkdir -p "${HOME}/.config/systemd/user"

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required but was not found in PATH" >&2
  exit 1
fi

if [[ -z "${PYTHON_BIN}" ]]; then
  echo "python3 or python is required but was not found in PATH" >&2
  exit 1
fi

if ! command -v loginctl >/dev/null 2>&1; then
  echo "loginctl is required but was not found in PATH" >&2
  exit 1
fi

if [[ ! -f "${ENV_PATH}" ]]; then
  cp "${APP_ROOT}/config/server-gateway.env.example" "${ENV_PATH}"
fi
chmod 600 "${ENV_PATH}"

replace_env_value() {
  local key="$1"
  local value="$2"

  "${PYTHON_BIN}" - "$ENV_PATH" "$key" "$value" <<'PY'
from pathlib import Path
import sys

env_path = Path(sys.argv[1])
target_key = sys.argv[2]
target_value = sys.argv[3]

lines = env_path.read_text().splitlines()
updated = False

for index, line in enumerate(lines):
    if line.startswith(f"{target_key}="):
        lines[index] = f"{target_key}={target_value}"
        updated = True
        break

if not updated:
    lines.append(f"{target_key}={target_value}")

env_path.write_text("\n".join(lines) + "\n")
PY
}

generate_secret() {
  "${PYTHON_BIN}" - <<'PY'
import secrets

print(secrets.token_urlsafe(48))
PY
}

write_runtime_env() {
  "${PYTHON_BIN}" - "$ENV_PATH" "$RUNTIME_ENV_PATH" <<'PY'
from pathlib import Path
import re
import sys

source_path = Path(sys.argv[1])
runtime_path = Path(sys.argv[2])
pattern = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
valid_lines = [
    line for line in source_path.read_text().splitlines() if pattern.match(line)
]
runtime_path.write_text("\n".join(valid_lines) + "\n")
PY
  chmod 600 "${RUNTIME_ENV_PATH}"
}

write_runtime_env

set -a
. "${RUNTIME_ENV_PATH}"
set +a

AUTH_MODE="${SERVER_GATEWAY_AUTH_MODE:-hmac}"
AUTH_MODE="${AUTH_MODE,,}"

if [[ "${AUTH_MODE}" == "bearer" || "${AUTH_MODE}" == "either" ]]; then
  if [[ -z "${SERVER_GATEWAY_BEARER_TOKEN:-}" || "${SERVER_GATEWAY_BEARER_TOKEN}" == "replace-me" ]]; then
    replace_env_value "SERVER_GATEWAY_BEARER_TOKEN" "$(generate_secret)"
  fi
fi

if [[ "${AUTH_MODE}" == "hmac" || "${AUTH_MODE}" == "either" ]]; then
  if [[ -z "${SERVER_GATEWAY_HMAC_KEYS:-}" || "${SERVER_GATEWAY_HMAC_KEYS}" == "default:replace-me" ]]; then
    replace_env_value "SERVER_GATEWAY_HMAC_KEYS" "default:$(generate_secret)"
  fi
fi

write_runtime_env

set -a
. "${RUNTIME_ENV_PATH}"
set +a

loginctl enable-linger "${CURRENT_USER}"

uv sync

cat > "${UNIT_PATH}" <<EOF
[Unit]
Description=Server Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_ROOT}
EnvironmentFile=${RUNTIME_ENV_PATH}
Environment=PYTHONPATH=${APP_ROOT}/src
ExecStart=${APP_ROOT}/.venv/bin/python -m uvicorn server_gateway.main:app --host ${SERVER_GATEWAY_HOST:-127.0.0.1} --port ${SERVER_GATEWAY_PORT:-8787} --log-level ${SERVER_GATEWAY_LOG_LEVEL:-info}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now server-gateway.service
systemctl --user --no-pager --full status server-gateway.service
