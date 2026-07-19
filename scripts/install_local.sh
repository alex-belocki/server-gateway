#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="$(pwd)"
ENV_PATH="${APP_ROOT}/.env"
UNIT_PATH="${HOME}/.config/systemd/user/server-gateway.service"
CREATED_ENV=0

if [[ ! -f "${APP_ROOT}/pyproject.toml" ]] || [[ ! -d "${APP_ROOT}/src/server_gateway" ]]; then
  echo "This script must be run from the project root directory." >&2
  exit 1
fi

mkdir -p "${HOME}/.config/systemd/user"

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

uv sync

cat > "${UNIT_PATH}" <<EOF
[Unit]
Description=Server Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_ROOT}
EnvironmentFile=${ENV_PATH}
Environment=PYTHONPATH=${APP_ROOT}/src
ExecStart=${APP_ROOT}/.venv/bin/python -m uvicorn server_gateway.main:app --host 127.0.0.1 --port 8787
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
if [[ "${CREATED_ENV}" -eq 1 ]]; then
  systemctl --user enable server-gateway.service
  echo "Created ${ENV_PATH}. Edit it, then start the service with:" >&2
  echo "  systemctl --user start server-gateway.service" >&2
else
  systemctl --user enable --now server-gateway.service
fi
