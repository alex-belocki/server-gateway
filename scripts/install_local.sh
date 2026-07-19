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
