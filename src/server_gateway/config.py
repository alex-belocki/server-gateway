from __future__ import annotations

import os
import base64
from decimal import Decimal
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


def _env_decimal(name: str, default: str) -> Decimal:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return Decimal(default)
    return Decimal(raw.strip().replace(",", "."))


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


def _parse_encryption_keys(raw: str) -> dict[str, bytes]:
    keys: dict[str, bytes] = {}
    for chunk in raw.split(","):
        item = chunk.strip()
        if not item:
            continue
        key_id, sep, secret = item.partition(":")
        if not sep or not key_id.strip() or not secret.strip():
            raise ValueError(
                "SERVER_GATEWAY_ENCRYPTION_KEYS must be key_id:base64key pairs separated by commas"
            )
        decoded = base64.b64decode(secret.strip().encode("ascii"), validate=True)
        if len(decoded) not in {16, 24, 32}:
            raise ValueError("SERVER_GATEWAY_ENCRYPTION_KEYS values must decode to 16, 24, or 32 bytes")
        keys[key_id.strip()] = decoded
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
    encryption_keys: dict[str, bytes]
    request_ttl_seconds: int
    request_id_ttl_seconds: int
    rate_limit_per_minute: int
    state_db_path: Path
    service_name: str
    allowed_ips: tuple[str, ...]
    trusted_proxies: tuple[str, ...]
    require_idempotency_key: bool
    transfer_fee_percent: Decimal

    @classmethod
    def load(cls) -> "Settings":
        auth_mode = os.getenv("SERVER_GATEWAY_AUTH_MODE", "hmac").strip().lower()
        if auth_mode not in {"bearer", "hmac", "either"}:
            raise ValueError("SERVER_GATEWAY_AUTH_MODE must be bearer, hmac, or either")

        bearer_token = os.getenv("SERVER_GATEWAY_BEARER_TOKEN", "").strip()
        hmac_keys = _parse_hmac_keys(os.getenv("SERVER_GATEWAY_HMAC_KEYS", "").strip())
        encryption_keys = _parse_encryption_keys(
            os.getenv("SERVER_GATEWAY_ENCRYPTION_KEYS", "").strip()
        )
        if auth_mode in {"bearer", "either"} and not bearer_token:
            raise ValueError("SERVER_GATEWAY_BEARER_TOKEN is required for bearer/either mode")
        if auth_mode in {"hmac", "either"} and not hmac_keys:
            raise ValueError("SERVER_GATEWAY_HMAC_KEYS is required for hmac/either mode")
        if not encryption_keys:
            raise ValueError("SERVER_GATEWAY_ENCRYPTION_KEYS is required")

        allowed_ips = _parse_csv(os.getenv("SERVER_GATEWAY_ALLOWED_IPS", ""))
        trusted_proxies = _parse_csv(os.getenv("SERVER_GATEWAY_TRUSTED_PROXIES", "127.0.0.1,::1"))

        if auth_mode in {"bearer", "either"} and not allowed_ips:
            raise ValueError(
                "SERVER_GATEWAY_ALLOWED_IPS is required when bearer auth is enabled"
            )

        transfer_fee_percent = _env_decimal(
            "SERVER_GATEWAY_TRANSFER_FEE_PERCENT",
            "8.4",
        )
        if transfer_fee_percent < 0 or transfer_fee_percent >= 100:
            raise ValueError("SERVER_GATEWAY_TRANSFER_FEE_PERCENT must be in range [0, 100)")

        return cls(
            host=os.getenv("SERVER_GATEWAY_HOST", "127.0.0.1").strip(),
            port=_env_int("SERVER_GATEWAY_PORT", 8787),
            log_level=os.getenv("SERVER_GATEWAY_LOG_LEVEL", "info").strip().lower(),
            auth_mode=auth_mode,
            bearer_token=bearer_token,
            hmac_keys=hmac_keys,
            encryption_keys=encryption_keys,
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
            transfer_fee_percent=transfer_fee_percent,
        )
