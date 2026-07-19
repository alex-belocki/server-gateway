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
