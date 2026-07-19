from __future__ import annotations

import secrets
import logging
from contextlib import asynccontextmanager
from decimal import Decimal, InvalidOperation

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field

from . import __version__
from .auth import AuthContext, authenticate_request
from .config import Settings
from .converter import RateError, byn_to_rub, decimal_from_string, fetch_card_rate, format_decimal, rub_to_byn
from .crypto import decrypt_json_payload, encrypt_json_payload
from .state import RateLimiter, ReplayStore


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    auth_mode: str


class EncryptedRequestEnvelope(BaseModel):
    key_id: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    ciphertext: str = Field(min_length=1)


class EncryptedResponseEnvelope(BaseModel):
    key_id: str
    nonce: str
    ciphertext: str


class ConverterRequest(BaseModel):
    operation: str
    amount: str
    rate: str | None = None


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


def _require_hmac(auth: AuthContext) -> None:
    if auth.method != "hmac" or not auth.timestamp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This endpoint requires HMAC-authenticated requests",
        )


def _aad(method: str, path: str, request_id: str, timestamp: str) -> bytes:
    return "\n".join([method.upper(), path, request_id, timestamp]).encode("utf-8")


def _build_converter_response(payload: ConverterRequest) -> dict[str, str]:
    try:
        amount = decimal_from_string(payload.amount)
        rate = decimal_from_string(payload.rate) if payload.rate else fetch_card_rate()
    except InvalidOperation as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid decimal amount or rate") from exc
    except RateError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    response = {
        "operation": payload.operation,
        "rate_rub_per_byn": format_decimal(rate),
        "rate_source": "explicit" if payload.rate else "tbank",
    }

    if payload.operation == "byn-to-rub":
        result = byn_to_rub(amount, rate)
        response["input_byn"] = format_decimal(amount)
        response["result_rub"] = format_decimal(result)
        response["formula"] = (
            f"floor_to_kopecks({format_decimal(amount)} BYN * {format_decimal(rate)})"
        )
        return response

    if payload.operation == "rub-to-byn":
        result = rub_to_byn(amount, rate)
        response["input_rub"] = format_decimal(amount)
        response["result_byn"] = format_decimal(result)
        response["formula"] = (
            f"round_to_kopecks({format_decimal(amount)} RUB / {format_decimal(rate)})"
        )
        return response

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="operation must be byn-to-rub or rub-to-byn",
    )


@app.get("/health", response_model=HealthResponse)
async def health(request: Request):
    settings = _settings(request)
    return {
        "status": "ok",
        "service": settings.service_name,
        "auth_mode": settings.auth_mode,
        "version": __version__,
    }


@app.post("/v1/byn-rub/convert", response_model=EncryptedResponseEnvelope)
async def byn_rub_convert(
    envelope: EncryptedRequestEnvelope,
    request: Request,
    auth: AuthContext = Depends(_auth_dependency),
):
    _require_hmac(auth)
    settings = _settings(request)
    aad = _aad(request.method, request.url.path, auth.request_id, auth.timestamp)
    payload = ConverterRequest.model_validate(
        decrypt_json_payload(
            encryption_keys=settings.encryption_keys,
            key_id=envelope.key_id,
            nonce_b64=envelope.nonce,
            ciphertext_b64=envelope.ciphertext,
            aad=aad,
        )
    )
    response_payload = _build_converter_response(payload)
    encrypted_response = encrypt_json_payload(
        key=settings.encryption_keys[envelope.key_id],
        payload=response_payload,
        aad=aad,
        nonce=secrets.token_bytes(12),
    )
    return {
        "key_id": envelope.key_id,
        **encrypted_response,
    }
