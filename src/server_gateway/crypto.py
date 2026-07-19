from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException, status


def _b64decode(name: str, value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # pragma: no cover - exact exception type is not important here
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid base64 for {name}",
        ) from exc


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decrypt_json_payload(
    *,
    encryption_keys: dict[str, bytes],
    key_id: str,
    nonce_b64: str,
    ciphertext_b64: str,
    aad: bytes,
) -> dict[str, Any]:
    key = encryption_keys.get(key_id)
    if not key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown encryption key")

    nonce = _b64decode("nonce", nonce_b64)
    ciphertext = _b64decode("ciphertext", ciphertext_b64)

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # pragma: no cover - library surface varies
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to decrypt request payload",
        ) from exc

    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Decrypted payload is not valid JSON",
        ) from exc

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Decrypted payload must be a JSON object",
        )
    return data


def encrypt_json_payload(*, key: bytes, payload: dict[str, Any], aad: bytes, nonce: bytes) -> dict[str, str]:
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }
