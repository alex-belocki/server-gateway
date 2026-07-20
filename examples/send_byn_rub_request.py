from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main() -> None:
    url = os.getenv("SERVER_GATEWAY_URL", "http://127.0.0.1:8787/v1/byn-rub/convert")
    path = "/v1/byn-rub/convert"
    request_id = str(uuid.uuid4())
    timestamp = str(int(time.time()))
    hmac_key_id = os.getenv("SERVER_GATEWAY_HMAC_KEY_ID", "default")
    hmac_secret = os.environ["SERVER_GATEWAY_HMAC_SECRET"]
    enc_key_id = os.getenv("SERVER_GATEWAY_ENCRYPTION_KEY_ID", "default")
    enc_key = base64.b64decode(os.environ["SERVER_GATEWAY_ENCRYPTION_KEY_B64"])

    plaintext_payload = {
        "operation": os.getenv("SERVER_GATEWAY_OPERATION", "byn-to-rub"),
        "amount": os.getenv("SERVER_GATEWAY_AMOUNT", "11"),
        "mode": os.getenv("SERVER_GATEWAY_MODE", "transfer"),
    }
    explicit_rate = os.getenv("SERVER_GATEWAY_RATE", "").strip()
    if explicit_rate:
        plaintext_payload["rate"] = explicit_rate

    aad = "\n".join(["POST", path, request_id, timestamp]).encode("utf-8")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(enc_key).encrypt(
        nonce,
        json.dumps(plaintext_payload, separators=(",", ":")).encode("utf-8"),
        aad,
    )
    body_obj = {
        "key_id": enc_key_id,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    body_bytes = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    canonical = "\n".join(["POST", path, timestamp, body_hash])
    signature = hmac.new(hmac_secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    request = Request(
        url,
        data=body_bytes,
        headers={
            "Content-Type": "application/json",
            "X-Request-Id": request_id,
            "X-Key-Id": hmac_key_id,
            "X-Timestamp": timestamp,
            "X-Signature": signature,
        },
        method="POST",
    )
    with urlopen(request, timeout=30) as response:
        encrypted_response = json.loads(response.read().decode("utf-8"))

    plaintext_response = AESGCM(enc_key).decrypt(
        base64.b64decode(encrypted_response["nonce"]),
        base64.b64decode(encrypted_response["ciphertext"]),
        aad,
    )
    print(json.dumps(json.loads(plaintext_response), ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
