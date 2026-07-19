from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import tempfile
import time
import unittest
from importlib import reload

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

import server_gateway.main as main_module


def _canonical_string(method: str, path: str, timestamp: str, body_bytes: bytes) -> str:
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    return "\n".join([method.upper(), path, timestamp, body_hash])


def _encrypt_payload(key: bytes, payload: dict[str, str], aad: bytes) -> dict[str, str]:
    nonce = b"0123456789ab"
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(payload, separators=(",", ":")).encode("utf-8"), aad)
    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_env = os.environ.copy()
        self.key = b"0123456789abcdef0123456789abcdef"
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["SERVER_GATEWAY_HMAC_KEYS"] = "default:test-secret"
        os.environ["SERVER_GATEWAY_ENCRYPTION_KEYS"] = (
            "default:" + base64.b64encode(self.key).decode("ascii")
        )
        os.environ["SERVER_GATEWAY_STATE_DB"] = os.path.join(self.temp_dir.name, "state.db")
        reload(main_module)

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self.original_env)
        self.temp_dir.cleanup()
        reload(main_module)

    def _post(self, payload: dict[str, str], request_id: str) -> dict[str, str]:
        timestamp = str(int(time.time()))
        path = "/v1/byn-rub/convert"
        aad = "\n".join(["POST", path, request_id, timestamp]).encode("utf-8")
        body_obj = {
            "key_id": "default",
            **_encrypt_payload(self.key, payload, aad),
        }
        body_bytes = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(
            b"test-secret",
            _canonical_string("POST", path, timestamp, body_bytes).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        with TestClient(main_module.app) as client:
            response = client.post(
                path,
                content=body_bytes,
                headers={
                    "content-type": "application/json",
                    "x-request-id": request_id,
                    "x-key-id": "default",
                    "x-timestamp": timestamp,
                    "x-signature": signature,
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        envelope = response.json()
        plaintext = AESGCM(self.key).decrypt(
            base64.b64decode(envelope["nonce"]),
            base64.b64decode(envelope["ciphertext"]),
            aad,
        )
        return json.loads(plaintext)

    def test_encrypted_converter_endpoint_supports_byn_to_rub(self):
        from decimal import Decimal

        original_fetch_card_rate = main_module.fetch_card_rate
        main_module.fetch_card_rate = lambda: Decimal("29.457")
        try:
            payload = self._post({"operation": "byn-to-rub", "amount": "11"}, "req-1")
        finally:
            main_module.fetch_card_rate = original_fetch_card_rate

        self.assertEqual(payload["operation"], "byn-to-rub")
        self.assertEqual(payload["rate_rub_per_byn"], "29.457")
        self.assertEqual(payload["result_rub"], "324.02")

    def test_encrypted_converter_endpoint_supports_rub_to_byn_with_explicit_rate(self):
        payload = self._post(
            {"operation": "rub-to-byn", "amount": "324.02", "rate": "29.457"},
            "req-2",
        )

        self.assertEqual(payload["operation"], "rub-to-byn")
        self.assertEqual(payload["result_byn"], "11.00")


if __name__ == "__main__":
    unittest.main()
