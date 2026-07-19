# Server Gateway

Minimal secure automation gateway server. Accepts authenticated HTTP requests from trusted external systems and forwards them to business logic you add later.

## What This Service Does

- Runs a small FastAPI app on localhost.
- Enforces HMAC or bearer authentication, IP allowlisting, replay protection, and rate limiting.
- Encrypts business payloads with AES-GCM for protected endpoints.
- Exposes a `/health` endpoint for monitoring.
- Provides a secure foundation for adding custom automation endpoints.

## Architecture

`external client -> HTTPS -> Caddy -> 127.0.0.1:8787 -> FastAPI app`

## Endpoints

- `GET /health` - unauthenticated health probe.
- `POST /v1/byn-rub/convert` - encrypted BYN/RUB conversion endpoint.

## Authentication Modes

Configured through `SERVER_GATEWAY_AUTH_MODE`:

- `hmac` (recommended)
- `bearer`
- `either`

All authenticated requests must include:

- `X-Request-Id` (required)
- HMAC headers: `X-Key-Id`, `X-Timestamp`, `X-Signature` (HMAC mode)
- Or `Authorization: Bearer <token>` (bearer mode)

`POST /v1/byn-rub/convert` additionally requires:

- HMAC mode specifically
- AES-GCM encrypted JSON envelope in the request body

## Configuration

Copy the example environment file to the project root:

```bash
cp config/server-gateway.env.example .env
chmod 600 .env
```

Fill in at least the auth settings and any IP restrictions.
This `.env` file is the single source of truth for runtime configuration.

Required for encrypted endpoints:

- `SERVER_GATEWAY_ENCRYPTION_KEYS=default:<base64-aes-key>`

## Local Development

```bash
uv sync
SERVER_GATEWAY_HMAC_KEYS=default:replace-me SERVER_GATEWAY_ENCRYPTION_KEYS=default:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= uv run python -m uvicorn server_gateway.main:app --app-dir src --host 127.0.0.1 --port 8787
```

Health check:

```bash
curl http://127.0.0.1:8787/health
```

## Deployment

Run the installer on the target server:

```bash
./scripts/install_local.sh
```

The installer, run from the project root directory:

- creates `.env` from the example if missing
- reuses the existing `.env` if present
- generates only missing auth secrets when placeholder values remain
- uses `.env` directly as the systemd `EnvironmentFile`
- enables linger for the current user so the service survives logout and reboot
- installs a systemd user unit that runs the app in place
- runs `uv sync`
- enables and starts `server-gateway.service` automatically

Configure Caddy or another reverse proxy to terminate HTTPS and proxy to `127.0.0.1:8787`.

## Adding Business Logic

Add protected routes in `src/server_gateway/main.py` using the existing auth dependency:

```python
from fastapi import Depends

@app.post("/v1/custom-action")
async def custom_action(auth: AuthContext = Depends(_auth_dependency)):
    ...
```

## BYN/RUB Endpoint

Endpoint: `POST /v1/byn-rub/convert`

Supported operations from the original script:

- `byn-to-rub` with optional explicit `rate`
- `rub-to-byn` with optional explicit `rate`
- if `rate` is omitted, the service loads the current T-Bank `DebitCardsOperations` BYN/RUB rate

Plaintext request payload before encryption:

```json
{"operation":"byn-to-rub","amount":"11"}
```

or:

```json
{"operation":"rub-to-byn","amount":"324.02","rate":"29.457"}
```

Plaintext response after decryption will look like one of these:

```json
{"operation":"byn-to-rub","rate_rub_per_byn":"29.457","rate_source":"tbank","input_byn":"11","result_rub":"324.02","formula":"floor_to_kopecks(11 BYN * 29.457)"}
```

```json
{"operation":"rub-to-byn","rate_rub_per_byn":"29.457","rate_source":"explicit","input_rub":"324.02","result_byn":"11.00","formula":"round_to_kopecks(324.02 RUB / 29.457)"}
```

## How Secure Requests Work

The request principle is:

1. Build the plaintext JSON payload.
2. Encrypt it with AES-GCM.
3. Wrap it into a JSON envelope with `key_id`, `nonce`, `ciphertext`.
4. Compute HMAC over the final encrypted request body.
5. Send `X-Request-Id`, `X-Key-Id`, `X-Timestamp`, `X-Signature`.

Time window protection:

- `X-Timestamp` must be within `SERVER_GATEWAY_REQUEST_TTL_SECONDS`
- `X-Request-Id` is single-use within `SERVER_GATEWAY_REQUEST_ID_TTL_SECONDS`

Additional authenticated data for AES-GCM binds the payload to request metadata:

```text
POST
/v1/byn-rub/convert
<x-request-id>
<x-timestamp>
```

## Encryption Example

Python example for forming a valid request:

```python
import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

url = "https://your-host.example/v1/byn-rub/convert"
request_id = str(uuid.uuid4())
timestamp = str(int(time.time()))
path = "/v1/byn-rub/convert"

hmac_key_id = "default"
hmac_secret = "replace-me"

enc_key_id = "default"
enc_key = base64.b64decode("replace-me-base64")

plaintext_payload = {
    "operation": "byn-to-rub",
    "amount": "11",
}

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

response = requests.post(
    url,
    data=body_bytes,
    headers={
        "Content-Type": "application/json",
        "X-Request-Id": request_id,
        "X-Key-Id": hmac_key_id,
        "X-Timestamp": timestamp,
        "X-Signature": signature,
    },
    timeout=30,
)
response.raise_for_status()

encrypted_response = response.json()
plaintext_response = AESGCM(enc_key).decrypt(
    base64.b64decode(encrypted_response["nonce"]),
    base64.b64decode(encrypted_response["ciphertext"]),
    aad,
)
print(json.loads(plaintext_response))
```

## Curl Example

Because AES-GCM and HMAC must be calculated before sending, the most practical way to call this endpoint from shell is to generate the encrypted body first and then pass it to `curl`.

```bash
python3 examples/send_byn_rub_request.py
```

Where the script follows the Python example above and sends the produced JSON body with the required headers.
