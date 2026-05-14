#!/usr/bin/env python3
"""
SecurePass — decrypt ECDH-encrypted blob and store as a named secret.

Usage:
  python3 decrypt_and_store.py SECRET_NAME BASE64_BLOB

The blob format (produced by the GitHub Pages UI):
  bytes  0-64 : user EC public key (P-256, uncompressed, 0x04 prefix)
  bytes 65-76 : AES-GCM IV (12 bytes)
  bytes 77+   : AES-GCM ciphertext + auth tag (16 bytes)

Shared key = raw ECDH x-coordinate (agent_private ⊕ user_public) — 32 bytes.
This matches what SubtleCrypto.deriveBits({name:'ECDH',...}, 256) returns.

Secret is stored in workspace/.secrets/.env and never printed to stdout.
"""
import sys
import os
import base64

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, SECP256R1, EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_SECRETS_ENV = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.secrets', '.env')
)


def _load_private_key():
    b64 = os.environ.get('SECUREPASS_AGENT_PRIVATE_KEY')
    if not b64 and os.path.exists(_SECRETS_ENV):
        with open(_SECRETS_ENV) as f:
            for line in f:
                if line.startswith('SECUREPASS_AGENT_PRIVATE_KEY='):
                    b64 = line.strip().split('=', 1)[1]
                    break
    if not b64:
        raise RuntimeError(
            "SECUREPASS_AGENT_PRIVATE_KEY not found in env or .secrets/.env"
        )
    return serialization.load_der_private_key(base64.b64decode(b64), password=None)


def decrypt_blob(b64_blob: str) -> str:
    data = base64.b64decode(b64_blob)
    if len(data) < 65 + 12 + 16:
        raise ValueError(f"Blob too short: {len(data)} bytes (min 93)")
    if data[0] != 0x04:
        raise ValueError(f"Expected uncompressed EC point (0x04), got 0x{data[0]:02x}")

    x = int.from_bytes(data[1:33], 'big')
    y = int.from_bytes(data[33:65], 'big')
    user_pub = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()

    iv = data[65:77]
    ciphertext = data[77:]

    shared_secret = _load_private_key().exchange(ECDH(), user_pub)
    return AESGCM(shared_secret).decrypt(iv, ciphertext, None).decode('utf-8')


def store_secret(name: str, value: str) -> None:
    name = name.upper()
    entries: dict[str, str] = {}
    if os.path.exists(_SECRETS_ENV):
        with open(_SECRETS_ENV) as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    entries[k] = v
    entries[name] = value
    os.makedirs(os.path.dirname(_SECRETS_ENV), exist_ok=True)
    with open(_SECRETS_ENV, 'w') as f:
        for k, v in entries.items():
            f.write(f"{k}={v}\n")
    os.chmod(_SECRETS_ENV, 0o600)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: decrypt_and_store.py SECRET_NAME BASE64_BLOB", file=sys.stderr)
        sys.exit(1)

    secret_name, blob = sys.argv[1], sys.argv[2]
    try:
        plaintext = decrypt_blob(blob)
        store_secret(secret_name, plaintext)
        # Print length only — never print the value itself
        print(f"✅ Секрет '{secret_name.upper()}' сохранён ({len(plaintext)} символов)")
    except Exception as exc:
        print(f"❌ Ошибка: {exc}", file=sys.stderr)
        sys.exit(1)
