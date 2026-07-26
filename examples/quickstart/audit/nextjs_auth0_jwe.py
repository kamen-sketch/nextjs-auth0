"""
Independent, from-scratch Python re-implementation of the nextjs-auth0 SDK's
session-cookie JWE scheme (src/server/cookies.ts: encrypt()/decrypt()).

Deliberately does not call into the SDK, jose, @panva/hkdf, or any JS
tooling. Uses only Python's `cryptography` package to derive the encryption
key (HKDF-SHA256) and perform AES-256-GCM, and hand-builds the JWE Compact
Serialization. Written to let a Python-only HTTP client craft and read
session cookies for the running example app, closing the "runtime, not just
static text" gap left by the vitest proofs (real code, but only reachable
via the SDK's own internal test harness) and the static verifier (no
execution at all).

Cross-validated bidirectionally against the real SDK before being trusted
for anything: a cookie minted here decrypts correctly via the SDK's own
`decrypt()`, and a cookie minted by the SDK's `generateSessionCookie()`
decrypts correctly here. See audit/verify_runtime.py for that validation
and the subsequent live HTTP tests.

Scheme (matching src/server/cookies.ts exactly):
  - Key derivation: HKDF-SHA256(ikm=secret.encode("utf-8"), salt=b"",
    info=b"JWE CEK", length=32). `secret` is used as its raw UTF-8 bytes —
    e.g. the 64-*character* hex string from `openssl rand -hex 32` is used
    as 64 ASCII bytes, NOT hex-decoded to 32 bytes first. Getting this
    wrong is the single easiest way to produce a cookie that looks right
    but fails to decrypt.
  - JWE: alg="dir" (direct encryption — the derived key IS the content
    encryption key, no per-message key wrap), enc="A256GCM".
  - Compact serialization: `{header}..{iv}.{ciphertext}.{tag}` — the second
    segment (encrypted key) is empty for alg=dir, hence the double dot.
  - AAD for AES-GCM is the ASCII bytes of the base64url-encoded protected
    header (segment 1 of the compact serialization) — standard JWE, per
    RFC 7516 section 5.1 step 14.
  - Plaintext is the JSON-serialized claims object (the session dict plus
    an `exp` claim), UTF-8 encoded — jose's EncryptJWT has no inner JWS,
    it's direct encryption of the JSON claims.
"""

import base64
import json
import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ENC = "A256GCM"
ALG = "dir"
HKDF_INFO = b"JWE CEK"
KEY_LENGTH = 32


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def derive_key(secret: str) -> bytes:
    """HKDF-SHA256(ikm=secret as raw UTF-8 bytes, salt=b'', info=b'JWE CEK', 32)."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=b"",
        info=HKDF_INFO,
    )
    return hkdf.derive(secret.encode("utf-8"))


def encrypt(payload: dict, secret: str, expiration: int, additional_headers: dict | None = None) -> str:
    """
    Mint a session cookie value, matching src/server/cookies.ts encrypt().
    `expiration` is a Unix timestamp (seconds) — becomes the JWT `exp` claim.
    """
    key = derive_key(secret)
    claims = dict(payload)
    claims["exp"] = int(expiration)

    header = {"enc": ENC, "alg": ALG}
    if additional_headers:
        header.update(additional_headers)
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))

    plaintext = json.dumps(claims, separators=(",", ":")).encode("utf-8")
    aad = header_b64.encode("ascii")

    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(iv, plaintext, aad)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]

    return ".".join(
        [
            header_b64,
            "",  # empty encrypted-key segment (alg=dir)
            _b64url_encode(iv),
            _b64url_encode(ciphertext),
            _b64url_encode(tag),
        ]
    )


class JWEDecryptError(Exception):
    pass


def decrypt(cookie_value: str, secret: str) -> dict:
    """
    Decrypt a session cookie value, matching src/server/cookies.ts decrypt().
    Returns the claims dict (including `exp`). Raises JWEDecryptError on any
    failure (wrong secret, tampered ciphertext, malformed JWE, expired —
    expiry is NOT checked here, matching the fact that this is a pure crypto
    primitive; callers should check `exp` themselves, same division of
    responsibility as jose.jwtDecrypt + the SDK's own clockTolerance handling).
    """
    parts = cookie_value.split(".")
    if len(parts) != 5:
        raise JWEDecryptError(f"expected 5 JWE segments, got {len(parts)}")
    header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64 = parts
    if encrypted_key_b64 != "":
        raise JWEDecryptError("expected empty encrypted-key segment for alg=dir")

    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception as e:
        raise JWEDecryptError(f"invalid protected header: {e}") from e
    if header.get("alg") != ALG or header.get("enc") != ENC:
        raise JWEDecryptError(f"unexpected alg/enc in header: {header}")

    key = derive_key(secret)
    iv = _b64url_decode(iv_b64)
    ciphertext = _b64url_decode(ciphertext_b64)
    tag = _b64url_decode(tag_b64)
    aad = header_b64.encode("ascii")

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(iv, ciphertext + tag, aad)
    except Exception as e:
        raise JWEDecryptError(f"AES-GCM decryption failed (wrong secret or tampered cookie): {e}") from e

    try:
        return json.loads(plaintext)
    except Exception as e:
        raise JWEDecryptError(f"decrypted plaintext is not valid JSON: {e}") from e


def generate_session_cookie(session: dict, secret: str, max_age_seconds: int = 3600) -> str:
    """Python equivalent of @auth0/nextjs-auth0/testing's generateSessionCookie()."""
    session = dict(session)
    if "internal" not in session:
        session["internal"] = {"sid": "auth0-sid", "createdAt": int(time.time())}
    expiration = int(time.time()) + max_age_seconds
    return encrypt(session, secret, expiration)
