#!/usr/bin/env python3
"""
Runtime (not static) verification of the IPSIE ceiling bypass finding
(FINDING-ipsie-ceiling-connection-token-bypass.md), driven entirely from
Python against the REAL, running example app -- actual HTTP over the actual
Next.js dev server, the actual compiled SDK dist, the actual middleware.
No JS/vitest tooling is used anywhere in this script.

Session cookies are minted here using nextjs_auth0_jwe.py, a from-scratch
Python re-implementation of the SDK's HKDF+AES-256-GCM JWE scheme --
cross-validated bidirectionally against the real SDK's own encrypt()/
decrypt() before being trusted (see the docstring in that file and the
validation this script re-runs at the top, so a stale/broken crypto
implementation fails loudly here rather than producing silently-wrong
"proof").

Prerequisites: the example app's dev server running at BASE, with
app/api/connection-token-test/route.ts (a temporary route added only for
this test) present, and AUTH0_SECRET known.

Usage:
    AUTH0_SECRET=... python3 verify_runtime.py [base_url]
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

from nextjs_auth0_jwe import decrypt as jwe_decrypt
from nextjs_auth0_jwe import encrypt as jwe_encrypt

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
SECRET = os.environ.get("AUTH0_SECRET")

results: list[tuple[str, bool]] = []


def check(claim: str, passed: bool, detail: str = "") -> None:
    results.append((claim, passed))
    print(f"[{'PASS' if passed else 'FAIL'}] {claim}")
    if detail:
        print(f"       {detail}")


def http_get(path: str, cookie_header: str | None) -> tuple[int, dict]:
    req = urllib.request.Request(BASE + path, method="GET")
    if cookie_header:
        req.add_header("Cookie", cookie_header)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, {"_raw": body[:300]}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, {"_raw": body[:300]}


def main() -> int:
    if not SECRET:
        print("ERROR: set AUTH0_SECRET in the environment (same value the running server uses).", file=sys.stderr)
        return 2

    print("=" * 72)
    print(f"Runtime verification (pure Python, real HTTP) — {BASE}")
    print("=" * 72)

    # --- Step 0: sanity-check our from-scratch crypto against the live server ---
    # A session encrypted here MUST be accepted by the real running server, or
    # nothing below means anything. /auth/profile is the SDK's own built-in
    # route (no temp code involved) — the cleanest possible sanity check.
    print("\n--- Step 0: sanity check — does the running server accept a cookie minted here? ---\n")
    now = int(time.time())
    sane_session = {
        "user": {"sub": "auth0|py-sanity-check", "name": "Py Sanity"},
        "tokenSet": {
            "accessToken": "AT_SANITY",
            "idToken": "ID_SANITY",
            "refreshToken": "RT_SANITY",
            "expiresAt": now + 3600,
        },
        "internal": {"sid": "sid-sanity", "createdAt": now},
    }
    sane_cookie = jwe_encrypt(sane_session, SECRET, now + 3600)
    status, body = http_get("/auth/profile", f"__session={sane_cookie}")
    check(
        "Sanity: /auth/profile accepts a from-scratch Python-minted session cookie",
        status == 200 and body.get("sub") == "auth0|py-sanity-check",
        f"status={status} body={json.dumps(body)[:200]}",
    )
    if status != 200:
        print("\nABORTING — the crypto sanity check failed, no further result would be meaningful.")
        return 1

    # --- Step 1: baseline — a session whose ceiling is comfortably in the future ---
    print("\n--- Step 1: baseline (ceiling far in the future) ---\n")
    future_session = {
        "user": {"sub": "auth0|py-future", "name": "Future"},
        "tokenSet": {
            "accessToken": "AT_FUTURE",
            "idToken": "ID_FUTURE",
            "refreshToken": "RT_FUTURE_fake_but_shaped_like_one",
            "expiresAt": now + 3600,
        },
        "internal": {
            "sid": "sid-future",
            "createdAt": now,
            "sessionExpiresAt": now + 60 * 60 * 24 * 365,  # 1 year from now
        },
    }
    future_cookie = jwe_encrypt(future_session, SECRET, now + 3600)
    status_a, body_a = http_get("/auth/profile", f"__session={future_cookie}")
    check(
        "/auth/profile: session with ceiling 1yr in the FUTURE is accepted",
        status_a == 200,
        f"status={status_a}",
    )
    status_b, body_b = http_get("/api/connection-token-test", f"__session={future_cookie}")
    check(
        "/api/connection-token-test: reaches Auth0 (failed_to_exchange, fake connection/token) for a FUTURE-ceiling session",
        body_b.get("code") == "failed_to_exchange_refresh_token",
        f"status={status_b} body={json.dumps(body_b)[:200]}",
    )

    # --- Step 2: the actual finding — ceiling a year in the PAST ---
    print("\n--- Step 2: the finding — ceiling 1 year in the PAST ---\n")
    past_session = {
        "user": {"sub": "auth0|py-past", "name": "Past"},
        "tokenSet": {
            "accessToken": "AT_PAST",
            "idToken": "ID_PAST",
            "refreshToken": "RT_PAST_fake_but_shaped_like_one",
            "expiresAt": now + 3600,
        },
        "internal": {
            "sid": "sid-past",
            "createdAt": now - 60 * 60 * 24 * 400,
            "sessionExpiresAt": now - 60 * 60 * 24 * 365,  # 1 year ago
        },
    }
    past_cookie = jwe_encrypt(past_session, SECRET, now + 3600)

    status_c, body_c = http_get("/auth/profile", f"__session={past_cookie}")
    check(
        "/auth/profile: session with ceiling 1yr in the PAST is REJECTED (primary path enforces it)",
        status_c == 401,
        f"status={status_c} body={json.dumps(body_c)[:200]}",
    )

    status_d, body_d = http_get("/api/connection-token-test", f"__session={past_cookie}")
    reached_auth0 = body_d.get("code") == "failed_to_exchange_refresh_token"
    blocked_locally = body_d.get("code") == "missing_session"
    check(
        "/api/connection-token-test: PAST-ceiling session is NOT blocked locally (no missing_session) — reaches Auth0 exactly like the FUTURE-ceiling session did",
        reached_auth0 and not blocked_locally,
        f"status={status_d} body={json.dumps(body_d)[:250]}",
    )

    # --- Control: no refresh token at all -> SHOULD be blocked locally,
    # proving this script can tell the difference between "blocked locally"
    # and "reached Auth0" when it should see the former.
    print("\n--- Control: session with NO refresh token (must be blocked locally) ---\n")
    no_rt_session = {
        "user": {"sub": "auth0|py-norefresh", "name": "NoRefresh"},
        "tokenSet": {
            "accessToken": "AT_NORT",
            "idToken": "ID_NORT",
            "expiresAt": now + 3600,
            # no refreshToken key at all
        },
        "internal": {"sid": "sid-norefresh", "createdAt": now, "sessionExpiresAt": now + 3600},
    }
    no_rt_cookie = jwe_encrypt(no_rt_session, SECRET, now + 3600)
    status_e, body_e = http_get("/api/connection-token-test", f"__session={no_rt_cookie}")
    check(
        "CONTROL: no refresh token -> missing_refresh_token, a genuinely local error (proves this test can detect 'blocked locally')",
        body_e.get("code") == "missing_refresh_token",
        f"status={status_e} body={json.dumps(body_e)[:200]}",
    )

    print("\n" + "=" * 72)
    passed = sum(1 for _, p in results if p)
    print(f"TOTAL: {len(results)} checks | {passed} passed | {len(results) - passed} failed")
    if passed == len(results):
        print("\nRuntime-confirmed against the real running server: a session whose")
        print("IPSIE ceiling passed a year ago is rejected by the primary session path")
        print("(/auth/profile -> 401) but getAccessTokenForConnection still reaches out")
        print("to Auth0 to attempt a token exchange for it — the bypass is real at")
        print("runtime, not just in the source text or the SDK's internal test harness.")
        return 0
    print("\nSome checks failed — investigate before trusting the finding OR this script.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
