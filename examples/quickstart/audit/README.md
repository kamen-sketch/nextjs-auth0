# Auth0 integration audit

Black-box checks that exercise the running app's authentication surface and
assert on what actually goes over the wire — status codes, redirect targets,
cookie attributes, and response bodies.

## Running

The app must already be running, and the audit needs the same `AUTH0_SECRET` as
the server so it can mint and decrypt cookies:

```bash
pnpm dev &                      # terminal 1
set -a && . ./.env.local && set +a
pnpm audit:auth
```

Authenticated cases use `generateSessionCookie` from `@auth0/nextjs-auth0/testing`,
so no real user account or browser is needed.

## Coverage

| Group | What it asserts |
| ----- | --------------- |
| A | Anonymous requests: protected routes redirect or 401, never 200 |
| B | Login transaction: PKCE `S256`, random `state`/`nonce`, state bound to the encrypted transaction cookie, `code_verifier` never in the URL |
| C | Open redirect: `returnTo` sanitised to same-origin on login (incl. `//evil.com`) |
| D | Valid session: pages render, and access/refresh/ID tokens never reach HTML or JSON |
| E | Forged sessions: tampered, garbage, wrong-secret, and expired cookies are all rejected |
| F | Callback CSRF: no `state`, no transaction cookie, or an unknown `state` all fail without leaking a stack trace |
| G | Logout: local cookie cleared, `id_token_hint` sent, redirect to the Auth0 logout endpoint |
| H | SDK endpoints: `/auth/profile` returns claims only; `/auth/access-token` never returns the refresh or ID token |
| I | Sensitive responses carry `no-store` |
| J | Session lifetime: `Max-Age` present, and `absoluteDuration` caps a long-lived session |
| K | Oversized sessions still decode (SDK chunks into `__session.0` / `.1`) |
| L | Route handlers reject unsupported methods |
| M | Authorization parameter injection: `redirect_uri`, `client_id`, `response_type`, `code_challenge[_method]`, `state`, `nonce` cannot be overridden from the query string |
| N | Randomness: `state`, `nonce`, `code_challenge`, `code_verifier` differ across logins; parallel transactions get distinct cookies |
| O | Oversized sessions chunk into `__session__0/1/…` under the 4096-byte browser limit, the unchunked cookie is deleted, and logout clears every chunk |
| P | Legacy `appSession` cookie: garbage and wrong-secret values rejected, `__session` wins when both are present |
| Q | Callback binding: wrong `state`, a transaction cookie from another login, and a reflected `error_description` all fail safely |
| R | Dynamic base URL mode (`audit4-dynamic.mjs`, separate server) — see below |
| S | Malformed-session robustness (`audit5-malformed-session.mjs`) — **surfaces the SDK bug below** |

## Dynamic base URL mode

`audit4-dynamic.mjs` needs a server started *without* `APP_BASE_URL`, so it runs
separately:

```bash
grep -v '^APP_BASE_URL' .env.local > .env.dynamic
cp .env.local .env.backup && cp .env.dynamic .env.local
pnpm dev -p 3001
BASE=http://localhost:3001 node audit/audit4-dynamic.mjs
cp .env.backup .env.local          # restore
```

Note that `fetch()` cannot set `Host` — it is a forbidden header name and is
dropped silently, which makes the check pass for the wrong reason. The script
uses `node:http` for that one case.

## Known findings

### SDK bug — middleware 500s on a decryptable-but-malformed session cookie

This is the one worth reporting upstream: an unhandled exception (HTTP 500) in
`auth0.middleware`, reachable by an **unauthenticated** user, on the latest
published version (v4.25.0) and on `main`.

**Reproduce:** `node audit/audit5-malformed-session.mjs` (group S). An anonymous
visitor hits `/auth/login`, takes the `__txn_` cookie it is handed, and replays
that value as `__session`. Every subsequent request then returns 500 instead of
being treated as unauthenticated:

```
[FAIL] replaying the txn cookie as __session does NOT 500   status=500
[FAIL] same cookie on a page route does NOT 500             status=500
[PASS] control: an undecryptable cookie is handled (401)     status=401
```

**Root cause.** On any non-auth request the middleware rolls the session:

```ts
const { error, session } = await this.getSessionWithDomainCheck(req.cookies);
if (!error && session) {
  await this.sessionStore.set(req.cookies, res.cookies, { ...session });
}
```

`getSessionWithDomainCheck` returns any cookie that *decrypts*, without checking
its shape. `sessionStore.set` (stateless-session-store.ts, also stateful) then does:

```ts
const maxAge = this.calculateMaxAge(session.internal.createdAt);   // no ?.
```

If the payload has no `internal` block this throws
`TypeError: Cannot read properties of undefined (reading 'createdAt')`, which
propagates out of `middleware` as a 500. Tellingly, `getSessionWithDomainCheck`
two lines up already guards `session.internal?.sessionExpiresAt` and
`session.internal?.mcd` with optional chaining — the write path just missed this one.

**Why it is reachable pre-auth.** Every cookie the SDK issues is encrypted with
the same key — `hkdf("sha256", secret, "", "JWE CEK", 32)` — with no per-purpose
domain separation. The transaction cookie is handed to any anonymous visitor of
`/auth/login`, and its payload (`nonce`, `codeVerifier`, `state`, `returnTo`, …)
has no `internal` block. So a valid-under-key ciphertext of the wrong shape is
obtainable without knowing `AUTH0_SECRET`. (Confirmed: the txn cookie decrypts
cleanly under the session key.)

**Impact — honest scoping.** Not an auth bypass: the replayed payload has no
`user`, and the request crashes before any authorization decision, so it cannot
impersonate anyone. The defect is (1) a spec/robustness violation — the contract
everywhere else is "unusable cookie ⇒ no session ⇒ 401/redirect", and the
decrypt layer already returns `null` for expired or undecryptable cookies — and
(2) a conditional availability issue: `__session` is not `__Host-` prefixed, so a
cookie planted in a victim's browser (subdomain cookie injection on a shared
parent domain, MITM on cleartext HTTP, sibling-origin XSS) yields a persistent
app-wide 500 the victim cannot easily self-diagnose.

**Precedent.** [Issue #2081](https://github.com/auth0/nextjs-auth0/issues/2081)
("Middleware crashes when JWT is expired") is the same class — middleware 500 on
a bad session cookie — which the maintainers accepted and fixed at the
`decrypt()` layer (catching `ERR_JWT_EXPIRED` / `ERR_JWE_*`). That fix covers
crypto failures but not structural ones, so this variant slips through.

**Fix (one line).** Guard the access —
`this.calculateMaxAge(session.internal?.createdAt)` with a null-createdAt branch
— or, better, validate shape in the store's `get()` and return `null` when
`internal.createdAt` is missing, so a malformed cookie is treated as no session
like every other bad cookie. Optionally add domain separation to the HKDF `info`
per cookie purpose so a transaction ciphertext cannot decrypt as a session at
all. An app-level stopgap is to wrap `auth0.middleware()` in try/catch and treat
a throw as unauthenticated; this example keeps the faithful README middleware so
the repro stays visible.

### Lower-severity observations


**Logout `returnTo` is not validated locally.** `handleLogout` in the SDK
(v4.25.0) forwards `?returnTo=` straight into `post_logout_redirect_uri` without
a same-origin check — unlike login, which sanitises via `toSafeRedirect`.
Verified not exploitable against a correctly configured tenant: Auth0 rejects an
unregistered URL with `400 invalid_request`. It becomes a real open redirect only
if **Allowed Logout URLs** contains a wildcard, so keep that list exact.

**`/auth/access-token` returns a bearer token without cache directives when the
token did not need refreshing.** This is a scope gap, not an oversight — worth
understanding before reporting it upstream.

`addCacheControlHeadersForSession` exists to remediate
[CVE-2025-48947](https://nvd.nist.gov/vuln/detail/CVE-2025-48947) (CWE-525,
"CDN Caching of Session Cookies", affecting 4.0.1–4.6.0), whose threat model is
a shared cache storing a response that carries `Set-Cookie`. Accordingly the SDK
couples the headers to the cookie write, in `#updateSessionAfterTokenRetrieval`:

```ts
if (sessionChanges) {
  await this.sessionStore.set(req.cookies, res.cookies, finalSession);
  addCacheControlHeadersForSession(res);   // only on this branch
}
```

`getSessionChangesAfterGetAccessToken` returns `undefined` when the access token
is still valid, so the common path — token unexpired, no refresh — writes no
cookie and therefore gets no cache headers, while the response body still
contains the access token. Verified against v4.25.0: `Cache-Control: null`,
`Set-Cookie` count 0.

The CVE is fully patched; what is not covered is
[RFC 6749 §5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1), which
requires `no-store` on *any* response containing tokens, independent of cookies.
`proxy.ts` in this example closes that gap by marking every `/auth/*` response
uncacheable.

**Dynamic base URL mode makes `redirect_uri` attacker-controllable, and only the
Auth0 allowlist stops it.** With `APP_BASE_URL` unset the SDK derives the base
URL from the request, and *both* `Host` and `X-Forwarded-Host` flow straight into
`redirect_uri` — there is no host allowlist in the SDK. `X-Forwarded-Proto`
likewise controls the scheme. Measured:

| Sent | Resulting `redirect_uri` |
| ---- | ------------------------ |
| *(none)* | `http://localhost:3001/auth/callback` |
| `Host: evil.example.com` | `http://evil.example.com/auth/callback` |
| `X-Forwarded-Host: evil.example.com` | `http://evil.example.com/auth/callback` |
| `X-Forwarded-Proto: https` | `https://localhost:3001/auth/callback` |

This is the SDK's documented design — the README states the Host header is
untrusted and Auth0's Allowed Callback URLs are the safety net — and it holds:
Auth0 answered `403 Callback URL mismatch` for the forged host.

The risk is the combination. Dynamic mode exists for preview deployments, which
is exactly where a wildcard entry like `https://*-myorg.vercel.app/auth/callback`
is most tempting. A wildcard removes the only control: any attacker-supplied host
matching the pattern would be accepted and the authorization code delivered off-
origin. `X-Forwarded-Host` matters most here, since a proxy that forwards a
client-supplied value makes this reachable without controlling DNS. Keep
`APP_BASE_URL` set on stable domains, register callback URLs explicitly, and make
sure the edge strips client-supplied `X-Forwarded-*`.
