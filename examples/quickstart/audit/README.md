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

## Known findings

**Logout `returnTo` is not validated locally.** `handleLogout` in the SDK
(v4.25.0) forwards `?returnTo=` straight into `post_logout_redirect_uri` without
a same-origin check — unlike login, which sanitises via `toSafeRedirect`.
Verified not exploitable against a correctly configured tenant: Auth0 rejects an
unregistered URL with `400 invalid_request`. It becomes a real open redirect only
if **Allowed Logout URLs** contains a wildcard, so keep that list exact.

**`/auth/access-token` shipped without cache directives.** The SDK calls
`addCacheControlHeadersForSession` on 13 responses but not on the one returning a
bearer token, so it had no `no-store` while the less sensitive `/auth/profile`
did. `proxy.ts` in this example compensates by marking every `/auth/*` response
uncacheable.
