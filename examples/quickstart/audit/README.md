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
