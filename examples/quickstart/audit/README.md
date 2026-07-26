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
| S | Malformed-session robustness (`audit5-malformed-session.mjs`) — surfaces the middleware-500 bug below |
| T | `returnTo` open redirect (`audit6-returnto-open-redirect.mjs` + `returnto-open-redirect.callback-proof.test.ts`) — P4, see below |
| U | Connection-token cache not invalidated on shrink (`audit7-connection-token-resurrection.mjs`) — real bug, **security framing retracted on review**: `connectionTokenSets` is a pure cache with no gatekeeping role. Writeup: [`FINDING-connection-token-resurrection.md`](./FINDING-connection-token-resurrection.md) |
| V | Connect-account completion not bound to initiating session (`connect-account-cross-session.callback-proof.test.ts`) — SDK-level defense confirmed absent; server-side (Auth0) enforcement **not yet verified**, live test designed but on hold pending manual follow-up. Writeup: [`FINDING-connect-account-cross-session.md`](./FINDING-connect-account-cross-session.md) |

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

### Stale connection-token cache entry survives a shrink (not a security finding — see retraction)

> **Retracted as a security finding.** `connectionTokenSets` has exactly one
> consumer in the whole SDK (`getAccessTokenForConnection()` in `client.ts`),
> where an existing entry only decides whether a network round-trip can be
> skipped — it is never a gate. `getAccessTokenForConnection('x')` succeeds
> identically whether or not `x` is currently in the array, as long as the
> primary refresh token is valid. So even a correctly-cleaned-up array was
> never preventing anything; "removing an entry" was a cache-size
> optimization, not a revocation. The mechanism described below is real and
> reproduces exactly as documented, but the consequence is a stale cache
> entry / unbounded cookie growth, not broken access control. Full detail:
> [`FINDING-connection-token-resurrection.md`](./FINDING-connection-token-resurrection.md).

**Severity: real, but not a classic VRT category — closer to CWE-459
(Incomplete Cleanup) / broken revocation than a textbook web vuln.** Found by
going deeper than input validation: reviewing what happens when the SDK's own
*array-shrink* path runs, not what happens to a malicious string. No attacker
network position, no forged cookie, no race timing required — it reproduces
100% deterministically from the app's own normal operation. Present on v4.25.0
and `main`.

**The bug.** `getAccessTokenForConnection()` stores each entry of
`session.connectionTokenSets` in its own cookie, named positionally: `__FC_0`,
`__FC_1`, `__FC_2`, … `StatelessSessionStore.get()` reconstructs the array by
decrypting *every* cookie whose name starts with `__FC`, with no regard for how
many entries the current session actually has. `connectionTokenSets` is a
public field of `SessionData` and is passed into and returned from the
documented `beforeSessionSaved` hook — the natural, expected way to implement
"let the user disconnect a linked account." When an app does that — returns a
*shorter* `connectionTokenSets` array from the hook — `StatelessSessionStore.set()`
only writes cookies for indices `0..newLength-1`. It never deletes the trailing
`__FC_N` cookies that are no longer needed. Contrast this with the *main*
session cookie's chunking (`setChunkedCookie` in cookies.ts), which explicitly
deletes trailing chunks when a session shrinks — the equivalent cleanup for
`connectionTokenSets` cookies simply doesn't exist.

The orphaned cookie is not expired (it has the connection's normal, full-length
TTL), so it isn't pruned by the JWE-expiry check either — that check only drops
entries whose *own* encrypted `exp` has passed
(`stateless-session-store.test.ts`, "...exclude a connection when the JWE is
expired"), and this one hasn't. It just sits in the browser, fully valid, until
`get()` picks it straight back up on the user's very next request — no attacker
action needed.

**Proof** (`audit7-connection-token-resurrection.mjs`, runs directly against
the real built `StatelessSessionStore`, no HTTP, no mocking of SDK logic — only
the cookie *transport* between two `set()` calls is simulated, exactly as a
browser applies `Set-Cookie` headers):

```
Step 1: connect three accounts (A, B, C) → __FC_0, __FC_1, __FC_2
Step 2: "disconnect C" saves connectionTokenSets = [A, B]
        did this response delete __FC_2?  NO
Step 3: next read → connectionTokenSets = ["connA","connB","connC"]
FINDING CONFIRMED — connC's token: "tokC" (unchanged, still fully valid)
```

The script also runs a control: a real `logout()` (`StatelessSessionStore.delete()`)
correctly clears **all** `__FC_*` cookies via
`getConnectionTokenSetsCookies(...).forEach(...)`. That confirms the gap is
specific to `set()` — any shrink short of full logout — not a general cookie-
cleanup miss.

**Impact.** If an app's UI tells the user a connection was disconnected, and the
app (reasonably) trusts `session.connectionTokenSets` as the source of truth
for "is this still linked," the disconnect does not actually hold — the stale
token is available again for the app to use against the third-party API on the
user's next request, with no indication anything is wrong. This is a
self-contained failure of the app's own revocation logic (not a third party
attacking the user), so it's not "exploitable" in the classic sense, but it
does mean a documented extension point silently does not do what a developer
implementing it would reasonably expect. It also compounds under concurrency:
two concurrent session-saves computed from the same stale base (e.g. a
"disconnect" request racing an unrelated token refresh) can produce the same
resurrection non-deterministically, since writes are positional/absolute with
no compare-and-swap — the sequential repro above is just the cleanest way to
show it.

**Where to report.** A GitHub issue on `auth0/nextjs-auth0` at minimum (clear
functional defect with a byte-for-byte repro); worth asking the maintainers
whether they'd rather handle it as a GHSA given the "silently un-revoke a
credential" angle — that judgment call belongs to them, not this audit.

**Fix.** In `StatelessSessionStore.set()`, before writing the new
`connectionTokenSets` cookies, delete any existing `__FC_N` cookie whose index
is `>= connectionTokenSets.length` — the same pattern `setChunkedCookie` already
uses for the main session cookie's trailing chunks.

**Scope.** Confirmed specific to `StatelessSessionStore` (`grep` for
`connectionTokenSets`/`__FC` in `stateful-session-store.ts` returns nothing) —
i.e. it hits every app that has *not* configured a custom `sessionStore`, which
is the SDK's default. Apps using database sessions (`sessionStore` option) are
unaffected: the whole session, `connectionTokenSets` included, is one blob
overwritten atomically in the developer's store, so a shrink just shrinks it.

### Open redirect (post-authentication) via `returnTo`

**Severity: low (Bugcrowd VRT: Open Redirect → GET-Based = P4).** Real bug, and
the same class Auth0 has advisoried before (GHSA-2mqv-4j3r-vjvp), but not a
bounty-grade finding, and here's the honest reason it can't be elevated: the
authorization code is exchanged for tokens **server-side in `handleCallback`
before** the redirect fires, so the redirect to the attacker origin carries no
code, token, or session — it's phishing-only, not account takeover. Present on
v4.25.0 and `main`.

**Right channel: a GitHub Security Advisory on `auth0/nextjs-auth0`, not
Bugcrowd.** Auth0's Bugcrowd program scopes the hosted service (`*.auth0.com`);
SDK bugs go through the repo's private disclosure and yield credit/a CVE, not a
service-bounty payout. A P4 open redirect there is low priority regardless.

**PoC.** `GET /auth/login?returnTo=/https://evil.example.com`. The victim logs in
normally; after a successful callback the app redirects them to
`https://evil.example.com/`.

**Why the sanitiser misses it — an unsafe composition of two individually-correct
functions.**

- `/auth/login` runs `toSafeRedirect(returnTo, appBaseUrl)`, which validates the
  *parsed URL's origin*. `"/https://evil.example.com"` parses as an absolute
  **path** on the app origin (`new URL("/https://evil.example.com", app)` →
  origin = app, pathname = `/https://evil.example.com`), so the origin check
  passes and the SDK stores the pathname verbatim in the transaction cookie.
- After a successful login, `defaultOnCallback` redirects to
  `createRouteUrl(transactionState.returnTo, appBaseUrl)`, and `createRouteUrl`
  calls `ensureNoLeadingSlash()`. Stripping the one leading slash turns
  `/https://evil.example.com` back into `https://evil.example.com`, which
  `new URL("https://evil.example.com", appBaseUrl)` resolves to a **different
  origin**.

Each function is reasonable alone; composed, `toSafeRedirect` "neutralises" the
payload into a path and `createRouteUrl` un-neutralises it back into an absolute
URL. Crucially this redirect is **purely application-side** — it is never sent to
Auth0 as a `redirect_uri`, so the Allowed Callback / Logout URL allowlists that
gate the login and logout redirects give **no protection here**.

**The SDK's own tests already treat these as attack payloads but miss this path.**
`src/test/fixtures/open-redirect-payloads.json` (485 entries) contains
`/https://google.com`, `/http://google.com`, `/javascript:alert(1)` and friends,
and `url-helpers.test.ts` asserts `toSafeRedirect(payload).toString()` starts with
the app origin. That assertion passes —
`toSafeRedirect("/https://google.com").toString()` is
`http://localhost:3000/https://google.com` — because the test checks the *full
URL string* and never simulates the `store pathname → createRouteUrl` round-trip
that the runtime actually performs. So the vector is covered in spirit and
missed in fact.

**Reproduce.**
- `node audit/audit6-returnto-open-redirect.mjs` — proves the two runtime
  primitives with the real SDK: the live `/auth/login` stores the payload
  verbatim, and the real `createRouteUrl` expands it off-origin.
- `audit/returnto-open-redirect.callback-proof.test.ts` — wire-level proof using
  the SDK's own test harness (mocked token exchange, no network): a successful
  `handleCallback` with `returnTo: "/https://evil.example.com"` returns
  `307 Location: https://evil.example.com/`. Verified passing against v4.25.0:

  ```
  [PROOF] status=307 Location=https://evil.example.com/ host=evil.example.com
  ✓ passed
  ```

**Scope / severity.** Post-authentication open redirect: needs the victim to
complete a login through the crafted link (or an active SSO session that
completes it silently). Standard open-redirect impact — phishing that inherits
the trusted login origin, and a stepping stone for token/code exfiltration in
flows that place secrets in the URL. `javascript:` and `data:` payloads also
survive the sanitiser (`/javascript:alert(1)` → `javascript:alert(1)`), though
browsers do not navigate to those via a `Location` header, so the realistic sink
is the `http(s)://` cross-origin redirect.

**Fix.** After `ensureNoLeadingSlash`/`normalizeWithBasePath`, reject any path
that still parses as absolute or scheme-relative before basing it — or re-run the
same-origin check on the *final* `createRouteUrl` result, not only on the stored
value at login time. Add the `store-pathname → createRouteUrl` round-trip to the
`open-redirect-payloads.json` test so the fixture's own payloads are exercised
end to end.

### SDK bug — middleware 500s on a decryptable-but-malformed session cookie

**File this as a bug, not a security advisory.** The same class —
[#2081](https://github.com/auth0/nextjs-auth0/issues/2081), "Middleware crashes
when JWT is expired" — was handled as an ordinary bug, and this is the same
shape: the middleware should degrade to "no session" on an unusable cookie, and
instead it throws. Treating it as a vulnerability oversells it (see *Scope*
below), so the report should be a plain bug report.

**The claim, stated precisely.** It is not "you can send a 500" — anyone can make
any server 500 with bad input; that alone is not interesting. The claim is a
*contract violation*:

> `auth0.middleware` handles an invalid session cookie by throwing an unhandled
> `TypeError` (→ HTTP 500) in one specific case — a cookie that **decrypts** but
> whose payload has no `internal` block — whereas every other invalid-cookie case
> (undecryptable, tampered, expired) is handled gracefully by returning `null`
> and treating the request as unauthenticated. So the SDK already has a defined,
> safe behaviour for bad cookies; this input misses it and crashes instead.

The interesting part is not the 500 itself but that it is the *odd one out*: the
control case in the repro (an undecryptable cookie) returns a clean 401 from the
same code path, which is exactly what the malformed-but-decryptable cookie should
also do.

Confirmed on v4.25.0 and on `main`, and in a **production build**
(`next build && next start`, not just `next dev`): all of `/`, `/dashboard` and
`/api/me` return `500 Internal Server Error`, with
`TypeError: Cannot read properties of undefined (reading 'createdAt')` in the
server log.

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

**How the repro obtains such a cookie.** You need a payload that decrypts under
the session key but has no `internal` block. The audit uses the transaction
cookie for this: every cookie the SDK issues shares one key —
`hkdf("sha256", secret, "", "JWE CEK", 32)`, no per-purpose domain separation —
and the `__txn_` cookie handed to any anonymous `/auth/login` visitor has exactly
that shape (`nonce`, `codeVerifier`, `state`, `returnTo`, … and no `internal`).
This is just a convenient way to demonstrate the crash without `AUTH0_SECRET`; it
is not required for the bug. Any stale, truncated, or version-mismatched
`__session` value that still decrypts hits the same path.

**Scope — why this is a bug and not a vulnerability.** It is *not* an auth
bypass: the payload has no `user`, and the request crashes before any
authorization decision, so nothing is impersonated and no protected data is
returned. The only real-world consequence beyond "an error page instead of a
redirect" would be availability, and only under extra preconditions (a malformed
`__session` planted in a victim's browser — `__session` is not `__Host-`
prefixed — via subdomain cookie injection, cleartext-HTTP MITM, or sibling-origin
XSS, each of which is its own bigger problem). That is thin, so it is mentioned
for completeness, not as the headline. The defensible core is the robustness
contract violation, which stands on its own regardless of the security angle.

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
