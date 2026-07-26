# Connection tokens keep minting after the enterprise session ceiling is reached

**Component:** `@auth0/nextjs-auth0` — `Auth0Client.getAccessTokenForConnection()`
/ `AuthClient.getSessionWithDomainCheck({ skipCeilingCheck: true })`
**Affected:** confirmed on source as of this writing (matches v4.25.0 and `main`)
**Status:** confirmed, deterministic, at the SDK level. Unlike the
connect-account finding, this one does **not** carry a "maybe Auth0 catches it
server-side anyway" caveat — see §3 for why.

---

## 1. Summary

For enterprise connections, a Post-Login Action can stamp a `session_expiry`
claim into the ID token — an upstream-IdP-mandated ceiling on how long the
session may be used, independent of any token's own TTL. The SDK enforces
this correctly and consistently for the *primary* session and access token:
`getSession()`, `getAccessToken()` (both browser and server paths) all treat
a past-ceiling session as gone.

`getAccessTokenForConnection()` — the API for fetching tokens to call
*third-party* APIs (Google, GitHub, Slack, etc.) on the user's behalf — does
not. It explicitly bypasses the ceiling check, and its underlying token
exchange has no ceiling awareness at all. So once an enterprise's
session-termination mandate should have killed a session, an app can still
successfully mint fresh third-party API access for that user, indefinitely,
through this one specific call.

## 2. Root cause

`getAccessTokenForConnection()` (`src/server/client.ts`, ~line 1120) passes
`skipCeilingCheck: true`, with a comment stating the rationale:

```ts
// Connection tokens follow the upstream IdP's own TTLs, not the IPSIE
// session ceiling — skip only the ceiling check, MCD domain validation
// still applies.
const { error: sessionError, session } =
  await authClient.getSessionWithDomainCheck(reqCookies, { skipCeilingCheck: true });
```

Inside `getSessionWithDomainCheck()` (`src/server/auth-client.ts`, ~line 3218):

```ts
if (!skipCeilingCheck && isSessionCeilingReached(session.internal?.sessionExpiresAt)) {
  this.sessionStore.deleteByReqCookies(cookies).catch(...);
  return { error: null, session: null, exists: false };
}
```

For the primary path, this same guard runs unconditionally
(`getTokenSet()`, ~line 2482, no skip flag). Only `getAccessTokenForConnection`
opts out.

Downstream, `getConnectionTokenSet()` — the function that actually exchanges
the primary refresh token for a fresh connection access token — never
references `sessionExpiresAt` or the ceiling at all; confirmed by reading the
full function. It operates purely on a bare `tokenSet` object (accessToken,
refreshToken, expiresAt), with no session-level context, so there is no
second layer where the ceiling could be checked even incidentally.

## 3. Why this is not "maybe the server catches it anyway" — confirmed, not assumed

Unlike the connect-account finding, this one doesn't carry an open question
about server-side enforcement. Two independent facts rule it out:

1. **The SDK's own docs state the ceiling comes from a tenant-authored
   Post-Login Action**, not a native Auth0 platform feature
   (README.md / EXAMPLES.md, "Session Expiry from the Upstream IdP": *"add a
   Post-Login Action on your Auth0 tenant that sets the `session_expiry`
   claim"*). Post-Login Actions run during the authentication/login flow —
   they don't re-run on every subsequent refresh-token or token-exchange
   grant. There is no platform-level mechanism visible anywhere that would
   cause Auth0 to independently re-check this claim when
   `getConnectionTokenSet()` later exchanges the same refresh token for a
   federated connection access token.
2. **Reaching the ceiling never revokes anything server-side.** The
   enforcement in `getSessionWithDomainCheck` is a pure local read-time
   check — `deleteByReqCookies` clears the *local* session/cookie state; no
   call to Auth0's `/oauth/revoke` or equivalent happens. The refresh token
   remains fully valid at Auth0 for as long as it otherwise would.

So the SDK-side check is the *only* enforcement point for this ceiling, full
stop — and `getAccessTokenForConnection` is the one code path that skips it.

## 4. Proof (deterministic, no live network)

`examples/quickstart/audit/ipsie-ceiling-connection-token-bypass.proof.test.ts`
— written against the SDK's own `auth-client.test.ts` harness (msw-mocked
Auth0). Constructs a session whose `sessionExpiresAt` is a full year in the
past (not a 30-second leeway edge case), and:

1. Calls the default `getSessionWithDomainCheck()` (what `getSession()`/
   `getAccessToken()` use) — confirms the session is correctly rejected.
2. Calls it again with `{ skipCeilingCheck: true }` (what
   `getAccessTokenForConnection()` actually passes) — the same session comes
   back in full.
3. Feeds that session's `tokenSet` into `getConnectionTokenSet()` — it
   successfully exchanges the refresh token for a brand-new, distinctly-named
   connection access token, proving the mint genuinely succeeds, not just
   that a stale cache entry survived.

**Observed:**

```
[PROOF] Default getSessionWithDomainCheck() with a ceiling 1 year in the past:
[PROOF]   session: null (ceiling enforced)
[PROOF] getSessionWithDomainCheck(cookies, { skipCeilingCheck: true }):
[PROOF]   session: RETURNED IN FULL, ceiling ignored
[PROOF] getConnectionTokenSet() using the post-ceiling session's refresh token:
[PROOF]   error: null
[PROOF]   minted access token: FRESH_CONNECTION_TOKEN_MINTED_POST_CEILING
✓ passed
```

**Existing test coverage checked, confirms this is untested territory:** the
SDK already has a dedicated, well-written
`describe("getSessionWithDomainCheck — IPSIE ceiling enforcement")` block
with 4 tests (ceiling passed → rejected; ceiling fires → cleans up store;
ceiling in future → passes; ceiling absent → passes). None of them exercise
`skipCeilingCheck: true`. The bypass this finding is about has no regression
test in either direction — nothing currently locks in "this is intentional
and here's what it allows," nor would anything break if it were tightened.

## 4b. Runtime confirmation (real HTTP, real server, no JS tooling)

The proof above runs the SDK's own code but only reachable through its
internal vitest harness. To rule out that being an artifact of that harness,
the same claim was re-verified against the actual running example app —
real Next.js dev server, the real compiled `@auth0/nextjs-auth0` dist, real
middleware — driven entirely by a from-scratch Python HTTP client with no
JS/vitest involved at any point.

`audit/nextjs_auth0_jwe.py` independently re-implements the SDK's session-
cookie scheme (`src/server/cookies.ts`) — HKDF-SHA256 key derivation and
AES-256-GCM, hand-built JWE Compact Serialization — using only Python's
`cryptography` package. Before being trusted for anything, it was
cross-validated bidirectionally: a cookie minted by the real SDK's
`generateSessionCookie()` decrypts correctly here, and a cookie minted here
decrypts correctly via the SDK's own `decrypt()` — byte-for-byte compatible,
independently confirmed both ways.

`audit/verify_runtime.py` then crafts session cookies purely in Python and
drives the live server:

```bash
AUTH0_SECRET=... python3 audit/verify_runtime.py http://localhost:3000
```

(needs `app/api/connection-token-test/route.ts` — a small route added
alongside this test, calling `getAccessTokenForConnection()` and reporting
its error code, since the SDK has no built-in HTTP endpoint for that method)

**Result — 6/6, including a sanity check and a control:**

```
[PASS] Sanity: /auth/profile accepts a from-scratch Python-minted session cookie
[PASS] /auth/profile: ceiling 1yr in the FUTURE is accepted
[PASS] /api/connection-token-test: reaches Auth0 for a FUTURE-ceiling session
[PASS] /auth/profile: ceiling 1yr in the PAST is REJECTED (401)
[PASS] /api/connection-token-test: PAST-ceiling session reaches Auth0 too —
       error code failed_to_exchange_refresh_token, NOT missing_session
[PASS] CONTROL: no refresh token -> missing_refresh_token (a genuinely local
       error, proving this test can tell "blocked locally" apart from
       "reached Auth0" when it should see the former)
```

The distinguishing signal is the error *code*, not just success/failure:
`AccessTokenForConnectionErrorCode.MISSING_SESSION` would mean the SDK
blocked the request locally (ceiling enforced, same as `/auth/profile`);
`FAILED_TO_EXCHANGE` means the request reached Auth0's token endpoint and
was rejected *there* (fake connection name, fake refresh token — expected).
For the year-past-ceiling session, the code was `failed_to_exchange_refresh_token`
— identical to the future-ceiling baseline — confirming the ceiling made no
difference to this code path at runtime, end to end, through the real stack.

## 5. Impact

IPSIE-style session ceilings exist specifically for enterprise
session-termination scenarios: offboarding, compliance windows, breach
response, upstream IdP session timeout policy. The realistic failure mode is
exactly the kind of *silent, ongoing* access this feature is meant to stop:

- A background job that periodically calls `getAccessTokenForConnection()`
  to sync a user's Google Calendar, or a webhook handler that fetches a
  fresh GitHub token on demand, keeps working after the ceiling — no error,
  no indication anything should have stopped.
- This only matters for *minting new* connection tokens after the ceiling
  (an already-cached, not-yet-expired connection token would remain usable
  regardless, same as any bearer token — that part is unavoidable and not
  specific to this bug). The bypass is what lets the app keep *refreshing*
  that access indefinitely, past the point the primary session is correctly
  dead.
- Severity is proportional to how long past the ceiling an app keeps trying,
  and how sensitive the connected third-party API is (calendar read vs.
  email send vs. code repo write, for example) — this audit can't quantify
  that generically since it depends entirely on what a given app connects
  to and how it uses `getAccessTokenForConnection()`.

## 6. Suggested fix

Either:

- **(a)** Drop `skipCeilingCheck: true` from `getAccessTokenForConnection()`
  and let the primary-session ceiling gate connection-token minting like
  everything else, or
- **(b)** If the "connection tokens follow the upstream IdP's own TTLs"
  rationale is intentional policy, document it explicitly as a known
  IPSIE-ceiling exception (it currently isn't mentioned in the "Session
  Expiry from the Upstream IdP" section of EXAMPLES.md/README.md at all),
  and add the regression test that's currently missing in either direction,
  so the tradeoff is a documented, deliberate design decision rather than an
  implicit one a reader only discovers by tracing the code.

Given the ceiling's whole purpose is enterprise-mandated termination and the
SDK is the only enforcement point (§3), (a) is the safer default; (b) is
reasonable only if there's a concrete case where continued third-party access
past the ceiling is actually desired behavior (e.g. a long-running background
sync that's explicitly meant to outlive the interactive session) — which
would need to be an opt-in, not the current unconditional bypass.

## 7. Official documentation check — is `skipCeilingCheck: true` documented/intended, or a gap?

Checked sources external to this SDK's own README/EXAMPLES.md:

- Auth0 docs: *Session Lifetime Limits* (`session_expiry` / upstream-IdP ceiling)
- Auth0 docs: *Session Lifecycle*
- Auth0 docs: *Refresh Token Exchange with Token Vault*
- Auth0 docs: *Connected Accounts for Token Vault*
- Auth0 docs: *Token Vault* (overview)
- IPSIE itself: `oauth.net/ipsie/` and the OpenID Foundation IPSIE working-group charter (`openid.net/wg/ipsie/ipsie-charter`)

**Findings:**

1. Auth0's own docs describe `session_expiry` strictly as *"an upper bound on
   the user's session"* (the primary Auth0 session, evaluated as the minimum
   of the upstream IdP claim, the tenant's absolute session expiration, and
   any Actions-set expiry). None of the Token Vault, Refresh Token Exchange,
   or Connected Accounts pages mention `session_expiry`, session ceilings, or
   session termination at all. The refresh-token-exchange doc describes
   validation purely as: does the refresh token belong to a known user
   profile, does that profile have the requested connected account — no
   session-state check is documented anywhere in that flow.
2. That means this isn't just under-documented in the SDK — **the
   interaction between these two Auth0 platform features (IPSIE session
   ceiling, and Token Vault/Connected Accounts refresh-token exchange) is
   undocumented on the Auth0 platform side too.** There is no official page
   asserting "Token Vault exchanges are also bound by `session_expiry`," but
   there is equally no page asserting "Token Vault exchanges are
   intentionally exempt from it." The SDK code comment's rationale
   ("connection tokens follow the upstream IdP's own TTLs, not the IPSIE
   session ceiling") is not traceable to any Auth0 or IPSIE source found —
   it reads as the SDK authors' own interpretive choice, not a cited platform
   guarantee.
3. IPSIE's own charter states its logout/termination scope is explicitly
   **not** limited to the primary session: *"Define an interoperability
   profile of logout specifications to enable an identity provider to revoke
   sessions and **tokens of downstream applications**."* A connection token
   used to call a third-party API (Google, GitHub, Slack) on the user's
   behalf is conceptually exactly this kind of downstream-application token
   — the exact category IPSIE's stated purpose is meant to reach.

**Conclusion:** `skipCeilingCheck: true` is not confirmed anywhere as
documented, intentional Auth0 platform behavior — neither Auth0's own docs
nor the IPSIE spec/charter say connection-token minting is meant to survive
past the session ceiling. It's an unaddressed gap in both the SDK and the
platform docs, and it runs against IPSIE's own stated goal of termination
reaching "tokens of downstream applications." (This audit could not test
Auth0's live backend behavior for a real IPSIE-enabled enterprise
connection + Token Vault combination — that would need a live tenant
configured with both features — so this conclusion rests on the absence of
any documented exemption, combined with the already-demonstrated fact from
§3–§4b that the SDK is the sole enforcement layer regardless of what Auth0's
backend does.)

**Practical verdict:** yes, this is a security issue — a real,
runtime-confirmed access-control gap (insufficient session expiration,
comparable to CWE-613) in the one code path meant to gate access after an
enterprise-mandated session termination. It's not a critical/RCE-class bug;
it's a stale-session/broken-session-management class issue whose actual
severity is bounded by what a given app does with
`getAccessTokenForConnection()` after termination — which is why §5
deliberately doesn't assign a single generic severity number.
