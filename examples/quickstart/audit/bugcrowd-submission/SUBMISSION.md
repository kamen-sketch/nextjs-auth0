# Bugcrowd Submission

## Title

Enterprise IPSIE session-ceiling is not enforced by `getAccessTokenForConnection()` — third-party (Token Vault) access tokens keep minting after a mandated session termination (`@auth0/nextjs-auth0`)

## Affected component / version

- Package: `@auth0/nextjs-auth0`
- Confirmed on: `v4.25.0` and `main` (source-read + test-proven on this exact version; re-check on the current `main` before triage in case it has since moved)
- Function: `Auth0Client.getAccessTokenForConnection()` → `AuthClient.getSessionWithDomainCheck(cookies, { skipCeilingCheck: true })` (`src/server/client.ts`, `src/server/auth-client.ts`)
- Feature area: IPSIE-style enterprise session ceiling (`session_expiry`) combined with Connected Accounts / Token Vault

## CWE

**CWE-613: Insufficient Session Expiration** — the application does not correctly honor an established session-expiration/termination signal on one specific code path, allowing continued use of session-derived credentials after they should be dead.

(Secondary/contributing: CWE-284 Improper Access Control — a security decision, "is this session still valid," is enforced inconsistently across code paths that all rely on the same underlying session state.)

## CVSS v3.1

**Baseline vector (representative case — a typical read-scope third-party connection, e.g. calendar/profile read):**

```
AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N
Base Score: 4.9 (Medium)
```

**Rationale for each metric:**

| Metric | Value | Why |
|---|---|---|
| Attack Vector | Network | Exploited entirely over HTTP against the app; no local/physical access needed. |
| Attack Complexity | Low | No race condition, no timing window, no special configuration — just call an existing, documented SDK API with an already-issued session. |
| Privileges Required | Low | Requires possessing a session cookie / refresh token that was legitimately issued at some point (i.e. a real, prior authentication) — not exploitable from zero. |
| User Interaction | None | No victim action needed; the app (or a background job/webhook handler) triggers this on its own by calling `getAccessTokenForConnection()`. |
| Scope | Changed | The vulnerable component is the app's own session/ceiling enforcement, but the impact lands on a *different* security authority — the third-party API provider (Google, GitHub, Slack, etc.) whose access token keeps getting refreshed. |
| Confidentiality | Low (baseline) | Continued read access to whatever the connected third-party scope grants. |
| Integrity | None (baseline) | Baseline assumes a read-only connection scope. |
| Availability | None | Not a denial-of-service issue. |

**This is not a single fixed number** — Confidentiality/Integrity scale directly with what the app's third-party connection is scoped to, which this audit cannot generalize (see Impact below). For a write-capable connection (e.g. send-email, push-to-repo scopes), the honest vector becomes:

```
AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N
Base Score: 9.6 (Critical)
```

Triage should pick the vector that matches the specific program/app being assessed, not assume either end by default.

## Description

For enterprise (upstream-IdP-federated) connections, Auth0 supports a `session_expiry` claim — either asserted by the upstream IdP itself (Okta / OIDC enterprise connections, in alignment with the IPSIE SL1 profile) or set via a tenant Post-Login Action — which acts as a hard ceiling on how long an Auth0-issued session may be used, independent of any individual token's own TTL. This exists specifically to support enterprise session-termination scenarios: offboarding, compromise response, upstream IdP logout propagation.

`@auth0/nextjs-auth0` enforces this ceiling correctly and consistently for the primary session: `getSession()` and `getAccessToken()` both treat a session whose ceiling has passed as fully invalid (`isSessionCeilingReached()` inside `AuthClient.getSessionWithDomainCheck()`, `src/server/auth-client.ts`).

`getAccessTokenForConnection()` — the API used to obtain access tokens for *third-party* APIs via Connected Accounts / Token Vault — does not. It calls the same internal `getSessionWithDomainCheck()` with an explicit `{ skipCeilingCheck: true }` override:

```ts
// src/server/client.ts, ~line 1120
// Connection tokens follow the upstream IdP's own TTLs, not the IPSIE
// session ceiling — skip only the ceiling check, MCD domain validation
// still applies.
const { error: sessionError, session } =
  await authClient.getSessionWithDomainCheck(reqCookies, { skipCeilingCheck: true });
```

```ts
// src/server/auth-client.ts, ~line 3218
if (!skipCeilingCheck && isSessionCeilingReached(session.internal?.sessionExpiresAt)) {
  this.sessionStore.deleteByReqCookies(cookies).catch(...);
  return { error: null, session: null, exists: false };
}
```

Downstream, `getConnectionTokenSet()` (the function that exchanges the primary refresh token for a fresh connection access token) never references `sessionExpiresAt` or the ceiling at all — confirmed by reading the full function. It operates purely on a bare `tokenSet` (accessToken/refreshToken/expiresAt), with no session-level context, so there is no second layer where the ceiling could incidentally still apply.

**Why this is a real gap and not "the server catches it anyway":**

1. Reaching the ceiling never revokes anything server-side — `getSessionWithDomainCheck`'s enforcement is a pure local read-time check; `deleteByReqCookies` clears local cookie state only, no call to `/oauth/revoke` or equivalent. The refresh token stays fully valid at Auth0.
2. `session_expiry` is populated by a tenant-authored Post-Login Action / upstream IdP claim captured at *login* time — it is not something Auth0's token endpoint re-validates on a later refresh-token or connection-token-exchange grant. Confirmed by reading Auth0's own official documentation (Session Lifetime Limits, Session Lifecycle, Refresh Token Exchange with Token Vault, Connected Accounts for Token Vault): none of the Token Vault / refresh-token-exchange docs mention `session_expiry`, session ceilings, or session termination at all — the interaction between these two platform features is undocumented on Auth0's own platform side, not just in the SDK. The SDK's `skipCeilingCheck: true` rationale is not traceable to any official Auth0 or IPSIE source.
3. IPSIE's own charter (OpenID Foundation IPSIE working group) states its logout/termination scope is explicitly meant to reach beyond the primary session — *"define an interoperability profile of logout specifications to enable an identity provider to revoke sessions and tokens of downstream applications."* A connection token used to call a third-party API on the user's behalf is exactly this kind of downstream-application token, so this bypass runs counter to the feature's own stated purpose.

So the SDK-side check in `getSessionWithDomainCheck()` is the **only** enforcement point for this ceiling anywhere in the flow, and `getAccessTokenForConnection()` is the one code path that skips it — deliberately, per the code comment, but not per anything traceable to official documentation.

## Steps to reproduce

Two independent proofs are provided in `poc/`, at two different levels of rigor. Either is sufficient to reproduce; both are included because they were built to cross-validate each other.

### Method A — SDK-internal (vitest), no live Auth0 tenant needed

1. Clone `auth0/nextjs-auth0` (or this fork) and `npm install`.
2. Open `src/server/auth-client.test.ts` and paste in the single `it(...)` block from `poc/poc.proof.test.ts` (it's written to run in-place inside that file's existing `describe` blocks, using the harness's own `createSessionData`, `makeStore`, `makeCookies`, `DEFAULT`, `getMockAuthorizationServer`, `getDefaultRoutes`, `generateSecret`, `AuthClient` fixtures — all already in scope there).
3. Run `npx vitest run src/server/auth-client.test.ts -t "PROOF: skipCeilingCheck"`.
4. Observe: a session whose ceiling passed a full year ago is rejected by the default path (`session: null`) but returned in full via `{ skipCeilingCheck: true }`, and its refresh token successfully mints a brand-new connection access token (`FRESH_CONNECTION_TOKEN_MINTED_POST_CEILING`).
5. Revert the test file (`git checkout src/server/auth-client.test.ts`) — this step is not part of the vulnerability, just cleanup for a shared repo.

### Method B — real HTTP against a live example app, no vitest/JS tooling at all

This drives an actual running Next.js app (real dev server, real compiled SDK, real middleware) purely over HTTP from Python, to rule out the vitest harness being an artifact.

1. Stand up the SDK's own `examples/quickstart` app (or any minimal app using `@auth0/nextjs-auth0` v4.25.0+) with `npm run dev`, and note its `AUTH0_SECRET`.
2. Add `poc/connection-token-test.route.ts` to the app at `app/api/connection-token-test/route.ts` — it just calls `getAccessTokenForConnection()` and reports the resulting error code, since the SDK has no built-in HTTP endpoint for that call.
3. `pip3 install cryptography`
4. Run:
   ```bash
   AUTH0_SECRET=<the app's secret> python3 poc/poc_runtime.py http://localhost:3000
   ```
   (`poc_runtime.py` uses `poc/nextjs_auth0_jwe.py`, a from-scratch, independently cross-validated re-implementation of the SDK's session-cookie JWE scheme — HKDF-SHA256 + AES-256-GCM — to mint session cookies without touching any SDK/JS code.)
5. Observe 6/6 checks pass, in particular:
   - A session with `sessionExpiresAt` one year in the future: `/auth/profile` → 200, `/api/connection-token-test` → reaches Auth0 (`failed_to_exchange_refresh_token`, expected since the connection/refresh-token are fake).
   - The **same session with `sessionExpiresAt` one year in the past**: `/auth/profile` → 401 (ceiling correctly enforced), but `/api/connection-token-test` still returns `failed_to_exchange_refresh_token` — **not** `missing_session` — proving the ceiling made zero difference to this path. The control case (no refresh token at all) *does* return a local `missing_refresh_token`, confirming the script can tell "blocked locally" apart from "reached Auth0" when it should see the former.

Full narrative, source citations, and additional discussion: `../FINDING-ipsie-ceiling-connection-token-bypass.md`.

## Impact

IPSIE-style session ceilings exist specifically for enterprise session-termination scenarios: offboarding, compliance windows, breach response, upstream IdP session-timeout policy. The realistic failure mode this bug produces is exactly what that control is meant to prevent:

- A background job that periodically calls `getAccessTokenForConnection()` to sync a user's calendar, or a webhook handler that fetches a fresh GitHub/Slack token on demand, keeps working after the ceiling — no error, no signal that anything should have stopped.
- This specifically matters for **minting new** connection tokens after the ceiling. An already-cached, not-yet-expired connection token remaining usable is unavoidable bearer-token behavior and not specific to this bug. What this bug adds is the ability to keep *refreshing* that access indefinitely, past the point the primary session is correctly and verifiably dead.
- Actual severity is proportional to (a) how long past the ceiling an app keeps calling this API, and (b) what the connected third-party scope grants — read-only calendar access vs. email-send vs. source-repo-write are very different outcomes. This audit deliberately does not assign one universal severity, since it depends entirely on the specific app/tenant configuration (reflected in the two CVSS vectors above).

**What this is *not*:** it does not let an attacker obtain access without ever having authenticated, it does not bypass the primary session ceiling for `getSession()`/`getAccessToken()` (those are correctly enforced), and it does not itself revoke or steal any other user's tokens — the affected user is the one whose own session ceiling was reached.

## Suggested remediation

Either:

- **(a)** Drop `skipCeilingCheck: true` from `getAccessTokenForConnection()` so the primary-session ceiling gates connection-token minting the same as every other path, or
- **(b)** If "connection tokens follow the upstream IdP's own TTLs" is genuinely intended as a deliberate exception, make it an explicit, documented, opt-in behavior (it currently isn't mentioned anywhere in the "Session Expiry from the Upstream IdP" section of the SDK's own README/EXAMPLES.md, nor in any official Auth0 platform documentation found during this review), and add the regression test that's currently missing in either direction — the existing `describe("getSessionWithDomainCheck — IPSIE ceiling enforcement")` block has 4 tests and none of them exercise `skipCeilingCheck: true`.

Given the ceiling's whole purpose is enterprise-mandated termination, and per the Description above the SDK is the *only* enforcement point for it anywhere in this flow, **(a) is the safer default**; (b) is only reasonable if there's a concrete, deliberate use case (e.g. an explicitly opt-in long-running background sync meant to outlive the interactive session).

## Supporting material

- `poc/poc.proof.test.ts` — SDK-internal vitest PoC (Method A)
- `poc/poc_runtime.py`, `poc/nextjs_auth0_jwe.py`, `poc/connection-token-test.route.ts` — live-HTTP PoC (Method B)
- `poc/README.md` — how to run both
- `../FINDING-ipsie-ceiling-connection-token-bypass.md` — full writeup with additional source citations and the official-documentation research this submission's Description section summarizes
