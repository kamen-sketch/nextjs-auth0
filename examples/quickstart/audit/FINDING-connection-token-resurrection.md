# Revoked connection tokens are silently and permanently resurrected

**Component:** `@auth0/nextjs-auth0` — `StatelessSessionStore` (the default session
store; no `sessionStore` option configured)
**Affected:** v4.25.0 (latest published) and `main` at the time of testing
**Class:** CWE-459 (Incomplete Cleanup) / CWE-613 (Insufficient Session
Expiration) — broken revocation, not a classic input-validation vulnerability
**Reporter posture:** documented for the maintainers to triage; not yet
reported upstream

---

## 1. Summary

When an application removes an entry from `session.connectionTokenSets` (the
SDK's mechanism for storing per-connection access tokens obtained via
`getAccessTokenForConnection()`) — the only realistic way to do this is via the
documented `beforeSessionSaved` hook, since the SDK has no
`disconnect`/`revoke`-a-connection API of its own — the removal does not take
effect. The connection's access token cookie is never deleted, so it is
silently **read back into the session on the user's very next request**, with
no attacker action, no race condition, and no forged input required. Once
resurrected, the entry becomes a permanent part of the session's steady state:
every subsequent write re-persists it, and the *only* way to actually remove it
is a full logout.

This is not a hidden edge case triggered by crafted input — it is what happens
when the SDK's **own** array-shrink code path runs, discovered by asking "what
happens when session data legitimately gets smaller?" rather than "what happens
if I send it garbage?".

## 2. Why this matters (and why we're not over-claiming)

We want to be precise about what this is and is not, because the honest answer
determines whether this belongs in a GitHub issue or a security advisory. This
section was tightened after a specific, useful challenge during review: *"in
the real world, if a token is stolen, doesn't it stay valid regardless of
logout anyway?"* That's true, and it's worth answering directly before
describing this finding's impact, because the two are easy to conflate and
they are not the same thing.

**The "stolen token survives logout" question, answered directly, because
this SDK does something worth crediting here.** For the *primary* Auth0
refresh token, no — this SDK actively defends against exactly that scenario.
`handleLogout()` calls `performTokenRevocation()` against the refresh token
before clearing the session
(`src/server/auth-client.ts`, ~line 1114), with an explicit code comment —
*"Revoke the refresh token before clearing the session so it cannot be
replayed after logout (e.g. from a stolen session cookie)"* — and dedicated
test coverage (`auth-client.test.ts`, `describe("refresh token revocation on
logout")`, 6 tests). So if an attacker has a copy of a stolen session cookie
from *before* the legitimate user logs out, that copy cannot be used to mint
*new* tokens after logout — refresh will fail. This extends transitively to
connection tokens too: `ConnectionTokenSet` has no refresh token of its own
(`src/types/token-vault.ts`) — refreshing one requires re-presenting the
*primary* refresh token to Auth0's federated-connection-token-exchange
endpoint (`getConnectionTokenSet()`, `src/server/auth-client.ts` ~line 3321),
which is now revoked. The only thing that survives any logout, in this SDK or
any OAuth system, is the *last already-issued* access token, valid until its
own short TTL naturally expires — that's inherent to stateless bearer-token
validation everywhere, not a gap in this SDK.

**This finding is not that scenario at all — no theft, no attacker.** The
repro in §4 has zero attacker action. The *legitimate* user, in their own
unmodified browser, asks the app to forget a connection; the app tries to
comply; the removal silently fails and the entry comes back on the user's own
next page load. This is a data-integrity bug in the SDK's own session
bookkeeping, not a credential-theft or revocation-window problem. Given that,
the honest ceiling on what "disconnect" could ever guarantee — even with this
bug fixed — is narrower than "instantly kill the token everywhere": it was
always just "stop *this app* from continuing to offer/use this token going
forward, locally," the same way logout's refresh-token revocation stops
*future* token issuance rather than retroactively invalidating an
already-issued access token. This bug takes away even that narrower, local
guarantee.

**What it is:** an application-level revocation control silently fails,
permanently, with no workaround short of destroying the entire session. That
is a real defect in the class CWE-613 exists for — "insufficient session
expiration" is exactly "a security-relevant piece of state should have been
terminated and was not." An app whose UI tells a user "Google account
disconnected" while continuing to hold (and remaining able to use) a live
access token for that connection has a broken trust boundary, regardless of
whether an external attacker is involved.

**What it is not:**
- **Not remotely exploitable.** There is no attacker action anywhere in the
  repro. Nothing here lets a third party read, forge, or gain a *new*
  capability they didn't already have.
- **Not a credential-theft bug.** The resurrected token is one the app already
  legitimately possessed a moment earlier; the bug is failing to forget it, not
  leaking it to anyone new.
- **Not a logout/revocation-window bug.** Unlike the primary refresh token
  (which the SDK correctly revokes on logout, see above), this finding isn't
  about what survives logout at all — it reproduces with no logout step
  anywhere in the sequence.
- **Not necessarily "live" at the third-party IdP.** Whether the resurrected
  token can still be used to call Google/GitHub/etc. depends on whether the
  app's "disconnect" feature *also* revokes the grant server-side at the IdP
  (a separate step this SDK doesn't provide either). If it does, the
  resurrected token is a dead credential and the impact is closer to
  "confusing UI state." If it doesn't — which is plausible, since the SDK
  offers no revoke-at-IdP helper either, and many "disconnect" implementations
  are local-only — the app can continue actually calling the third-party API
  on the user's behalf after they explicitly asked it to stop.

Given that, we classify this as: **a real, deterministic, permanent defect
with conditional but plausible security impact**, worth a GitHub issue at
minimum, with the security angle (CWE-613-style broken revocation) flagged for
the maintainers to decide whether it warrants a GHSA. We are not asserting a
CVE-worthy vulnerability, and we did not find a way to chain this into
something stronger (see §7).

## 3. Root cause

`StatelessSessionStore` stores each entry of `session.connectionTokenSets` in
its **own** cookie, named **positionally** — `__FC_0`, `__FC_1`, `__FC_2`, …
(`src/server/session/stateless-session-store.ts`):

```ts
// set() — writes one cookie per array entry, indices 0..length-1 only
if (connectionTokenSets?.length) {                               // line 129
  await Promise.all(
    connectionTokenSets.map((connectionTokenSet, index) =>       // line 131
      this.storeInCookie(
        reqCookies, resCookies, connectionTokenSet,
        `${this.connectionTokenSetsCookieName}_${index}`,        // line 136
        maxAge
      )
    )
  );
}
```

```ts
// get() — reconstructs the array from EVERY cookie matching the prefix,
// with no regard for how many entries the current session should have
const connectionTokenSetsCookies =
  this.getConnectionTokenSetsCookies(reqCookies);                 // line 74-75
const connectionTokenSets = [];
for (const cookie of connectionTokenSetsCookies) {                 // line 78
  ...
  connectionTokenSets.push(decryptedCookie.payload);               // line 85
}
```

```ts
// getConnectionTokenSetsCookies() — a bare prefix match, blind to length
private getConnectionTokenSetsCookies(cookies) {                   // line 248
  return cookies.getAll().filter((cookie) =>
    cookie.name.startsWith(this.connectionTokenSetsCookieName)     // line 254
  );
}
```

**The gap:** `set()` only ever writes indices `0..connectionTokenSets.length-1`.
When the array shrinks (3 entries → 2), it never deletes the now-unused
`__FC_2`. That cookie is not malformed and not expired — it is a fully valid,
correctly-encrypted ciphertext with its own full-length TTL — so nothing else
in the system ever cleans it up. On the very next request, `get()`'s blind
prefix scan picks it straight back up.

**This is a known, solved problem elsewhere in the same file** — the main
session cookie's own chunking explicitly handles exactly this case
(`src/server/cookies.ts`, `setChunkedCookie`):

```ts
// clear unused chunks
const chunks = getAllChunkedCookies(reqCookies, name);
const chunksToRemove = chunks.length - chunkIndex;
if (chunksToRemove > 0) {
  for (let i = 0; i < chunksToRemove; i++) {
    const chunkIndexToRemove = chunkIndex + i;
    const chunkName = `${name}${CHUNK_PREFIX}${chunkIndexToRemove}`;
    deleteCookie(resCookies, chunkName, { ... });
    reqCookies.delete(chunkName);
  }
}
```

The `connectionTokenSets` write path has no equivalent. The asymmetry is total:
`StatelessSessionStore.delete()` (full logout) *does* correctly clear every
`__FC_*` cookie via `getConnectionTokenSetsCookies(...).forEach(...)` — so the
maintainers clearly know these cookies need cleanup on teardown. The gap is
specifically that `set()` (a shrink short of full teardown) never performs the
equivalent partial cleanup.

**Why this is trivially reachable:** `connectionTokenSets` is a public field
of the exported `SessionData` type, and the SDK's own public, documented
`updateSession()` method — "can be used in... Route Handlers," i.e. exactly
where a "Disconnect" button's server action would live — calls
`this.sessionStore.set()` **directly** with whatever `SessionData` the caller
passes in (`src/server/client.ts`, `updateSession()`, ~line 1575 for the App
Router Route Handler overload). No hook, no extra configuration, no special
mode — a single call with a shorter `connectionTokenSets` array is enough.
(The documented `beforeSessionSaved` hook is a second way to reach the same
`set()` gap — it also receives and can shrink the full session — but it isn't
even necessary; `updateSession()` alone is sufficient.) Critically, the SDK
has **no** `disconnectConnection()`/`revokeConnection()` method of its own
(confirmed — grepping the SDK source and `EXAMPLES.md`/`README.md` for
`disconnectAccount`/`removeConnection`/`revokeConnection` returns nothing), so
a developer building "let the user unlink a connected account" — an ordinary
feature request for any app using Connected Accounts — has no
maintainer-provided alternative to reach for.

**Scope:** confirmed specific to `StatelessSessionStore` (the SDK's default,
cookie-only mode — `grep` for `connectionTokenSets`/`__FC` in
`stateful-session-store.ts` returns nothing). Apps configured with a custom
`sessionStore` (database sessions) are unaffected, because the whole session —
`connectionTokenSets` included — is one blob overwritten atomically in the
developer's own store; a shrink there just shrinks it. Every app on the
default mode is affected.

## 4. Proof of Concept

### 4.1 Automated, whitebox (no HTTP, no mocking of SDK logic)

`examples/quickstart/audit/audit7-connection-token-resurrection.mjs` drives
the real, npm-published `StatelessSessionStore` class directly (imported from
`node_modules/@auth0/nextjs-auth0/dist`, the same build every consumer of the
package runs). Only the cookie **transport** between calls is simulated — by
literally applying each call's `Set-Cookie` output onto a `Map` standing in
for the browser's cookie jar, honoring `Max-Age<=0` as a deletion, exactly as
a real browser would. No SDK internals are stubbed, mocked, or monkey-patched.

**Prerequisites:** none beyond a checkout of this repo with
`examples/quickstart`'s dependencies installed (`pnpm install`).

**Steps to reproduce:**

```bash
cd examples/quickstart
node audit/audit7-connection-token-resurrection.mjs
```

**What the script does, step by step:**

1. Constructs a `StatelessSessionStore` with a fixed 32-byte secret (any
   secret works; this is not secret-dependent).
2. **Step 1 — connect three accounts.** Calls `store.set()` with
   `connectionTokenSets = [connA, connB, connC]`. Applies the response's
   `Set-Cookie` headers to a simulated browser jar. Jar now contains
   `__session`, `__FC_0`, `__FC_1`, `__FC_2`.
3. **Step 2 — disconnect connC.** Calls `store.set()` again, this time with
   the request cookies from step 1 and `connectionTokenSets = [connA, connB]`
   only — exactly what an app's `beforeSessionSaved` hook would produce after
   a user clicks "Disconnect" on connC. Checks whether this response deletes
   `__FC_2`. Applies the response to the jar.
4. **Step 3 — the user's next page load.** Calls `store.get()` with the
   current jar (no modification since step 2 — this models an ordinary
   subsequent request, not an attack) and inspects the resulting
   `connectionTokenSets`.
5. **Control — real logout.** Calls `store.delete()` (what `handleLogout`
   invokes) and confirms it *does* clear all three `__FC_*` cookies, to prove
   the gap is specific to `set()`/shrink and not a general cleanup miss.
6. **Follow-up — permanence.** Simulates one more, entirely unrelated,
   ordinary request: reads the session and writes it straight back
   unmodified (`{ ...session }`) — this is exactly what the SDK's own
   passive rolling-session touch does on every non-auth request
   (`src/server/auth-client.ts`, lines 769–792). Confirms the resurrected
   entry survives this too.

**Observed output (v4.25.0):**

```
Step 1: user connects three third-party accounts (A, B, C)
  browser cookie jar: __session, __FC_0, __FC_1, __FC_2

Step 2: app's "disconnect connC" feature runs a beforeSessionSaved-style
         shrink, saving connectionTokenSets = [A, B] only
  did this response delete __FC_2 (connC's cookie)? NO
  browser cookie jar: __session, __FC_0, __FC_1, __FC_2

Step 3: user's very next page load reads the session (no attacker action)
  connectionTokenSets read back: ["connA","connB","connC"]

============================================================
FINDING CONFIRMED: connC was disconnected in step 2 but is back in step 3.
  its (stale but still valid) access token: "tokC"
  __FC_2 was never deleted; get() re-decrypts it on every subsequent read.

Control: does a real logout (delete()) clean up __FC_* correctly?
  cookies cleared by delete(): __session, __FC_0, __FC_1, __FC_2
  all three __FC_* cookies cleared? yes — delete() is correct
  (confirms the gap is specific to set()/shrink, not delete()/logout)

Follow-up: is the resurrection permanent, or does it self-heal?
  session read for the routine touch sees: ["connA","connB","connC"]
  after a routine, unrelated page load: ["connA","connB","connC"]
  PERMANENT: connC survives an ordinary, unrelated session touch.
  Every future 'disconnect' attempt re-derives its array length from this
  ghost-inflated read, so the connection can never be fully removed by
  set() alone — only a full logout (delete()) clears it.
```

Re-run 3× consecutively during development; the outcome is deterministic
every time (cookie insertion order in the printed jar list may vary since it
comes from a `Map`, the resurrection itself does not).

### 4.2 How this looks in a real application

The whitebox proof isolates the store logic; here is the equivalent flow as a
developer would actually build and hit it, to make the reachability concrete.
No `beforeSessionSaved` hook is even required — the SDK's own public,
documented `updateSession()` API is enough:

```ts
// app/api/connections/[connection]/disconnect/route.ts
import { NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

export async function POST(_req: Request, { params }: { params: { connection: string } }) {
  const session = await auth0.getSession();
  if (!session) return new NextResponse(null, { status: 401 });

  await auth0.updateSession({
    ...session,
    connectionTokenSets: session.connectionTokenSets?.filter(
      (c) => c.connection !== params.connection
    )
  });

  return NextResponse.json({ ok: true });
}
```

1. User connects Google, GitHub, and Salesforce over time via
   `/auth/connect?connection=...`. Session now has three `connectionTokenSets`
   entries and three `__FC_N` cookies.
2. User clicks "Disconnect" on GitHub. The route above runs; `updateSession()`
   writes back `connectionTokenSets` with GitHub filtered out — `__FC_1`
   (GitHub's cookie, say) is left behind, un-deleted.
3. The UI shows "GitHub: not connected." The user believes it.
4. The user loads any other page. The SDK's own passive rolling-session touch
   (present by default — no special code needed) reads the session, which
   picks GitHub's orphaned cookie back up, and immediately re-persists it.
5. `session.connectionTokenSets` now contains GitHub again, permanently, for
   the rest of that session's life. If any code path in the app calls
   `getAccessTokenForConnection('github')` or otherwise trusts this array —
   a background sync job, a "your connections" dashboard, a webhook handler —
   it will find the "disconnected" entry present and usable.

## 5. Impact analysis

| Question | Answer |
| --- | --- |
| Does this let an attacker do anything new? | No. |
| Is any secret disclosed to a party that shouldn't have it? | No — the token stays in the same user's own `HttpOnly` cookie. |
| Does it require the user/app to have done anything unusual? | No — only to have used the SDK's default session mode and implemented "disconnect a connection" the only way the SDK allows. |
| Is it deterministic? | Yes — 100% reproducible, not a race. |
| Is it self-healing? | No — confirmed permanent until full logout (§4.1, follow-up). |
| Does severity depend on app-specific behavior? | Yes — whether the resurrected token is still honored by the third-party IdP, and whether any app code path actually re-uses a "removed" connection. |
| Is this a token-theft / logout-revocation-window issue? | No — see §2. Logout's refresh-token revocation is unrelated and, separately, confirmed working correctly. |

The concrete harm is a **broken security control**: an application's own
"disconnect this connection" feature does not durably do what it says, for as
long as the user stays logged in, with no error, warning, or indication to
either the developer or the user that anything failed.

## 6. What we did *not* find (ruled out during this investigation)

To be transparent about the scope of this audit and avoid implying a broader
compromise than is supported by evidence:

- **No cross-user leakage.** We reviewed `getAccessToken()`/`getTokenSet()`/
  `#refreshTokenSet()` for a shared, cross-request in-memory cache (the kind
  that could coalesce two different users' concurrent token refreshes on a
  warm server process) and found none — no `Map`/in-flight-promise structure
  keyed by anything other than per-call arguments exists outside the
  (non-secret, domain-keyed) `DiscoveryCache`. We did not find a way for one
  user's connection token to end up in another user's session.
- **No index-collision/cross-connection confusion.** Because `get()` always
  re-inflates the array with every surviving ghost *before* any subsequent
  `set()` computes new indices, a newly-added connection is always appended
  at the next free index rather than colliding with a stale one — the bug
  causes resurrection of the *same* connection, not swapping between two
  different ones.
- **`StatefulSessionStore` (database sessions) is unaffected** (§3, Scope).
- We did not attempt to chain this with the previously-documented
  `returnTo` open redirect or the middleware-500 finding; there is no
  mechanism by which either interacts with `connectionTokenSets` cleanup.
- **Logout's primary-refresh-token revocation is correct and unrelated.**
  Checked specifically because it's the natural "but doesn't a stolen token
  survive logout anyway?" question (§2): `handleLogout()` does revoke the
  refresh token server-side, with dedicated test coverage, and that
  transitively blocks minting *new* connection tokens after logout too (they
  require the primary refresh token to exchange). This finding doesn't
  interact with or weaken that protection — it reproduces with no logout step
  at all.

## 7. Remediation

In `StatelessSessionStore.set()`, before (or after) writing the new
`connectionTokenSets` cookies, delete any existing `__FC_N` cookie whose index
is `>= connectionTokenSets.length` — the same pattern `setChunkedCookie`
already implements for the main session cookie's trailing chunks. A minimal
sketch:

```ts
if (connectionTokenSets?.length) {
  await Promise.all(
    connectionTokenSets.map((cts, index) =>
      this.storeInCookie(reqCookies, resCookies, cts,
        `${this.connectionTokenSetsCookieName}_${index}`, maxAge)
    )
  );
}
// NEW: delete any leftover cookies beyond the current length
const existing = this.getConnectionTokenSetsCookies(reqCookies);
const newLength = connectionTokenSets?.length ?? 0;
for (const cookie of existing) {
  const idx = getIndexFromCookieName(cookie.name); // parse trailing _N
  if (idx !== undefined && idx >= newLength) {
    cookies.deleteCookie(resCookies, cookie.name, { ...this.cookieConfig });
    reqCookies.delete(cookie.name);
  }
}
```

This also caps the previously-unbounded growth of `__FC_*` cookie count over a
long-lived session (connect/disconnect cycles currently only ever grow the
high-water mark of cookies in play, which is a secondary, non-security
concern about eventually approaching request-header-size limits).

## 8. Suggested disclosure channel

A GitHub issue on `auth0/nextjs-auth0` at minimum — this is a clear,
reproducible functional defect with a precise root cause and fix. Given the
CWE-613-shaped angle (a revocation control that silently and permanently does
not take effect), it is reasonable to also flag it as security-relevant and
let the maintainers decide whether it warrants a GHSA; that judgment call
belongs to them, not to this audit. We are not filing anything without the
repository owner's explicit go-ahead.
