# Connect-account completion is not bound to the session that started it

**Component:** `@auth0/nextjs-auth0` — `AuthClient.handleCallback()`,
`RESPONSE_TYPES.CONNECT_CODE` branch
**Affected:** confirmed on source as of this writing (matches v4.25.0 and `main`)
**Status:** SDK-level defense confirmed absent (proven, deterministic).
Server-side (Auth0) enforcement **not verified** — live test designed but not
yet run, pending manual follow-up.

---

## 1. Summary

`connectAccount()` (which starts the Connected Accounts / Token Vault linking
flow) stores no identity — no `sid`, no `sub` — in the transaction cookie it
creates. At `/auth/callback`, the `CONNECT_CODE` branch of `handleCallback()`
completes that transaction using **whichever session happens to be active in
the current request**, with zero comparison against who initiated the flow.

Proven at the SDK level with a deterministic, wire-level test against the
SDK's own code (mocked Auth0, no live network — see §3). **Not yet proven
end-to-end**, because that additionally depends on whether Auth0's own
`/me/v1/connected-accounts/complete` endpoint independently rejects
completing one user's `auth_session` with a different user's access token —
server-side platform behavior this SDK's source can't answer.

## 2. Root cause

**`connectAccount()`** builds `TransactionState` with no identity fields
(`src/server/auth-client.ts`, ~line 4166):

```ts
const transactionState: TransactionState = {
  codeVerifier,
  responseType: RESPONSE_TYPES.CONNECT_CODE,
  state,
  returnTo,
  authSession: connectAccountResponse.authSession // opaque handle from Auth0
};
```

**`handleCallback()`'s `CONNECT_CODE` branch** (~line 1191) reads the *current
request's* session and uses its access token to complete the transaction:

```ts
if (transactionState.responseType === RESPONSE_TYPES.CONNECT_CODE) {
  const { error: sessionError, session } =
    await this.getSessionWithDomainCheck(req.cookies);   // whoever is active NOW
  ...
  const [tokenSetError, tokenSetResponse] = await this.getTokenSet(session, {
    audience: `${this.issuer}me/`,
    scope: "create:me:connected_accounts"
  });
  ...
  const [completeConnectAccountError, connectedAccount] =
    await this.completeConnectAccount({
      tokenSet: tokenSetResponse.tokenSet,        // CURRENT session's token
      authSession: transactionState.authSession!, // ORIGINAL flow's handle
      connectCode: req.nextUrl.searchParams.get("connect_code")!,
      ...
    });
  ...
  const res = await this.onCallback(null, { ...onCallbackCtx, connectedAccount }, session);
```

**`completeConnectAccount()`** then authenticates the completion request to
Auth0 using that same current-session access token
(`src/server/auth-client.ts`, ~line 4276):

```ts
const fetcher = await this.fetcherFactory({
  useDPoP: this.useDPoP,
  getAccessToken: async () => ({ accessToken: options.tokenSet.accessToken, ... }),
  fetch: this.fetch
});
...
const res = await fetcher.fetchWithAuth(completeConnectAccountUrl, {
  method: "POST",
  body: JSON.stringify({
    auth_session: options.authSession,   // whichever flow's handle was in the txn cookie
    connect_code: options.connectCode,
    ...
  })
});
```

Nowhere in this path is `transactionState` compared against `session` for
identity. Contrast with the SDK's MCD domain binding
(`getSessionWithDomainCheck`), which explicitly checks
`session.internal.mcd.domain !== this.domain` and rejects with
`SessionDomainMismatchError` — the same kind of check simply doesn't exist
here for "is this the session that started this flow."

## 3. Proof (SDK-level, deterministic, no live network)

`examples/quickstart/audit/connect-account-cross-session.callback-proof.test.ts`
— written against the SDK's own `auth-client.test.ts` harness (msw-mocked
Auth0). Constructs two sessions ("User A" starts `connectAccount()`; "User B"
is active at callback time) and runs the real `handleCallback()`.

To make the proof airtight, it captures the **`refresh_token` actually
submitted** to `/oauth/token` (not just the resulting access-token string,
since the mock's canned token response doesn't vary by input and a naive
string comparison would be a false read — an earlier draft of this test
caught that mistake on its first run).

**Observed:**

```
[PROOF] refresh_token submitted to /oauth/token: rt_USER_B_token
[PROOF]   (User A's refresh token is "rt_123"; User B's is "rt_USER_B_token")
[PROOF] onCallback session.user.sub: "USER_B_sub_999"
[PROOF] connectedAccount: {"id":"cac_abc123","connection":"google-oauth2",...}
✓ passed
```

User B's own refresh token was what got exchanged and sent to Auth0 to
complete User A's `connect_code`/`authSession`, and the resulting
`connectedAccount` was attached to User B's session via `onCallback`. No
error, no rejection, at any point in the SDK.

**Reachability check — does this need a logout in between?** No, and that
matters: `handleLogout()` clears **every** `__txn_*` cookie
(`transactionStore.deleteAll`, confirmed by reading the source), so a
normal logout-then-different-login sequence would wipe the pending
connect-account transaction and close this path. The scenario requires the
active session to change **without** an intervening logout — e.g. a second
login on a shared/kiosk device, or any other app-specific way the session
cookie could be replaced while an old `__txn_*` cookie is still around.

## 4. What is NOT yet known

This is the crux of why the finding is documented, not reported, at this
stage. Whether it's exploitable end-to-end hinges entirely on a question this
SDK's source cannot answer: **does Auth0's `/me/v1/connected-accounts/complete`
endpoint itself verify that the access token completing an `auth_session`
belongs to the same user that created it via `/me/v1/connected-accounts/connect`?**

- If Auth0 enforces that server-side (the expected, standard design for any
  competently-built resource-scoped handle), B's completion attempt is
  rejected regardless of what the SDK does, and this is a defense-in-depth
  gap only.
- If Auth0 does *not* enforce it, this SDK provides no backstop at all, and
  the scenario in §3 becomes a real cross-account-linking issue.

We deliberately did not guess. `authSession` is documented elsewhere in this
SDK's own types (`passwordless-db.ts`) as "opaque... treat as a black box,"
which is circumstantial support for it being a server-scoped handle, but is
not proof.

## 5. Live test — designed, not yet executed

Confirmed the target tenant has the Connected Accounts API surface live
(`POST https://dev-con6iu63x7v2zdaw.us.auth0.com/me/v1/connected-accounts/connect`
returns `401 Invalid Token` for a garbage bearer — the endpoint exists and
processes requests — rather than `404`).

Running the real test requires dashboard configuration this session cannot
perform (no Management API access) and creates a real, live link to an
external account that would need manual cleanup afterward — so it's on hold
for the repo owner to run manually. Setup, cross-checked against Auth0's own
documentation:

1. **Create an OAuth app at a provider.** GitHub recommended over Google —
   Auth0's Google "Dev Keys" are documented as unreliable for `offline_access`
   (refresh tokens), which Connected Accounts requires; a real Google Cloud
   Console project adds setup overhead a GitHub OAuth App avoids.
   GitHub → Settings → Developer settings → OAuth Apps → New OAuth App.
2. **Auth0 Dashboard → Authentication → Social → Create Connection →
   GitHub**, using that app's Client ID/Secret.
3. On that connection: **Purpose** tab → enable **"Connected Accounts for
   Token Vault"**. **Permissions** tab → enable **Offline Access**. Save.
4. **Applications** tab on that connection → enable it for the target app.
5. **Applications → APIs → Auth0 My Account API → Application Access** → find
   the app → **Edit** → **User Access: Authorized** → grant
   `create:me:connected_accounts` (and `read:`/`delete:` for completeness).
6. **Applications → Applications →** the app → **Multi-Resource Refresh
   Token** → Edit Configuration → enable **My Account API**.
7. Confirm the app's **Grant Types** include **Authorization Code** and
   **Refresh Token** (default on regular web apps).
8. In the example app, set `enableConnectAccountEndpoint: true` on the
   `Auth0Client` in `lib/auth0.ts`.

**Test procedure once configured:**

1. Log in as User A (browser/profile 1). Start `GET /auth/connect?connection=<github-connection-name>`. Stop at GitHub's consent screen — do not authorize yet.
2. In a separate browser profile (or after clearing only the session cookie, not the `__txn_*` one, in the same browser), log in as User B.
3. Return to the GitHub consent tab from step 1 and authorize.
4. Observe the callback: does the resulting connected account attach to A or B? Does Auth0 return an error instead?
5. **Cleanup regardless of outcome:** unlink the test connection from whichever account it landed on (My Account API / Connected Accounts UI, or the GitHub account's own "Authorized OAuth Apps" settings), and consider deleting the test GitHub OAuth App and Auth0 social connection afterward.

Sources consulted: [Connected Accounts for Token Vault — Auth0 Docs](https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault/connected-accounts-for-token-vault), [Test Social Connections with Auth0 Developer Keys — Auth0 Docs](https://auth0.com/docs/authenticate/identity-providers/social-identity-providers/devkeys).

## 6. Suggested fix (independent of what Auth0 does server-side)

Bind `TransactionState` for `CONNECT_CODE` to the initiating session and
check it at callback time — the same defense-in-depth pattern already used
for MCD domain binding:

```ts
const transactionState: TransactionState = {
  ...
  responseType: RESPONSE_TYPES.CONNECT_CODE,
  initiatorSid: session.internal.sid // NEW — captured when connectAccount() is called
};
```

```ts
if (transactionState.responseType === RESPONSE_TYPES.CONNECT_CODE) {
  const { session } = await this.getSessionWithDomainCheck(req.cookies);
  if (session?.internal.sid !== transactionState.initiatorSid) {
    return this.handleCallbackError(new ConnectAccountError({ code: "SESSION_MISMATCH", ... }), ...);
  }
  ...
}
```

This closes the gap regardless of Auth0's server-side behavior, the same way
PKCE/state binding is implemented even though Auth0's own checks are also
part of the defense.
