/**
 * Wire-level regression test for the IPSIE session-ceiling bypass finding.
 *
 * Written against the SDK's own test harness (src/server/auth-client.test.ts):
 * drop it in right after the existing
 * `describe("getSessionWithDomainCheck — IPSIE ceiling enforcement")` tests,
 * where `createSessionData`, `makeStore`, `makeCookies`, `DEFAULT`,
 * `getMockAuthorizationServer`, `getDefaultRoutes`, `generateSecret` and
 * `AuthClient` are all in scope. Kept here rather than in the SDK tree
 * because this example only owns files under examples/.
 *
 * Background: for enterprise connections, a Post-Login Action can stamp a
 * `session_expiry` claim into the ID token — an upstream-IdP-mandated ceiling
 * on how long the session may be used, independent of the access/refresh
 * token's own TTL (README.md "Session Expiry from the Upstream IdP",
 * EXAMPLES.md same section). The SDK enforces it by checking
 * `isSessionCeilingReached(session.internal.sessionExpiresAt)` inside
 * `getSessionWithDomainCheck()` — confirmed by a dedicated, well-tested
 * describe block covering the primary getSession()/getAccessToken() paths.
 *
 * `getAccessTokenForConnection()` (client.ts) explicitly opts out of that
 * check: it calls `getSessionWithDomainCheck(cookies, { skipCeilingCheck: true })`,
 * with a code comment explaining "connection tokens follow the upstream IdP's
 * own TTLs, not the IPSIE session ceiling."
 *
 * The ceiling is enforced ENTIRELY client-side (SDK-side): reaching it never
 * calls Auth0 to revoke the underlying refresh token — `getSessionWithDomainCheck`
 * just locally treats the session as gone and deletes the local store record.
 * Since `session_expiry` is populated by a custom Post-Login Action (not a
 * native Auth0 platform mechanism), there is no reason to expect Auth0's own
 * token endpoint independently re-validates it on a later grant.
 * `getConnectionTokenSet()` (used by `getAccessTokenForConnection`) confirmed
 * by inspection to never reference `sessionExpiresAt`/ceiling at all — it
 * operates purely on the `tokenSet` object, with no session-level context.
 *
 * This test proves: a session whose ceiling passed a full year ago is
 * correctly rejected by the default (primary-token) path, but
 * `getAccessTokenForConnection`'s bypass path returns that same session in
 * full, and its (never independently revoked) refresh token successfully
 * mints a brand-new connection access token.
 *
 * Observed result when run against @auth0/nextjs-auth0 (source as of this
 * writing; same code on v4.25.0 and main):
 *
 *   [PROOF] Default getSessionWithDomainCheck(): session: null (ceiling enforced)
 *   [PROOF] skipCeilingCheck: true: session: RETURNED IN FULL, ceiling ignored
 *   [PROOF] getConnectionTokenSet() minted: FRESH_CONNECTION_TOKEN_MINTED_POST_CEILING
 *   ✓ passed
 *
 * Untested territory confirmed: the existing "IPSIE ceiling enforcement"
 * describe block has 4 tests, none of which exercise `skipCeilingCheck: true`
 * — the bypass this test targets has no prior regression coverage either way.
 */
it("PROOF: skipCeilingCheck (used by getAccessTokenForConnection) returns the session even long past the ceiling, and getConnectionTokenSet then mints a fresh connection token from it", async () => {
  const secret = await generateSecret(32);
  const transactionStore = new TransactionStore({ secret });
  // Ceiling passed a full year ago — not a 30s-leeway edge case.
  const longPastCeiling = Math.floor(Date.now() / 1000) - 60 * 60 * 24 * 365;
  const session = createSessionData({
    tokenSet: {
      accessToken: DEFAULT.accessToken,
      refreshToken: DEFAULT.refreshToken,
      expiresAt: Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60 // also expired, forces a refresh
    },
    internal: {
      sid: DEFAULT.sid,
      createdAt: Math.floor(Date.now() / 1000) - 60 * 60 * 24 * 400,
      sessionExpiresAt: longPastCeiling
    }
  });
  const store = makeStore(session);
  const fetchSpy = getMockAuthorizationServer({
    tokenEndpointResponse: {
      token_type: "Bearer",
      access_token: "FRESH_CONNECTION_TOKEN_MINTED_POST_CEILING",
      expires_in: 86400
    } as oauth.TokenEndpointResponse
  });

  const authClient = new AuthClient({
    transactionStore,
    sessionStore: store as any,
    domain: DEFAULT.domain,
    clientId: DEFAULT.clientId,
    clientSecret: DEFAULT.clientSecret,
    secret,
    appBaseUrl: DEFAULT.appBaseUrl,
    routes: getDefaultRoutes(),
    fetch: fetchSpy
  });

  // 1. Default (as used by getSession()/getAccessToken()): ceiling enforced.
  const normalResult = await authClient.getSessionWithDomainCheck(makeCookies() as any);

  // 2. skipCeilingCheck: true — exactly what getAccessTokenForConnection()
  //    passes (client.ts, resolveRequestContext -> getSessionWithDomainCheck).
  const bypassResult = await authClient.getSessionWithDomainCheck(makeCookies() as any, {
    skipCeilingCheck: true
  });

  expect(normalResult.session).toBeNull();
  expect(bypassResult.session).not.toBeNull();

  // 3. Prove the bypassed session's tokenSet can actually mint a brand-new
  //    connection token — this is getAccessTokenForConnection()'s next step
  //    after getSessionWithDomainCheck(..., { skipCeilingCheck: true }).
  const [connError, connectionTokenSet] = await authClient.getConnectionTokenSet(
    bypassResult.session!.tokenSet,
    undefined,
    { connection: "google-oauth2" }
  );

  expect(connError).toBeNull();
  expect(connectionTokenSet?.accessToken).toEqual("FRESH_CONNECTION_TOKEN_MINTED_POST_CEILING");
});
