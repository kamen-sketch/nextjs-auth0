/**
 * Wire-level regression test for the connect-account cross-session finding.
 *
 * Written against the SDK's own test harness (src/server/auth-client.test.ts):
 * drop it in as an `it(...)` inside the `describe("connect account callback")`
 * block, where `DEFAULT`, `getMockAuthorizationServer`, `getDefaultRoutes`,
 * `generateSecret`, `AuthClient`, `TransactionStore`, `StatelessSessionStore`,
 * `encrypt`, `RESPONSE_TYPES` and `TransactionState` are all in scope. Kept
 * here rather than in the SDK tree because this example only owns files under
 * examples/.
 *
 * What it proves: `TransactionState` for `RESPONSE_TYPES.CONNECT_CODE` carries
 * no identity (no `sid`/`sub`) for who started the connectAccount() flow.
 * At /auth/callback, handleCallback reads whichever session is active in the
 * CURRENT request and uses ITS credentials to complete the connect-account
 * transaction — with no comparison anywhere to who initiated it.
 *
 * The test simulates: User A starts connectAccount() (their authSession is
 * baked into the __txn_ cookie). Before the OAuth consent screen is completed,
 * a different session — User B — becomes active in the same browser (no
 * logout in between; handleLogout() DOES clear __txn_ cookies, so this
 * requires an active-session change WITHOUT a logout step, e.g. a shared
 * device or a second login). The callback then fires with A's connect_code
 * but B's session active.
 *
 * The mock /oauth/token endpoint returns a canned access_token regardless of
 * input, so the resulting Authorization header string is NOT proof by itself
 * of whose credentials were used — this test additionally intercepts the
 * refresh_token grant parameter actually submitted to /oauth/token, which the
 * mock does NOT canned-echo, to prove conclusively that User B's refresh
 * token (not User A's) was what got exchanged and sent to Auth0 to complete
 * User A's connect_code/authSession.
 *
 * Observed result when run against @auth0/nextjs-auth0 (source as of this
 * writing; same code on v4.25.0 and main):
 *
 *   [PROOF] refresh_token submitted to /oauth/token: rt_USER_B_token
 *   [PROOF] onCallback session.user.sub: "USER_B_sub_999"
 *   [PROOF] connectedAccount: {...} (attached successfully, no rejection)
 *   ✓ passed
 *
 * IMPORTANT — what this does and does NOT prove:
 * This proves the SDK provides zero LOCAL defense against completing one
 * user's connect-account transaction using a different, currently-active
 * user's session. It does NOT prove this is exploitable end-to-end, because
 * that also depends on whether Auth0's own `/me/v1/connected-accounts/complete`
 * endpoint independently rejects completing an `auth_session` with a
 * different user's access token than the one that created it via
 * `/me/v1/connected-accounts/connect`. That is Auth0 platform (server-side)
 * behavior, outside this SDK's source and not verified here.
 */
it("PROOF: connect-account completion uses whichever session is active at callback time, not the one that started the flow", async () => {
  const state = "transaction-state";
  const connectCode = "connect-code";

  let capturedAuthHeader: string | null = null;
  let capturedOnCallbackSessionSub: string | undefined;
  let capturedConnectedAccount: unknown;
  let capturedRefreshTokenSubmitted: string | null = null;

  const mockOnCallback = vi.fn(async (_err, ctx, session) => {
    capturedOnCallbackSessionSub = (session as any)?.user?.sub;
    capturedConnectedAccount = (ctx as any)?.connectedAccount;
    return NextResponse.redirect(new URL("/dashboard", DEFAULT.appBaseUrl));
  });

  const secret = await generateSecret(32);
  const transactionStore = new TransactionStore({ secret });
  const sessionStore = new StatelessSessionStore({ secret });

  const innerMockFetch = getMockAuthorizationServer({
    onCompleteConnectAccountRequest: async (req) => {
      capturedAuthHeader = req.headers.get("authorization");
    }
  });
  // The mock's canned /oauth/token response doesn't vary by input, so the
  // resulting access_token string alone can't prove whose credentials were
  // used. The refresh_token actually submitted can.
  const instrumentedFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url.includes("/oauth/token") && init?.body) {
      const bodyText =
        typeof init.body === "string" ? init.body : await new Response(init.body as any).text();
      capturedRefreshTokenSubmitted = new URLSearchParams(bodyText).get("refresh_token");
    }
    return (innerMockFetch as any)(input, init);
  }) as typeof fetch;

  const authClient = new AuthClient({
    transactionStore,
    sessionStore,
    domain: DEFAULT.domain,
    clientId: DEFAULT.clientId,
    clientSecret: DEFAULT.clientSecret,
    secret,
    appBaseUrl: DEFAULT.appBaseUrl,
    routes: getDefaultRoutes(),
    fetch: instrumentedFetch,
    onCallback: mockOnCallback
  });

  const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
  url.searchParams.set("connect_code", connectCode);
  url.searchParams.set("state", state);

  // The transaction was created while "User A" started connectAccount().
  // authSession is the opaque handle Auth0 gave to A specifically.
  const transactionState: TransactionState = {
    maxAge: 3600,
    codeVerifier: "code-verifier",
    responseType: RESPONSE_TYPES.CONNECT_CODE,
    state,
    returnTo: "/dashboard",
    authSession: DEFAULT.connectAccount.authSession // belongs to User A's flow
  };
  const maxAge = 60 * 60;
  const expiration = Math.floor(Date.now() / 1000 + maxAge);
  const headers = new Headers();
  headers.set("cookie", `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`);

  // But by the time the callback fires, the ACTIVE session in this same
  // browser belongs to a completely different user, "User B" — e.g. A started
  // linking Google on a shared device, then B logged in before A went back to
  // finish the Google consent screen.
  const userBSession: SessionData = {
    user: { sub: "USER_B_sub_999", name: "User B", email: "userb@example.com" },
    tokenSet: {
      accessToken: "at_USER_B_token",
      scope: "openid profile email",
      refreshToken: "rt_USER_B_token",
      expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60
    },
    internal: { sid: "sid_USER_B", createdAt: Math.floor(Date.now() / 1000) }
  };
  headers.append("cookie", `__session=${await encrypt(userBSession, secret, expiration)}`);

  const request = new NextRequest(url, { method: "GET", headers });
  const response = await authClient.handleCallback(request);

  expect(response.status).toEqual(307);
  // The SDK refreshed using User B's refresh token, not User A's — proving the
  // exchange was authenticated as B, even though the connect_code and
  // authSession being completed originated from A's flow.
  expect(capturedRefreshTokenSubmitted).toEqual("rt_USER_B_token");
  expect(capturedAuthHeader).toBeTruthy();
  // A's connect_code/authSession got completed and attached to B's session —
  // no local check anywhere compared the two identities.
  expect(capturedOnCallbackSessionSub).toEqual("USER_B_sub_999");
  expect(capturedConnectedAccount).toBeDefined();
});
