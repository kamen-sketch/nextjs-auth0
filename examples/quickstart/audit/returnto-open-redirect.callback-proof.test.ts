/**
 * Wire-level regression test for the returnTo open redirect.
 *
 * This is written against the SDK's own test harness (src/server/auth-client.test.ts):
 * drop it in as an `it(...)` inside the `describe("handleCallback")` block, where
 * `DEFAULT`, `getMockAuthorizationServer`, `getDefaultRoutes`, `generateSecret`,
 * `AuthClient`, `TransactionStore`, `StatelessSessionStore`, `encrypt`,
 * `RESPONSE_TYPES` and `TransactionState` are all in scope. It is kept here rather
 * than in the SDK tree because this example only owns files under examples/.
 *
 * It drives a *successful* callback (the Auth0 token exchange is mocked, so no
 * network) with the transaction returnTo set to the value that
 * `/auth/login?returnTo=/https://evil.example.com` stores verbatim (proven live
 * by audit6-returnto-open-redirect.mjs), and asserts that handleCallback issues a
 * 307 to a different origin.
 *
 * Observed result when run against @auth0/nextjs-auth0 v4.25.0:
 *
 *   [PROOF] status=307 Location=https://evil.example.com/ host=evil.example.com
 *   ✓ passed
 */
it("redirects off-origin after a successful login when returnTo is /https://evil.example.com", async () => {
  const state = "transaction-state";
  const code = "auth-code";

  const secret = await generateSecret(32);
  const transactionStore = new TransactionStore({ secret });
  const sessionStore = new StatelessSessionStore({ secret });
  const authClient = new AuthClient({
    transactionStore,
    sessionStore,
    domain: DEFAULT.domain,
    clientId: DEFAULT.clientId,
    clientSecret: DEFAULT.clientSecret,
    secret,
    appBaseUrl: DEFAULT.appBaseUrl,
    routes: getDefaultRoutes(),
    fetch: getMockAuthorizationServer()
  });

  const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
  url.searchParams.set("code", code);
  url.searchParams.set("state", state);

  const headers = new Headers();
  const transactionState: TransactionState = {
    nonce: "nonce-value",
    maxAge: 3600,
    codeVerifier: "code-verifier",
    responseType: RESPONSE_TYPES.CODE,
    state,
    // exactly what /auth/login?returnTo=/https://evil.example.com stores
    returnTo: "/https://evil.example.com"
  };
  const expiration = Math.floor(Date.now() / 1000 + 3600);
  headers.set(
    "cookie",
    `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
  );

  const response = await authClient.handleCallback(
    new NextRequest(url, { method: "GET", headers })
  );

  const location = new URL(response.headers.get("Location")!);
  expect(response.status).toEqual(307);
  expect(location.host).toEqual("evil.example.com"); // off-origin: open redirect
});
