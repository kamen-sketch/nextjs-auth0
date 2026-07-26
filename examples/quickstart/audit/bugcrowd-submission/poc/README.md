# PoC — IPSIE session-ceiling bypass for connection tokens

Two independent, self-contained proofs. See `../SUBMISSION.md` "Steps to
reproduce" for full context; this is the quick-start version.

## Method A — `poc.proof.test.ts` (SDK-internal vitest, no live tenant)

1. In a checkout of `auth0/nextjs-auth0`, open `src/server/auth-client.test.ts`.
2. Paste the single `it(...)` block from `poc.proof.test.ts` in anywhere
   inside the file's top-level `describe` block (it only needs
   `createSessionData`, `makeStore`, `makeCookies`, `DEFAULT`,
   `getMockAuthorizationServer`, `getDefaultRoutes`, `generateSecret`,
   `AuthClient`, `TransactionStore` — all already imported/defined there).
3. `npx vitest run src/server/auth-client.test.ts -t "PROOF: skipCeilingCheck"`
4. Revert the file afterwards (`git checkout src/server/auth-client.test.ts`).

## Method B — `poc_runtime.py` (real HTTP, real live app, no JS tooling)

1. Run any app using `@auth0/nextjs-auth0` v4.25.0+ (e.g. the SDK's own
   `examples/quickstart`) with `npm run dev`. Note its `AUTH0_SECRET`.
2. Copy `connection-token-test.route.ts` into that app at
   `app/api/connection-token-test/route.ts`.
3. `pip3 install cryptography`
4. `AUTH0_SECRET=<secret> python3 poc_runtime.py http://localhost:3000`

`nextjs_auth0_jwe.py` is a required dependency of `poc_runtime.py` — keep
both in the same directory. It's a from-scratch Python re-implementation of
the SDK's session-cookie encryption (HKDF-SHA256 + AES-256-GCM JWE), used
only to mint/read test session cookies; it does not call into the SDK or any
JS code. It was cross-validated bidirectionally against the real SDK before
being trusted: a cookie minted here decrypts correctly via the SDK's own
`decrypt()`, and vice versa.

Expected output: 6/6 `[PASS]`, with the key line being that a session whose
`sessionExpiresAt` is a year in the past gets `401` from `/auth/profile` but
`failed_to_exchange_refresh_token` (not `missing_session`) from
`/api/connection-token-test` — i.e. it still reaches Auth0's token endpoint
instead of being blocked locally like the primary path is.
