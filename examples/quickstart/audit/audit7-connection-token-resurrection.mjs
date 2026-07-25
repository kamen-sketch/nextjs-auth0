/**
 * FINDING — StatelessSessionStore.set() never deletes orphaned `__FC_N`
 * (connection access token) cookies when `connectionTokenSets` shrinks, so a
 * "revoked" third-party connection token is silently resurrected on the next
 * session read.
 *
 * Background: `getAccessTokenForConnection()` stores each entry of
 * `session.connectionTokenSets` in its OWN cookie, named positionally —
 * `__FC_0`, `__FC_1`, `__FC_2`, ... (stateless-session-store.ts, `storeInCookie`).
 * `get()` reconstructs the array by decrypting every cookie whose name starts
 * with `__FC`, regardless of how many entries the CURRENT session actually has.
 *
 * The only way this SDK-managed array shrinks is via the documented
 * `beforeSessionSaved` hook — a natural, expected way for an app to implement
 * "let the user disconnect a linked account" (`session.connectionTokenSets`
 * is part of the public `SessionData` type and is passed into and returned
 * from that hook). When a shrink happens, `set()` only writes cookies for
 * indices `0..newLength-1` — compare with the MAIN session cookie's chunking
 * (`setChunkedCookie` in cookies.ts), which explicitly deletes trailing
 * chunks no longer needed. `storeInCookie` / the connectionTokenSets write
 * loop has no equivalent cleanup, so trailing `__FC_N` cookies beyond the new
 * length are left untouched in the browser — still valid, non-expired
 * ciphertext — and `get()` picks them straight back up on the very next
 * request, with no attacker action required.
 *
 * This is distinct from (and NOT mitigated by) the JWE-expiry pruning tested
 * in stateless-session-store.test.ts ("...exclude a connection when the JWE
 * is expired") — that only drops entries whose OWN encrypted expiry has
 * passed. A revoked-but-freshly-issued connection token has a full-length TTL
 * and does not expire on its own.
 *
 * It is also distinct from full logout: `delete()` correctly clears every
 * `__FC_*` cookie via `getConnectionTokenSetsCookies(...).forEach(...)`. The
 * gap is specific to `set()`, i.e. any shrink that is not a full session
 * teardown.
 *
 * Proven here directly against the real SDK's built `StatelessSessionStore`
 * class (no HTTP, no mocking of SDK logic) — only the cookie *transport* is
 * simulated, by literally replaying set() #2's Set-Cookie output on top of
 * the browser jar left by set() #1, exactly as a browser would.
 */
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const distDir = path.join(here, "..", "node_modules", "@auth0", "nextjs-auth0", "dist");

const { StatelessSessionStore } = await import(
  `file://${path.join(distDir, "server", "session", "stateless-session-store.js")}`
);
const { RequestCookies, ResponseCookies } = await import(
  `file://${path.join(distDir, "server", "cookies.js")}`
);

const secret =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const store = new StatelessSessionStore({ secret });

const newReqCookies = (headerValue) => {
  const h = new Headers();
  if (headerValue) h.set("cookie", headerValue);
  return new RequestCookies(h);
};
const newResCookies = () => new ResponseCookies(new Headers());

const baseSession = (extra) => ({
  user: { sub: "auth0|user" },
  tokenSet: {
    accessToken: "at",
    idToken: "id",
    expiresAt: Math.floor(Date.now() / 1000) + 3600
  },
  internal: { sid: "sid-1", createdAt: Math.floor(Date.now() / 1000) },
  ...extra
});

/** Apply a response's Set-Cookie entries onto a browser-side jar, respecting Max-Age<=0 deletions. */
function applyResponseToJar(jar, resCookies) {
  for (const c of resCookies.getAll()) {
    if (c.maxAge !== undefined && c.maxAge <= 0) {
      jar.delete(c.name);
    } else {
      jar.set(c.name, c.value);
    }
  }
}
const jarToHeader = (jar) =>
  [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");

console.log("Connection-token resurrection proof — real StatelessSessionStore\n" + "=".repeat(60));

console.log("\nStep 1: user connects three third-party accounts (A, B, C)");
const jar = new Map();
{
  const req = newReqCookies(null);
  const res = newResCookies();
  await store.set(
    req,
    res,
    baseSession({
      connectionTokenSets: [
        { connection: "connA", accessToken: "tokA", expiresAt: 9999999999 },
        { connection: "connB", accessToken: "tokB", expiresAt: 9999999999 },
        { connection: "connC", accessToken: "tokC", expiresAt: 9999999999 }
      ]
    })
  );
  applyResponseToJar(jar, res);
  console.log(`  browser cookie jar: ${[...jar.keys()].join(", ")}`);
}

console.log(
  '\nStep 2: app\'s "disconnect connC" feature runs a beforeSessionSaved-style' +
    "\n         shrink, saving connectionTokenSets = [A, B] only"
);
let fc2DeletedInResponse;
{
  const req = newReqCookies(jarToHeader(jar));
  const res = newResCookies();
  await store.set(
    req,
    res,
    baseSession({
      connectionTokenSets: [
        { connection: "connA", accessToken: "tokA-refreshed", expiresAt: 9999999999 },
        { connection: "connB", accessToken: "tokB", expiresAt: 9999999999 }
      ]
    })
  );
  fc2DeletedInResponse = res
    .getAll()
    .some((c) => c.name === "__FC_2" && c.maxAge !== undefined && c.maxAge <= 0);
  applyResponseToJar(jar, res);
  console.log(`  did this response delete __FC_2 (connC's cookie)? ${fc2DeletedInResponse ? "yes" : "NO"}`);
  console.log(`  browser cookie jar: ${[...jar.keys()].join(", ")}`);
}

console.log("\nStep 3: user's very next page load reads the session (no attacker action)");
const finalSession = await store.get(newReqCookies(jarToHeader(jar)));
const conns = (finalSession?.connectionTokenSets ?? []).map((c) => c.connection);
console.log(`  connectionTokenSets read back: ${JSON.stringify(conns)}`);

console.log("\n" + "=".repeat(60));
if (!fc2DeletedInResponse && conns.includes("connC")) {
  const resurrected = finalSession.connectionTokenSets.find((c) => c.connection === "connC");
  console.log("FINDING CONFIRMED: connC was disconnected in step 2 but is back in step 3.");
  console.log(`  its (stale but still valid) access token: ${JSON.stringify(resurrected.accessToken)}`);
  console.log("  __FC_2 was never deleted; get() re-decrypts it on every subsequent read.");
} else {
  console.log("No resurrection observed — the array shrink was handled safely.");
}

console.log("\nControl: does a real logout (delete()) clean up __FC_* correctly?");
{
  const req = newReqCookies(jarToHeader(jar));
  const res = newResCookies();
  await store.delete(req, res);
  const deleted = res.getAll().filter((c) => c.maxAge !== undefined && c.maxAge <= 0).map((c) => c.name);
  console.log(`  cookies cleared by delete(): ${deleted.join(", ")}`);
  const allFcCleared = ["__FC_0", "__FC_1", "__FC_2"].every((n) => deleted.includes(n));
  console.log(`  all three __FC_* cookies cleared? ${allFcCleared ? "yes — delete() is correct" : "NO"}`);
  console.log("  (confirms the gap is specific to set()/shrink, not delete()/logout)");
}
