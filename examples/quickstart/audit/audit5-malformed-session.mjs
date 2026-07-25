/**
 * Finding: the middleware throws an unhandled TypeError (HTTP 500) instead of
 * treating the request as unauthenticated when the __session cookie decrypts to
 * a payload with no `internal` block.
 *
 * Root cause: on any non-auth request the middleware rolls the session:
 *
 *   const { error, session } = await this.getSessionWithDomainCheck(req.cookies);
 *   if (!error && session) {
 *     await this.sessionStore.set(req.cookies, res.cookies, { ...session });
 *   }
 *
 * getSessionWithDomainCheck returns any cookie that DECRYPTS, without checking
 * its shape. sessionStore.set then calls:
 *
 *   const maxAge = this.calculateMaxAge(session.internal.createdAt);  // no `?.`
 *
 * so a session without `internal` throws `Cannot read properties of undefined
 * (reading 'createdAt')`. The same file guards session.internal?.mcd and
 * session.internal?.sessionExpiresAt with optional chaining — this one call
 * was missed.
 *
 * Why it is reachable without AUTH0_SECRET: every cookie the SDK issues is
 * encrypted with the same key — hkdf("sha256", secret, "", "JWE CEK", 32) —
 * with no per-purpose domain separation. The transaction cookie is handed to
 * any anonymous visitor of /auth/login and its payload has no `internal` block.
 * Replaying it as __session is therefore a valid ciphertext that decrypts to a
 * shape the write path cannot handle.
 */
const BASE = process.env.BASE || "http://localhost:3000";
const raw = (p, o = {}) => fetch(`${BASE}${p}`, { redirect: "manual", ...o });

const results = [];
function check(name, pass, detail) {
  results.push({ name, pass, detail });
  const m = pass === true ? "PASS" : pass === false ? "FAIL" : "INFO";
  console.log(`[${m}] ${name}${detail ? `\n        ${detail}` : ""}`);
}

console.log(`\nMalformed-session robustness — ${BASE}\n${"=".repeat(60)}\n`);

// --- Step 1: anonymous visitor obtains a transaction cookie ---------------
const login = await raw("/auth/login");
const txnSetCookie = (login.headers.getSetCookie?.() || []).find((c) =>
  c.startsWith("__txn_")
);
check(
  "anonymous /auth/login issues a __txn_ cookie",
  !!txnSetCookie,
  txnSetCookie ? txnSetCookie.split("=")[0] + "=<jwe>" : "none"
);
const txnValue = decodeURIComponent(
  txnSetCookie.split("=").slice(1).join("=").split(";")[0]
);

// --- Step 2: replay that ciphertext as __session --------------------------
// A correctly-behaving app treats an unusable session cookie as "no session":
// 401 on an API route, or a redirect to login. A 5xx means an unhandled throw.
const replay = await raw("/api/me", {
  headers: { cookie: `__session=${txnValue}` }
});
check(
  "replaying the txn cookie as __session does NOT 500",
  replay.status !== 500,
  `status=${replay.status} (expected 401; 500 = unhandled TypeError in middleware rolling-session write)`
);

// --- Step 3: same class of input on a page route --------------------------
const replayPage = await raw("/dashboard", {
  headers: { cookie: `__session=${txnValue}` }
});
check(
  "same cookie on a page route does NOT 500",
  replayPage.status !== 500,
  `status=${replayPage.status} (expected 307 -> /auth/login)`
);

// --- Step 4: the crash repeats for as long as the cookie is present -------
// It is deterministic, not a transient — every request with the malformed
// cookie 500s. (This is what a cookie-injection availability angle would rest
// on, but that needs extra preconditions and is not the point of the bug.)
let persistent = true;
for (let i = 0; i < 3; i++) {
  const r = await raw("/", { headers: { cookie: `__session=${txnValue}` } });
  if (r.status !== 500) persistent = false;
}
check(
  "the failure is not persistent across repeated requests",
  !persistent,
  persistent
    ? "every request with the planted cookie 500s — availability impact if the cookie can be set in a victim's browser"
    : "recovered on a later request"
);

// --- Step 5: a normal invalid cookie is still handled cleanly (control) ----
const garbage = await raw("/api/me", {
  headers: { cookie: "__session=not-a-valid-jwe" }
});
check(
  "control: an undecryptable cookie is handled cleanly (401)",
  garbage.status === 401,
  `status=${garbage.status} — proves the 500 is specific to decryptable-but-malformed input, not all bad cookies`
);

console.log("");
const fail = results.filter((r) => r.pass === false);
console.log("=".repeat(60));
console.log(
  `Total: ${results.length} | PASS ${results.filter((r) => r.pass === true).length} | FAIL ${fail.length} | INFO ${results.filter((r) => r.pass === null).length}`
);
if (fail.length) {
  console.log(
    "\nFINDING — middleware 500s on a decryptable-but-malformed session cookie:"
  );
  fail.forEach((f) => console.log(`  - ${f.name}\n      ${f.detail}`));
}
