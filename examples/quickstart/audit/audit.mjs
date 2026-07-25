import { hkdf } from "@panva/hkdf";
import * as jose from "jose";
import { generateSessionCookie } from "@auth0/nextjs-auth0/testing";

const BASE = process.env.BASE || "http://localhost:3000";
const SECRET = process.env.AUTH0_SECRET;

const key = () => hkdf("sha256", SECRET, "", "JWE CEK", 32);

async function decryptCookie(v) {
  const { payload } = await jose.jwtDecrypt(v, await key(), {
    clockTolerance: 15
  });
  return payload;
}

const results = [];
function check(area, name, pass, detail) {
  results.push({ area, name, pass, detail });
  const mark = pass === true ? "PASS" : pass === false ? "FAIL" : "INFO";
  console.log(`[${mark}] ${area} :: ${name}${detail ? `\n        ${detail}` : ""}`);
}

function parseSetCookie(res, prefix) {
  const all = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  return all.find((c) => c.startsWith(prefix));
}

const raw = (p, opts = {}) =>
  fetch(`${BASE}${p}`, { redirect: "manual", ...opts });

// ---------------------------------------------------------------- A. anon
async function anonymousAccess() {
  const cases = [
    ["/", 200],
    ["/dashboard", 307],
    ["/api/me", 401],
    ["/auth/profile", 401],
    ["/auth/access-token", 401]
  ];
  for (const [path, want] of cases) {
    const res = await raw(path);
    check(
      "A. Akses anonim",
      `${path} -> ${res.status}`,
      res.status === want,
      res.status === want ? "" : `diharapkan ${want}`
    );
  }
  const dash = await raw("/dashboard");
  const loc = dash.headers.get("location") || "";
  check(
    "A. Akses anonim",
    "/dashboard redirect ke login dgn returnTo",
    loc.includes("/auth/login") && loc.includes("returnTo=%2Fdashboard") ||
      loc.includes("returnTo=/dashboard"),
    loc
  );
}

// ------------------------------------------------- B. transaction / PKCE
async function transactionHardening() {
  const res = await raw("/auth/login");
  const loc = new URL(res.headers.get("location"));
  const q = loc.searchParams;

  check("B. Login transaction", "PKCE S256 dipakai", q.get("code_challenge_method") === "S256", q.get("code_challenge_method"));
  check("B. Login transaction", "state ada & acak (>=32 char)", (q.get("state") || "").length >= 32, `len=${(q.get("state") || "").length}`);
  check("B. Login transaction", "nonce ada & acak (>=32 char)", (q.get("nonce") || "").length >= 32, `len=${(q.get("nonce") || "").length}`);
  check("B. Login transaction", "response_type=code (bukan implicit)", q.get("response_type") === "code", q.get("response_type"));
  check("B. Login transaction", "redirect_uri = app callback", q.get("redirect_uri") === `${BASE}/auth/callback`, q.get("redirect_uri"));

  const txn = parseSetCookie(res, "__txn_");
  check("B. Login transaction", "txn cookie HttpOnly", /HttpOnly/i.test(txn || ""), "");
  check("B. Login transaction", "txn cookie SameSite=Lax", /SameSite=lax/i.test(txn || ""), "");
  check("B. Login transaction", "txn cookie ada Max-Age (tidak permanen)", /Max-Age=\d+/i.test(txn || ""), (txn || "").match(/Max-Age=\d+/i)?.[0]);

  // state di URL harus cocok dgn state di dalam txn cookie (binding)
  const txnVal = txn.split("=").slice(1).join("=").split(";")[0];
  const payload = await decryptCookie(decodeURIComponent(txnVal));
  check("B. Login transaction", "state di cookie == state di URL (binding)", payload.state === q.get("state"), "");
  check("B. Login transaction", "codeVerifier disimpan server-side (di cookie terenkripsi)", typeof payload.codeVerifier === "string" && payload.codeVerifier.length > 20, "");
  check("B. Login transaction", "codeVerifier TIDAK bocor ke URL authorize", !loc.search.includes(payload.codeVerifier), "");
}

// ------------------------------------------------------- C. open redirect
async function openRedirect() {
  // login returnTo
  const evil = "https://evil.example.com/steal";
  const res = await raw(`/auth/login?returnTo=${encodeURIComponent(evil)}`);
  const txn = parseSetCookie(res, "__txn_");
  const txnVal = txn.split("=").slice(1).join("=").split(";")[0];
  const payload = await decryptCookie(decodeURIComponent(txnVal));
  check(
    "C. Open redirect",
    "login ?returnTo=evil.com ditolak (disanitasi)",
    !String(payload.returnTo).includes("evil.example.com"),
    `txn.returnTo = ${JSON.stringify(payload.returnTo)}`
  );

  // path relatif harus tetap diterima
  const res2 = await raw("/auth/login?returnTo=%2Fdashboard");
  const txn2 = parseSetCookie(res2, "__txn_");
  const p2 = await decryptCookie(decodeURIComponent(txn2.split("=").slice(1).join("=").split(";")[0]));
  check("C. Open redirect", "login ?returnTo=/dashboard tetap diterima", p2.returnTo === "/dashboard", `txn.returnTo = ${JSON.stringify(p2.returnTo)}`);

  // protocol-relative bypass
  const res3 = await raw("/auth/login?returnTo=%2F%2Fevil.example.com");
  const txn3 = parseSetCookie(res3, "__txn_");
  const p3 = await decryptCookie(decodeURIComponent(txn3.split("=").slice(1).join("=").split(";")[0]));
  check("C. Open redirect", "login ?returnTo=//evil.com ditolak", !String(p3.returnTo).includes("evil.example.com"), `txn.returnTo = ${JSON.stringify(p3.returnTo)}`);

  // logout returnTo -> diteruskan ke Auth0
  const res4 = await raw(`/auth/logout?returnTo=${encodeURIComponent(evil)}`);
  const l4 = new URL(res4.headers.get("location"));
  const plru = l4.searchParams.get("post_logout_redirect_uri") || l4.searchParams.get("returnTo");
  check(
    "C. Open redirect",
    "logout ?returnTo=evil.com TIDAK divalidasi lokal",
    plru !== evil,
    `post_logout_redirect_uri = ${plru} (SDK meneruskan apa adanya; Auth0 yang memvalidasi)`
  );
}

// ------------------------------------------------------ D. sesi valid
async function authenticated() {
  const cookie = await generateSessionCookie(
    {
      user: { sub: "auth0|audit-user", name: "Audit User", email: "audit@example.com" },
      tokenSet: {
        accessToken: "AUDIT_ACCESS_TOKEN_SENTINEL",
        refreshToken: "AUDIT_REFRESH_TOKEN_SENTINEL",
        idToken: "AUDIT_ID_TOKEN_SENTINEL",
        expiresAt: Math.floor(Date.now() / 1000) + 3600
      }
    },
    { secret: SECRET }
  );
  const H = { cookie: `__session=${cookie}` };

  const home = await raw("/", { headers: H });
  const homeBody = await home.text();
  check("D. Sesi valid", "/ menampilkan nama user", home.status === 200 && homeBody.includes("Audit User"), `status=${home.status}`);

  const dash = await raw("/dashboard", { headers: H });
  const dashBody = await dash.text();
  check("D. Sesi valid", "/dashboard dapat diakses (200)", dash.status === 200, `status=${dash.status}`);

  const me = await raw("/api/me", { headers: H });
  const meBody = await me.text();
  check("D. Sesi valid", "/api/me mengembalikan 200 + user", me.status === 200 && meBody.includes("auth0|audit-user"), `status=${me.status}`);

  // KEBOCORAN TOKEN
  for (const [label, body] of [["/", homeBody], ["/dashboard", dashBody], ["/api/me", meBody]]) {
    const leaks = ["AUDIT_ACCESS_TOKEN_SENTINEL", "AUDIT_REFRESH_TOKEN_SENTINEL", "AUDIT_ID_TOKEN_SENTINEL"].filter((t) => body.includes(t));
    check("D. Sesi valid", `${label} tidak membocorkan token ke HTML/JSON`, leaks.length === 0, leaks.length ? `BOCOR: ${leaks.join(", ")}` : "");
  }

  // flag cookie sesi saat di-refresh (rolling)
  const sc = parseSetCookie(home, "__session");
  if (sc) {
    check("D. Sesi valid", "cookie sesi HttpOnly", /HttpOnly/i.test(sc), "");
    check("D. Sesi valid", "cookie sesi SameSite=Lax", /SameSite=lax/i.test(sc), "");
    // APP_BASE_URL=http://localhost -> Secure sengaja off. Yang diuji: konsisten dgn protokol.
    const isHttps = BASE.startsWith("https:");
    check(
      "D. Sesi valid",
      `cookie sesi Secure sesuai protokol (${isHttps ? "https" : "http"})`,
      /Secure/i.test(sc) === isHttps,
      `Secure=${/Secure/i.test(sc)}`
    );
  } else {
    check("D. Sesi valid", "rolling session menulis ulang cookie", null, "tidak ada Set-Cookie pada request ini");
  }

  return H;
}

// ------------------------------------------------- E. sesi rusak/palsu
async function tampered() {
  const good = await generateSessionCookie(
    { user: { sub: "auth0|audit-user", name: "Audit User" }, tokenSet: { accessToken: "x", idToken: "y", expiresAt: Math.floor(Date.now() / 1000) + 3600 } },
    { secret: SECRET }
  );

  // 1. byte diubah
  const flipped = good.slice(0, -6) + (good.slice(-6, -5) === "a" ? "b" : "a") + good.slice(-5);
  const r1 = await raw("/api/me", { headers: { cookie: `__session=${flipped}` } });
  check("E. Sesi dimanipulasi", "cookie sesi diubah -> ditolak", r1.status === 401, `status=${r1.status}`);

  // 2. sampah
  const r2 = await raw("/api/me", { headers: { cookie: "__session=not-a-real-jwe" } });
  check("E. Sesi dimanipulasi", "cookie sesi sampah -> ditolak", r2.status === 401, `status=${r2.status}`);

  // 3. dienkripsi dgn secret berbeda (attacker punya secret sendiri)
  const forged = await generateSessionCookie(
    { user: { sub: "auth0|attacker", name: "Attacker" }, tokenSet: { accessToken: "x", idToken: "y", expiresAt: Math.floor(Date.now() / 1000) + 3600 } },
    { secret: "f".repeat(64) }
  );
  const r3 = await raw("/api/me", { headers: { cookie: `__session=${forged}` } });
  check("E. Sesi dimanipulasi", "cookie ditempa dgn secret lain -> ditolak", r3.status === 401, `status=${r3.status}`);

  // 4. sesi kedaluwarsa
  const expired = await jose.EncryptJWT.prototype && (await new jose.EncryptJWT({
    user: { sub: "auth0|expired" },
    tokenSet: { accessToken: "x", idToken: "y", expiresAt: 1 },
    internal: { sid: "s", createdAt: 1 }
  })
    .setProtectedHeader({ enc: "A256GCM", alg: "dir" })
    .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
    .encrypt(await key()));
  const r4 = await raw("/api/me", { headers: { cookie: `__session=${expired}` } });
  check("E. Sesi dimanipulasi", "cookie sesi kedaluwarsa -> ditolak", r4.status === 401, `status=${r4.status}`);
}

// ----------------------------------------------------- F. callback CSRF
async function callbackHardening() {
  const cases = [
    ["tanpa state & code", "/auth/callback"],
    ["code tanpa state", "/auth/callback?code=fake_code"],
    ["state acak tanpa cookie txn", "/auth/callback?code=fake&state=" + "a".repeat(43)]
  ];
  for (const [label, path] of cases) {
    const res = await raw(path);
    const body = await res.text();
    const ok = res.status >= 400;
    check("F. Callback CSRF", `${label} -> ${res.status}`, ok, ok ? "" : "callback menerima request tanpa transaksi valid!");
    const leaky = /at .*\/src\/|node_modules|\.ts:\d+/.test(body);
    check("F. Callback CSRF", `${label}: tidak membocorkan stack trace`, !leaky, leaky ? body.slice(0, 160) : "");
  }
}

// --------------------------------------------------------- G. logout
async function logout() {
  const cookie = await generateSessionCookie(
    { user: { sub: "auth0|audit-user" }, tokenSet: { accessToken: "x", idToken: "y", expiresAt: Math.floor(Date.now() / 1000) + 3600 } },
    { secret: SECRET }
  );
  const res = await raw("/auth/logout", { headers: { cookie: `__session=${cookie}` } });
  const loc = res.headers.get("location") || "";
  check("G. Logout", "redirect ke endpoint logout Auth0", loc.includes("/oidc/logout") || loc.includes("/v2/logout"), loc.split("?")[0]);

  const sc = parseSetCookie(res, "__session");
  const cleared = sc && (/Max-Age=0/i.test(sc) || /Expires=Thu, 01 Jan 1970/i.test(sc));
  check("G. Logout", "cookie sesi lokal dihapus", !!cleared, sc ? sc.split(";").slice(0, 3).join(";") : "tidak ada Set-Cookie");

  const u = new URL(loc);
  check("G. Logout", "menyertakan id_token_hint (logout aman)", u.searchParams.has("id_token_hint"), "");
  check("G. Logout", "menyertakan client_id", u.searchParams.has("client_id"), "");
}

// --------------------------------------------------------------- run
console.log(`\nAudit integrasi Auth0 — ${BASE}\n${"=".repeat(60)}\n`);
for (const [name, fn] of [
  ["anon", anonymousAccess],
  ["txn", transactionHardening],
  ["redirect", openRedirect],
  ["auth", authenticated],
  ["tamper", tampered],
  ["callback", callbackHardening],
  ["logout", logout]
]) {
  try {
    await fn();
  } catch (e) {
    check(name, "bagian gagal dijalankan", false, e.message);
  }
  console.log("");
}

const fail = results.filter((r) => r.pass === false);
console.log("=".repeat(60));
console.log(`Total: ${results.length} | PASS ${results.filter((r) => r.pass === true).length} | FAIL ${fail.length} | INFO ${results.filter((r) => r.pass === null).length}`);
if (fail.length) {
  console.log("\nGAGAL:");
  fail.forEach((f) => console.log(`  - ${f.area} :: ${f.name}\n      ${f.detail}`));
}
