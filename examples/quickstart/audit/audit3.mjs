import { hkdf } from "@panva/hkdf";
import * as jose from "jose";
import { generateSessionCookie } from "@auth0/nextjs-auth0/testing";

const BASE = process.env.BASE || "http://localhost:3000";
const SECRET = process.env.AUTH0_SECRET;
const raw = (p, o = {}) => fetch(`${BASE}${p}`, { redirect: "manual", ...o });
const key = () => hkdf("sha256", SECRET, "", "JWE CEK", 32);

const results = [];
function check(area, name, pass, detail) {
  results.push({ area, name, pass, detail });
  const m = pass === true ? "PASS" : pass === false ? "FAIL" : "INFO";
  console.log(`[${m}] ${area} :: ${name}${detail ? `\n        ${detail}` : ""}`);
}

const setCookies = (res) => (res.headers.getSetCookie?.() || []);
const txnOf = (res) => setCookies(res).find((c) => c.startsWith("__txn_"));
const cookieVal = (sc) => decodeURIComponent(sc.split("=").slice(1).join("=").split(";")[0]);
const decryptTxn = async (sc) => (await jose.jwtDecrypt(cookieVal(sc), await key(), { clockTolerance: 15 })).payload;

// ============================================ M. Injeksi parameter otorisasi
async function paramInjection() {
  // Parameter yang TIDAK boleh bisa ditimpa lewat query string.
  const attacks = [
    ["redirect_uri", "https://evil.example.com/harvest", `${BASE}/auth/callback`],
    ["client_id", "ATTACKER_CLIENT_ID", null],
    ["response_type", "token", "code"],
    ["code_challenge_method", "plain", "S256"],
    ["code_challenge", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", null],
    ["state", "attacker-fixed-state", null],
    ["nonce", "attacker-fixed-nonce", null]
  ];

  for (const [param, evil, expected] of attacks) {
    const res = await raw(`/auth/login?${param}=${encodeURIComponent(evil)}`);
    if (res.status !== 307) {
      check("M. Injeksi param", `?${param} -> status ${res.status}`, null, "tidak redirect, dilewati");
      continue;
    }
    const got = new URL(res.headers.get("location")).searchParams.get(param);
    const held = got !== evil && (expected === null || got === expected);
    check(
      "M. Injeksi param",
      `?${param}=${evil.slice(0, 28)} TIDAK menimpa nilai SDK`,
      held,
      `terkirim ke Auth0: ${param}=${got === null ? "(tidak ada)" : got.slice(0, 60)}`
    );
  }

  // Parameter yang MEMANG boleh diteruskan (by design).
  const pass = await raw("/auth/login?audience=https%3A%2F%2Fapi.example.com&scope=openid%20profile%20read%3Aall&prompt=login&login_hint=a%40b.c");
  const q = new URL(pass.headers.get("location")).searchParams;
  check("M. Injeksi param", "audience/scope/prompt/login_hint diteruskan (by design)", null,
    `audience=${q.get("audience")} | scope=${q.get("scope")} | prompt=${q.get("prompt")} | login_hint=${q.get("login_hint")}`);
  check("M. Injeksi param", "penerusan scope dibatasi Auth0, bukan SDK", null,
    "eskalasi scope/audience ditolak authorization server lewat Client Grants, bukan di sisi aplikasi");
}

// ============================================== N. Keacakan & fiksasi sesi
async function randomness() {
  const runs = [];
  for (let i = 0; i < 3; i++) {
    const res = await raw("/auth/login");
    const q = new URL(res.headers.get("location")).searchParams;
    const txn = await decryptTxn(txnOf(res));
    runs.push({ state: q.get("state"), nonce: q.get("nonce"), cc: q.get("code_challenge"), cv: txn.codeVerifier });
  }
  for (const f of ["state", "nonce", "cc", "cv"]) {
    const uniq = new Set(runs.map((r) => r[f]));
    check("N. Keacakan", `${f}: 3 login menghasilkan 3 nilai berbeda`, uniq.size === 3, `unik=${uniq.size}/3`);
  }
  // transaksi paralel: tiap login punya cookie txn sendiri
  const names = new Set();
  for (let i = 0; i < 3; i++) {
    const res = await raw("/auth/login");
    names.add(txnOf(res).split("=")[0]);
  }
  check("N. Keacakan", "transaksi paralel: tiap login punya cookie __txn_ unik", names.size === 3, `cookie unik=${names.size}/3`);
}

// ================================================== O. Chunking cookie sesi
async function chunking() {
  // Sesi > 3500 byte harus dipecah saat DITULIS (rolling session menulis ulang).
  const big = await generateSessionCookie(
    {
      user: { sub: "auth0|chunk", name: "Chunk", bloat: "x".repeat(5000) },
      tokenSet: { accessToken: "AT", idToken: "ID", expiresAt: Math.floor(Date.now() / 1000) + 3600 }
    },
    { secret: SECRET }
  );
  const res = await raw("/", { headers: { cookie: `__session=${big}` } });
  const written = setCookies(res).filter((c) => c.startsWith("__session"));
  const chunks = written.filter((c) => /^__session__\d+=/.test(c));

  check("O. Chunking", "sesi besar terbaca (200)", res.status === 200, `status=${res.status}, nilai=${big.length} byte`);
  if (written.length === 0) {
    check("O. Chunking", "cookie dipecah saat ditulis ulang", null, "tidak ada Set-Cookie pada request ini (sesi tidak di-roll)");
  } else {
    check("O. Chunking", "cookie besar dipecah jadi __session__0/__1", chunks.length >= 2, `chunk=${chunks.length}, nama=${written.map((c) => c.split("=")[0]).join(", ")}`);
    for (const c of chunks) {
      const len = c.split(";")[0].length;
      check("O. Chunking", `${c.split("=")[0]} di bawah batas 4096 byte browser`, len < 4096, `${len} byte`);
    }
  }

  // Logout harus membersihkan chunk, bukan hanya __session
  const lo = await raw("/auth/logout", { headers: { cookie: `__session__0=aaa; __session__1=bbb` } });
  const cleared = setCookies(lo).filter((c) => /^__session/.test(c) && /Max-Age=0/i.test(c));
  check("O. Chunking", "logout menghapus cookie chunk juga", cleared.length >= 2,
    `dihapus: ${cleared.map((c) => c.split("=")[0]).join(", ") || "(tidak ada)"}`);
}

// ============================================ P. Cookie legacy (appSession)
async function legacyCookie() {
  // Cookie legacy v3 bernama `appSession`. Nilai sampah tidak boleh mengautentikasi.
  const r1 = await raw("/api/me", { headers: { cookie: "appSession=garbage-value" } });
  check("P. Cookie legacy", "appSession berisi sampah -> tetap 401", r1.status === 401, `status=${r1.status}`);

  // Cookie legacy ditempa dgn secret yg salah
  const forged = await generateSessionCookie(
    { user: { sub: "auth0|legacy-attacker" }, tokenSet: { accessToken: "x", idToken: "y", expiresAt: Math.floor(Date.now() / 1000) + 3600 } },
    { secret: "0".repeat(64) }
  );
  const r2 = await raw("/api/me", { headers: { cookie: `appSession=${forged}` } });
  check("P. Cookie legacy", "appSession ditempa secret lain -> 401", r2.status === 401, `status=${r2.status}`);

  // Cookie legacy VALID (dienkripsi dgn secret asli) diterima -> jalur migrasi
  const valid = await generateSessionCookie(
    { user: { sub: "auth0|legacy-user", name: "Legacy" }, tokenSet: { accessToken: "x", idToken: "y", expiresAt: Math.floor(Date.now() / 1000) + 3600 } },
    { secret: SECRET }
  );
  const r3 = await raw("/api/me", { headers: { cookie: `appSession=${valid}` } });
  check("P. Cookie legacy", "appSession valid diterima (migrasi v3->v4)", r3.status === 200,
    `status=${r3.status} — hanya pemegang AUTH0_SECRET yg bisa membuatnya, jadi bukan jalur downgrade`);

  // __session harus menang atas appSession
  const attacker = await generateSessionCookie({ user: { sub: "auth0|ATTACKER" }, tokenSet: { accessToken: "x", idToken: "y", expiresAt: Math.floor(Date.now() / 1000) + 3600 } }, { secret: SECRET });
  const victim = await generateSessionCookie({ user: { sub: "auth0|VICTIM" }, tokenSet: { accessToken: "x", idToken: "y", expiresAt: Math.floor(Date.now() / 1000) + 3600 } }, { secret: SECRET });
  const r4 = await raw("/api/me", { headers: { cookie: `__session=${victim}; appSession=${attacker}` } });
  const who = r4.status === 200 ? (await r4.json()).user?.sub : null;
  check("P. Cookie legacy", "__session diprioritaskan di atas appSession", who === "auth0|VICTIM", `identitas terpilih: ${who}`);
}

// ================================================= Q. Callback state binding
async function callbackBinding() {
  // Login sungguhan -> dapat cookie txn + state yg cocok
  const login = await raw("/auth/login");
  const state = new URL(login.headers.get("location")).searchParams.get("state");
  const txn = txnOf(login);
  const txnHeader = txn.split(";")[0];

  // state benar + cookie benar, tapi code palsu -> gagal di penukaran kode (bukan lolos)
  const r1 = await raw(`/auth/callback?code=FAKE_CODE&state=${state}`, { headers: { cookie: txnHeader } });
  check("Q. Callback binding", "state cocok tapi code palsu -> ditolak", r1.status >= 400, `status=${r1.status}`);

  // cookie txn benar tapi state di URL diubah -> ditolak
  const r2 = await raw(`/auth/callback?code=FAKE_CODE&state=${state.slice(0, -3)}XYZ`, { headers: { cookie: txnHeader } });
  check("Q. Callback binding", "state di URL diubah -> ditolak", r2.status >= 400, `status=${r2.status}`);

  // cookie txn dari transaksi LAIN (state milik login berbeda) -> ditolak
  const other = await raw("/auth/login");
  const otherTxn = txnOf(other).split(";")[0];
  const r3 = await raw(`/auth/callback?code=FAKE_CODE&state=${state}`, { headers: { cookie: otherTxn } });
  check("Q. Callback binding", "cookie txn dari transaksi lain -> ditolak", r3.status >= 400, `status=${r3.status}`);

  // error dari authorization server tidak boleh dipantulkan mentah (XSS/informasi)
  const r4 = await raw(`/auth/callback?error=access_denied&error_description=%3Cscript%3Ealert(1)%3C%2Fscript%3E&state=${state}`, { headers: { cookie: txnHeader } });
  const body4 = await r4.text();
  check("Q. Callback binding", "error_description tidak dipantulkan mentah sbg HTML", !body4.includes("<script>alert(1)</script>"),
    `status=${r4.status}, mengandung <script> mentah: ${body4.includes("<script>alert(1)</script>")}`);
}

// ================================================================== run
console.log(`\nAudit lanjutan — ${BASE}\n${"=".repeat(60)}\n`);
for (const [n, fn] of [["M", paramInjection], ["N", randomness], ["O", chunking], ["P", legacyCookie], ["Q", callbackBinding]]) {
  try { await fn(); } catch (e) { check(n, "bagian gagal dijalankan", false, e.message); }
  console.log("");
}
const fail = results.filter((r) => r.pass === false);
console.log("=".repeat(60));
console.log(`Total: ${results.length} | PASS ${results.filter((r) => r.pass === true).length} | FAIL ${fail.length} | INFO ${results.filter((r) => r.pass === null).length}`);
if (fail.length) {
  console.log("\nGAGAL:");
  fail.forEach((f) => console.log(`  - ${f.area} :: ${f.name}\n      ${f.detail}`));
}
