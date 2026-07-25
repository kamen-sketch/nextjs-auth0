/**
 * Dynamic base URL mode — run against a server started WITHOUT APP_BASE_URL.
 *
 *   grep -v '^APP_BASE_URL' .env.local > .env.dynamic
 *   cp .env.local .env.backup && cp .env.dynamic .env.local
 *   pnpm dev -p 3001
 *   BASE=http://localhost:3001 node audit/audit4-dynamic.mjs
 *   cp .env.backup .env.local          # restore
 *
 * With no APP_BASE_URL the SDK infers the base URL from the request host, so
 * the Host header becomes an input to redirect_uri. These checks pin down
 * exactly how far that goes and what stops it.
 */
import http from "node:http";

const BASE = process.env.BASE || "http://localhost:3001";
const raw = (p, o = {}) => fetch(`${BASE}${p}`, { redirect: "manual", ...o });

/**
 * fetch() refuses to set `Host` — it is a forbidden header name, so passing it
 * is silently dropped and the check reports a false negative. Go through
 * node:http, which lets the header through, to test Host handling honestly.
 */
function rawWithHost(path, headers) {
  const u = new URL(BASE + path);
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: "GET", headers },
      (res) => {
        res.resume();
        resolve({ status: res.statusCode, location: res.headers.location });
      }
    );
    req.on("error", reject);
    req.end();
  });
}

const results = [];
function check(area, name, pass, detail) {
  results.push({ area, name, pass, detail });
  const m = pass === true ? "PASS" : pass === false ? "FAIL" : "INFO";
  console.log(`[${m}] ${area} :: ${name}${detail ? `\n        ${detail}` : ""}`);
}

async function redirectUriFor(headers = {}) {
  const res = await raw("/auth/login", { headers });
  if (res.status !== 307) return null;
  return new URL(res.headers.get("location")).searchParams.get("redirect_uri");
}

console.log(`\nMode dynamic base URL — ${BASE}\n${"=".repeat(60)}\n`);

// Pastikan server memang berjalan tanpa APP_BASE_URL.
const baseline = await redirectUriFor();
if (baseline === null) {
  console.log("Server tidak merespons /auth/login dengan 307 — dilewati.");
  process.exit(0);
}
const host = new URL(BASE).host;
if (!baseline.includes(host)) {
  console.log(`redirect_uri baseline (${baseline}) tidak mengikuti host — server ini kemungkinan punya APP_BASE_URL. Dilewati.`);
  process.exit(0);
}
check("R. Base URL dinamis", "baseline mengikuti host permintaan", true, baseline);

// --- Host header mengendalikan redirect_uri -------------------------------
const hostRes = await rawWithHost("/auth/login", { Host: "evil.example.com" });
const viaHost = hostRes.location
  ? new URL(hostRes.location).searchParams.get("redirect_uri")
  : null;
check(
  "R. Base URL dinamis",
  "Host header mengendalikan redirect_uri",
  viaHost?.includes("evil.example.com") === true,
  `Host: evil.example.com -> ${viaHost}`
);

const viaXfh = await redirectUriFor({ "X-Forwarded-Host": "evil.example.com" });
check(
  "R. Base URL dinamis",
  "X-Forwarded-Host juga dihormati (tanpa allowlist)",
  viaXfh?.includes("evil.example.com") === true,
  `X-Forwarded-Host: evil.example.com -> ${viaXfh}`
);

const viaProto = await redirectUriFor({ "X-Forwarded-Proto": "https" });
check(
  "R. Base URL dinamis",
  "X-Forwarded-Proto mengendalikan skema",
  viaProto?.startsWith("https:") === true,
  `X-Forwarded-Proto: https -> ${viaProto}`
);

// --- Jaring pengaman: Auth0 harus menolak host yang tak terdaftar ---------
const evilAuthorize = await raw("/auth/login", { headers: { Host: "evil.example.com" } });
const authorizeUrl = evilAuthorize.headers.get("location");
let auth0Body = "";
let auth0Status = 0;
try {
  const r = await fetch(authorizeUrl, { redirect: "manual" });
  auth0Status = r.status;
  auth0Body = await r.text();
} catch (e) {
  auth0Body = `(gagal menghubungi Auth0: ${e.message})`;
}
const rejected = /Callback URL mismatch|not in the list of allowed callback URLs/i.test(auth0Body);
check(
  "R. Base URL dinamis",
  "Auth0 menolak redirect_uri dari host palsu",
  rejected,
  rejected
    ? `Auth0 -> ${auth0Status} "Callback URL mismatch" — inilah satu-satunya kontrol yg menahan`
    : `Auth0 -> ${auth0Status}; TIDAK menolak. Periksa apakah Allowed Callback URLs memakai wildcard!`
);

check(
  "R. Base URL dinamis",
  "wildcard di Allowed Callback URLs akan meniadakan proteksi ini",
  null,
  "Jika daftar berisi pola spt https://*.vercel.app/auth/callback, host apa pun yg cocok akan diterima " +
    "dan kode otorisasi bisa dikirim ke penyerang. Daftarkan URL secara eksplisit."
);

// --- Atribut cookie di mode ini ------------------------------------------
const txn = (evilAuthorize.headers.getSetCookie?.() || []).find((c) => c.startsWith("__txn_")) || "";
const isHttps = BASE.startsWith("https:");
check("R. Base URL dinamis", "cookie txn tetap HttpOnly", /HttpOnly/i.test(txn), "");
check(
  "R. Base URL dinamis",
  `cookie txn Secure sesuai protokol (${isHttps ? "https" : "http"})`,
  /Secure/i.test(txn) === isHttps,
  isHttps
    ? ""
    : "dev/http: Secure=off. Di produksi tanpa APP_BASE_URL, SDK memaksa secure=true atau melempar InvalidConfigurationError."
);

console.log("");
const fail = results.filter((r) => r.pass === false);
console.log("=".repeat(60));
console.log(`Total: ${results.length} | PASS ${results.filter((r) => r.pass === true).length} | FAIL ${fail.length} | INFO ${results.filter((r) => r.pass === null).length}`);
if (fail.length) {
  console.log("\nGAGAL:");
  fail.forEach((f) => console.log(`  - ${f.area} :: ${f.name}\n      ${f.detail}`));
}
