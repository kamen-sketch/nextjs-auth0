import { generateSessionCookie } from "@auth0/nextjs-auth0/testing";

const BASE = "http://localhost:3000";
const SECRET = process.env.AUTH0_SECRET;
const raw = (p, o = {}) => fetch(`${BASE}${p}`, { redirect: "manual", ...o });

const AT = "SENTINEL_ACCESS_TOKEN";
const RT = "SENTINEL_REFRESH_TOKEN";
const ID = "SENTINEL_ID_TOKEN";

function check(area, name, pass, detail) {
  const m = pass === true ? "PASS" : pass === false ? "FAIL" : "INFO";
  console.log(`[${m}] ${area} :: ${name}${detail ? `\n        ${detail}` : ""}`);
}

const session = await generateSessionCookie(
  {
    user: {
      sub: "auth0|audit",
      name: "Audit",
      email: "a@b.c",
      // klaim sensitif yg kadang ada di ID token
      "https://example.com/roles": ["admin"]
    },
    tokenSet: {
      accessToken: AT,
      refreshToken: RT,
      idToken: ID,
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      scope: "openid profile email offline_access"
    }
  },
  { secret: SECRET }
);
const H = { cookie: `__session=${session}` };

console.log("\nH. Endpoint bawaan SDK — kebocoran token\n" + "=".repeat(60));

// /auth/profile
const prof = await raw("/auth/profile", { headers: H });
const profBody = await prof.text();
check("H. Endpoint SDK", `/auth/profile -> ${prof.status}`, prof.status === 200, "");
const profLeaks = [["accessToken", AT], ["refreshToken", RT], ["idToken", ID]].filter(([, v]) => profBody.includes(v));
check(
  "H. Endpoint SDK",
  "/auth/profile TIDAK mengembalikan token apa pun",
  profLeaks.length === 0,
  profLeaks.length ? `BOCOR: ${profLeaks.map(([k]) => k).join(", ")}` : `body = ${profBody.slice(0, 120)}`
);

// /auth/access-token
const tok = await raw("/auth/access-token", { headers: H });
const tokBody = await tok.text();
check("H. Endpoint SDK", `/auth/access-token -> ${tok.status}`, tok.status === 200, "");
check(
  "H. Endpoint SDK",
  "/auth/access-token mengembalikan access token (by design)",
  tokBody.includes(AT),
  ""
);
check(
  "H. Endpoint SDK",
  "/auth/access-token TIDAK ikut membocorkan refresh token",
  !tokBody.includes(RT),
  tokBody.includes(RT) ? "BOCOR: refreshToken ikut terkirim ke browser!" : `field = ${Object.keys(JSON.parse(tokBody || "{}")).join(", ")}`
);
check(
  "H. Endpoint SDK",
  "/auth/access-token TIDAK ikut membocorkan id token",
  !tokBody.includes(ID),
  ""
);

// Cache-Control pada endpoint sensitif
console.log("\nI. Header respons\n" + "=".repeat(60));
for (const [p, res] of [["/auth/profile", prof], ["/auth/access-token", tok]]) {
  const cc = res.headers.get("cache-control") || "(tidak ada)";
  const priv = /no-store|no-cache|private/i.test(cc);
  check("I. Header", `${p} Cache-Control mencegah cache bersama`, priv, `Cache-Control: ${cc}`);
}

// apakah /api/me kita sendiri punya cache-control?
const me = await raw("/api/me", { headers: H });
check(
  "I. Header",
  "/api/me (route kita) Cache-Control",
  null,
  `Cache-Control: ${me.headers.get("cache-control") || "(tidak ada)"}`
);

// Masa berlaku sesi
console.log("\nJ. Masa berlaku sesi\n" + "=".repeat(60));
const home = await raw("/", { headers: H });
const sc = (home.headers.getSetCookie?.() || []).find((c) => c.startsWith("__session"));
if (sc) {
  const maxAge = sc.match(/Max-Age=(\d+)/i)?.[1];
  check("J. Sesi", "cookie sesi punya Max-Age (bukan cookie permanen)", !!maxAge, `Max-Age=${maxAge} detik (~${Math.round(maxAge / 86400)} hari)`);
} else {
  check("J. Sesi", "rolling session menulis ulang cookie tiap request", null, "tidak ada Set-Cookie");
}

// Penegakan absoluteDuration terjadi saat MENULIS cookie: exp JWE di-set ke
// min(now + inactivity, createdAt + absolute). Saat MEMBACA, yang dipercaya
// adalah exp JWE itu. Jadi yang benar diuji: maxAge menyusut untuk sesi lama.
const oldCreatedAt = Math.floor(Date.now() / 1000) - 60 * 60 * 24 * 2.5; // 2.5 hari
const oldSession = await generateSessionCookie(
  {
    user: { sub: "auth0|old" },
    tokenSet: { accessToken: AT, idToken: ID, expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    internal: { sid: "old-sid", createdAt: oldCreatedAt }
  },
  { secret: SECRET }
);
const oldRes = await raw("/", { headers: { cookie: `__session=${oldSession}` } });
const oldSc = (oldRes.headers.getSetCookie?.() || []).find((c) => c.startsWith("__session"));
const oldMaxAge = oldSc ? Number(oldSc.match(/Max-Age=(\d+)/i)?.[1]) : null;
check(
  "J. Sesi",
  "sesi umur 2.5 hari: maxAge dipotong oleh absoluteDuration (3 hari)",
  oldMaxAge !== null && oldMaxAge < 60 * 60 * 24,
  oldMaxAge === null
    ? "tidak ada Set-Cookie (sesi tidak di-roll pada request ini)"
    : `Max-Age=${oldMaxAge}s (~${(oldMaxAge / 3600).toFixed(1)} jam) — sisa dari batas 3 hari, bukan 1 hari penuh`
);

// sesi tidak aktif lama
const idle = await generateSessionCookie(
  {
    user: { sub: "auth0|idle" },
    tokenSet: { accessToken: AT, idToken: ID, expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    internal: { sid: "idle-sid", createdAt: Math.floor(Date.now() / 1000) - 60 * 30 }
  },
  { secret: SECRET }
);
const idleRes = await raw("/api/me", { headers: { cookie: `__session=${idle}` } });
check("J. Sesi", "sesi baru (30 menit) diterima", idleRes.status === 200, `status=${idleRes.status}`);

// Cookie sesi besar -> chunking
console.log("\nK. Cookie besar (chunking)\n" + "=".repeat(60));
const big = await generateSessionCookie(
  {
    user: { sub: "auth0|big", name: "Big", bloat: "x".repeat(6000) },
    tokenSet: { accessToken: AT, idToken: ID, expiresAt: Math.floor(Date.now() / 1000) + 3600 }
  },
  { secret: SECRET }
);
check("K. Chunking", "cookie sesi besar dihasilkan", true, `panjang = ${big.length} byte`);
const bigRes = await raw("/api/me", { headers: { cookie: `__session=${big}` } });
check(
  "K. Chunking",
  "sesi besar dalam satu cookie masih terbaca",
  bigRes.status === 200,
  `status=${bigRes.status}; catatan: batas cookie browser ~4096 byte/cookie — SDK memecah jadi __session.0/.1 saat menulis`
);

// Method selain GET pada route auth
console.log("\nL. Metode HTTP\n" + "=".repeat(60));
for (const m of ["POST", "DELETE"]) {
  const r = await raw("/auth/logout", { method: m, headers: H });
  check("L. Metode", `${m} /auth/logout -> ${r.status}`, null, "");
}
const rp = await raw("/api/me", { method: "POST", headers: H });
check("L. Metode", `POST /api/me -> ${rp.status}`, rp.status === 405, "route hanya mengekspor GET");
