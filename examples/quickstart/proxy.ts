import { auth0 } from "./lib/auth0";

/**
 * Next.js 16 replaces `middleware.ts` with `proxy.ts`. The Auth0 middleware
 * mounts the authentication routes (`/auth/login`, `/auth/logout`,
 * `/auth/callback`, `/auth/profile`, `/auth/access-token`) and keeps the
 * session cookie rolling on every request.
 */
export async function proxy(request: Request) {
  const res = await auth0.middleware(request);

  // Defence in depth: the SDK sets no-store on most auth responses, but as of
  // v4.25.0 `/auth/access-token` is not one of them — it returns a bearer token
  // with no cache directives, which a shared or heuristic cache may store. Mark
  // every auth response uncacheable regardless of which handler produced it.
  if (new URL(request.url).pathname.startsWith("/auth/")) {
    res.headers.set(
      "Cache-Control",
      "private, no-cache, no-store, must-revalidate, max-age=0"
    );
    res.headers.set("Pragma", "no-cache");
    res.headers.set("Expires", "0");
  }

  return res;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico, sitemap.xml, robots.txt (metadata files)
     */
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)"
  ]
};
