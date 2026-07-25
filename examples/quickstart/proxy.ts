import { auth0 } from "./lib/auth0";

/**
 * Next.js 16 replaces `middleware.ts` with `proxy.ts`. The Auth0 middleware
 * mounts the authentication routes (`/auth/login`, `/auth/logout`,
 * `/auth/callback`, `/auth/profile`, `/auth/access-token`) and keeps the
 * session cookie rolling on every request.
 */
export async function proxy(request: Request) {
  return await auth0.middleware(request);
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
