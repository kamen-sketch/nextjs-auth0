# Auth0 Next.js Quickstart

A minimal Next.js 16 (App Router) application authenticated with
[`@auth0/nextjs-auth0`](https://github.com/auth0/nextjs-auth0) v4.

## What's in here

| File                    | Purpose                                                             |
| ----------------------- | ------------------------------------------------------------------- |
| `lib/auth0.ts`          | The `Auth0Client` instance, configured from environment variables.  |
| `proxy.ts`              | Mounts the auth routes and keeps the session rolling.                |
| `app/page.tsx`          | Home page: login/signup links, or the user's name when signed in.    |
| `app/dashboard/page.tsx`| A page protected on the server via `redirect()`.                     |
| `app/api/me/route.ts`   | A protected Route Handler returning the current user as JSON.        |

The middleware mounts these routes for you — you don't write them yourself:

- `/auth/login` — start the login flow (`?screen_hint=signup` to sign up, `?returnTo=` to control the landing page)
- `/auth/logout` — log out
- `/auth/callback` — the callback Auth0 redirects back to
- `/auth/profile` — the current user's profile as JSON
- `/auth/access-token` — the current access token

> On Next.js 16 the network-boundary file is `proxy.ts`. On Next.js 15 use a
> `middleware.ts` exporting `middleware` instead — the body is identical.

## Configure Auth0

1. Create a **Regular Web Application** in the [Auth0 Dashboard](https://manage.auth0.com).
2. Add `http://localhost:3000/auth/callback` to **Allowed Callback URLs**.
3. Add `http://localhost:3000` to **Allowed Logout URLs**.

## Run it

```bash
cp .env.example .env.local
# fill in AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET
# and generate the session secret:
openssl rand -hex 32   # -> AUTH0_SECRET

pnpm install
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000).

## Learn more

- [SDK README](https://github.com/auth0/nextjs-auth0#readme)
- [EXAMPLES.md](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md) — access tokens, custom routes, session config, and more
- [Auth0 Next.js Quickstart](https://auth0.com/docs/quickstart/webapp/nextjs)
