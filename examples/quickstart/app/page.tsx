import Link from "next/link";

import { auth0 } from "@/lib/auth0";

export default async function Home() {
  const session = await auth0.getSession();

  if (!session) {
    return (
      <main>
        <h1>Auth0 Next.js Quickstart</h1>
        <p>You are not signed in.</p>
        {/*
          Use plain <a> tags rather than <Link>: the auth routes are handled at
          the network boundary, so they must not be navigated to client-side.
        */}
        <div className="actions">
          <a href="/auth/login">Log in</a>
          <a href="/auth/login?screen_hint=signup">Sign up</a>
        </div>
      </main>
    );
  }

  return (
    <main>
      <h1>Welcome, {session.user.name}!</h1>
      <p>{session.user.email}</p>
      <div className="actions">
        <Link href="/dashboard">Dashboard</Link>
        <a href="/auth/logout">Log out</a>
      </div>
    </main>
  );
}
