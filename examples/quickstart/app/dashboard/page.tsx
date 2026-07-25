import Link from "next/link";
import { redirect } from "next/navigation";

import { auth0 } from "@/lib/auth0";

/**
 * A page protected on the server: without a session the visitor is sent to the
 * login route and returned here afterwards.
 */
export default async function Dashboard() {
  const session = await auth0.getSession();

  if (!session) {
    redirect("/auth/login?returnTo=/dashboard");
  }

  return (
    <main>
      <h1>Dashboard</h1>
      <p>The claims below come from the ID token stored in the session.</p>
      <pre>{JSON.stringify(session.user, null, 2)}</pre>
      <div className="actions">
        <Link href="/">Home</Link>
        {/* Auth routes must use <a>: they are handled at the network boundary. */}
        <a href="/auth/logout">Log out</a>
      </div>
    </main>
  );
}
