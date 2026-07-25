import { NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

/**
 * A protected Route Handler. Reading the session works the same way in Route
 * Handlers, Server Components and Server Actions.
 */
export async function GET() {
  const session = await auth0.getSession();

  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  return NextResponse.json({ user: session.user });
}
