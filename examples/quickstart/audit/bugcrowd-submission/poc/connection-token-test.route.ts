import { NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

/**
 * TEMPORARY — added only to runtime-test FINDING-ipsie-ceiling-connection-
 * token-bypass.md against a real, running Next.js server (not just the
 * SDK's internal vitest harness). Not part of the example app; safe to
 * delete once that test is done.
 *
 * Calls getAccessTokenForConnection() and reports how far the request got:
 * blocked locally by the SDK (same as getSession()/getAccessToken() would
 * be, for a session whose IPSIE ceiling has passed) vs. reaching an actual
 * attempt to exchange the refresh token with Auth0 (proving the ceiling was
 * bypassed for this path, regardless of whether Auth0 itself then accepts
 * or rejects the exchange).
 */
export async function GET() {
  try {
    const result = await auth0.getAccessTokenForConnection({
      connection: "__ipsie_ceiling_runtime_probe__"
    });
    return NextResponse.json({ outcome: "unexpected_success", result });
  } catch (e: unknown) {
    const error = e as { code?: string; message?: string; constructor: { name: string } };
    return NextResponse.json({
      outcome: "error",
      code: error?.code,
      message: error?.message,
      name: error?.constructor?.name
    });
  }
}
