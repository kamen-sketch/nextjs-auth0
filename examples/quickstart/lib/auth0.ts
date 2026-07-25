import { Auth0Client } from "@auth0/nextjs-auth0/server";

/**
 * The Auth0 client is configured from environment variables:
 * AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_SECRET and the
 * optional APP_BASE_URL. See `.env.example`.
 */
export const auth0 = new Auth0Client();
