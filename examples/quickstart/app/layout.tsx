import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "Auth0 Next.js Quickstart",
  description: "A minimal Next.js app authenticated with @auth0/nextjs-auth0"
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
