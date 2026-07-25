import path from "node:path";

import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // This example lives inside the SDK repo, which has its own lockfile. Pin the
  // workspace root so Turbopack doesn't infer the parent directory. You can drop
  // this when copying the example into a standalone project.
  turbopack: {
    root: path.dirname(new URL(import.meta.url).pathname)
  }
};

export default nextConfig;
