import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

const config = [
  ...nextCoreWebVitals,
  ...nextTypescript,
  {
    // audit/ holds standalone probes (Node scripts + a reference .test.ts meant
    // to be dropped into the SDK's own suite), not part of the Next.js app build.
    ignores: [".next/**", "node_modules/**", "audit/**"]
  }
];

export default config;
