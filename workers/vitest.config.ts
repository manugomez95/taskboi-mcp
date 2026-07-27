import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.toml" },
        miniflare: {
          bindings: {
            TASKBOI_API_BASE_URL: "https://api.example.invalid/functions/v1/mcp-api",
            OAUTH_CLIENTS: JSON.stringify([{
              client_id: "test-client",
              redirect_uris: ["https://client.example/callback"],
              scopes: ["mcp"],
            }]),
            // Non-sensitive, deterministic 32-byte test-only key.
            OAUTH_ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            OAUTH_ISSUER: "https://worker.test",
            // Explicit test-only publisher allowlist; production has no default.
            OAUTH_CLIENT_METADATA_ALLOWED_ORIGINS: JSON.stringify(["https://metadata-client.example", "https://bad-metadata.example"]),
          },
        },
      },
    },
  },
});
