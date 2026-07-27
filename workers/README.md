# Taskboi MCP Worker

This directory contains the remote Cloudflare Worker transport for the public
Taskboi MCP integration. It uses OAuth 2.0 Authorization Code flow with
mandatory S256 PKCE, opaque short-lived access tokens, revocation, and
server-side encrypted Taskboi API keys.

This is deployable source, not a managed deployment. Cloning or deploying it
does not create a Taskboi Cloud account, a Taskboi API endpoint, a Cloudflare
account, or OAuth client registrations.

## Required operator configuration

Keep real values outside source control. The checked-in `wrangler.toml` contains
only structural Worker configuration.

The Worker validates these bindings on every request and fails closed if any
required value is missing or invalid:

| Binding | Type | Requirement |
| --- | --- | --- |
| `TASKBOI_API_BASE_URL` | plaintext variable | Absolute HTTPS URL ending exactly in `/functions/v1/mcp-api` |
| `OAUTH_ISSUER` | plaintext variable | Canonical public HTTPS origin of this Worker, with no path or trailing slash |
| `OAUTH_ENCRYPTION_KEY` | secret | Canonical base64 encoding of exactly 32 random bytes |
| `OAUTH_STORE` | Durable Object | Structurally declared in `wrangler.toml` |

Taskboi Cloud users should use the API endpoint provided with their separately
provisioned service. Self-hosting operators must supply an equivalent compatible
endpoint; this repository does not provide or discover one.

Optional `OAUTH_CLIENTS` is a JSON array of static public clients:

```json
[
  {
    "client_id": "example-public-client",
    "redirect_uris": ["https://client.example/callback"],
    "scopes": ["mcp"]
  }
]
```

Optional `OAUTH_CLIENT_METADATA_ALLOWED_ORIGINS` is a JSON array of exact
canonical HTTPS publisher origins. When absent or empty, URL-based client ID
metadata documents are rejected. Dynamic registration and static clients remain
available. Do not copy a hosted service's allowlist into a self-hosted instance.

Generate `OAUTH_ENCRYPTION_KEY` without printing it and store it as a Cloudflare
secret:

```sh
openssl rand -base64 32 | npx wrangler secret put OAUTH_ENCRYPTION_KEY
```

Rotating this key invalidates existing authorization codes and tokens. Never put
it in `wrangler.toml`, `.dev.vars`, logs, documentation, or source control.

## Local verification

Use Node.js 18 or later:

```sh
npm ci
npm test
npm run typecheck
npm run build
npm audit --omit=dev --audit-level=high
```

`npm run build` invokes Wrangler only with `--dry-run` and writes an ignored
local bundle to `dist/`. Tests use inert example domains and a deterministic
test-only key.

For interactive local development, create an untracked `.dev.vars` containing
test-only values, then run:

```sh
npm run dev
```

## Operator deployment

After reviewing the Worker, set the required plaintext variables and secret in
your own Cloudflare environment and deploy with Wrangler according to
Cloudflare's documentation. Deployment is an explicit operator action; this
repository has no deployment workflow or production automation.

The resulting MCP endpoint is `${OAUTH_ISSUER}/mcp`. Configure clients with that
URL and complete the OAuth flow. Never put a Taskboi API key in the URL or use
it directly as the MCP bearer token.

## OAuth endpoints

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/` and `/health` | GET | Health check |
| `/.well-known/oauth-protected-resource/mcp` | GET | Protected-resource metadata |
| `/.well-known/oauth-authorization-server` | GET | Authorization-server metadata |
| `/register` | POST | Dynamic public-client registration |
| `/authorize` | GET | Authorization with mandatory S256 PKCE |
| `/token` | POST | Authorization-code exchange |
| `/revoke` | POST | Access-token revocation |
| `/mcp` | POST | Authenticated Streamable HTTP MCP endpoint |

Authorization codes expire after five minutes and access tokens after one hour.
Authorization and token requests require exactly one `resource` value equal to
`${OAUTH_ISSUER}/mcp`. HTTPS redirect URIs are required except for loopback
native-development redirects on `localhost` or `127.0.0.1`.

The binding comparator in [`scripts/`](scripts/) is a reusable, value-suppressing
operator helper. It compares binding metadata without comparing secret values;
it does not deploy anything.

Licensed under the repository's [Apache License 2.0](../LICENSE).
