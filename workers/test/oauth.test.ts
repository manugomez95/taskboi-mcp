import { env, fetchMock, runDurableObjectAlarm, runInDurableObject, SELF } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { handleOAuth, validateOAuthConfiguration } from "../src/oauth";

const redirectUri = "https://client.example/callback";
const clientId = "test-client";
const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
let nextIssueIp = 1;

function base64Url(bytes: Uint8Array): string {
  let value = "";
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function challenge(value = verifier): Promise<string> {
  return base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}

function authorizationUrl(overrides: Record<string, string> = {}): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    state: "safe-state",
    code_challenge: "a".repeat(43),
    code_challenge_method: "S256",
    scope: "mcp",
    resource: "https://worker.test/mcp",
    ...overrides,
  });
  return `https://worker.test/authorize?${params}`;
}

async function issueCode(): Promise<string> {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    state: "round-trip",
    code_challenge: await challenge(),
    code_challenge_method: "S256",
    scope: "mcp",
    resource: "https://worker.test/mcp",
    api_key: "tk_test_api_key",
  });
  const response = await SELF.fetch("https://worker.test/authorize/submit", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "CF-Connecting-IP": `192.0.2.${nextIssueIp++}` },
    body: params,
    redirect: "manual",
  });
  expect(response.status).toBe(302);
  const location = new URL(response.headers.get("location")!);
  expect(location.origin + location.pathname).toBe(redirectUri);
  expect(location.searchParams.get("state")).toBe("round-trip");
  return location.searchParams.get("code")!;
}

async function exchange(code: string, overrides: Record<string, string> = {}): Promise<Response> {
  return SELF.fetch("https://worker.test/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: clientId,
      redirect_uri: redirectUri,
      resource: "https://worker.test/mcp",
      ...overrides,
    }),
  });
}

describe("hardened OAuth worker", () => {
  beforeAll(() => fetchMock.activate());
  afterEach(() => vi.useRealTimers());
  beforeEach(() => {
    fetchMock.disableNetConnect();
    fetchMock.get("https://api.example.invalid")
      .intercept({ path: "/functions/v1/mcp-api/projects", method: "GET" })
      .reply(200, { projects: [] });
  });

  it("fails closed for missing or malformed OAuth bindings", () => {
    const configured = {
      OAUTH_STORE: env.OAUTH_STORE,
      OAUTH_CLIENTS: env.OAUTH_CLIENTS,
      OAUTH_ISSUER: env.OAUTH_ISSUER,
      TASKBOI_API_BASE_URL: env.TASKBOI_API_BASE_URL,
    };
    expect(() => validateOAuthConfiguration(configured)).toThrow(/OAUTH_ENCRYPTION_KEY/);
    expect(() => validateOAuthConfiguration({ ...configured, OAUTH_ENCRYPTION_KEY: "not-base64" })).toThrow(/exactly 32 bytes/);
    expect(() => validateOAuthConfiguration({ ...configured, OAUTH_ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" })).not.toThrow();
    expect(() => validateOAuthConfiguration({ OAUTH_STORE: env.OAUTH_STORE, OAUTH_ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", OAUTH_ISSUER: "https://issuer.example", TASKBOI_API_BASE_URL: env.TASKBOI_API_BASE_URL })).not.toThrow();
    expect(() => validateOAuthConfiguration({ ...configured, OAUTH_ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", OAUTH_ISSUER: "https://issuer.example/path" })).toThrow(/origin/);
  });

  it("publishes RFC metadata and advertises protected-resource discovery on 401", async () => {
    const resource = await SELF.fetch("https://untrusted-host.test/.well-known/oauth-protected-resource/mcp");
    expect(await resource.json()).toEqual({ resource: "https://worker.test/mcp", authorization_servers: ["https://worker.test"], scopes_supported: ["mcp"] });
    const server = await (await SELF.fetch("https://untrusted-host.test/.well-known/oauth-authorization-server")).json<Record<string, unknown>>();
    expect(server).toMatchObject({ issuer: "https://worker.test", authorization_endpoint: "https://worker.test/authorize", token_endpoint: "https://worker.test/token", registration_endpoint: "https://worker.test/register", client_id_metadata_document_supported: true });
    expect(server.code_challenge_methods_supported).toEqual(["S256"]);
    const unauthorized = await SELF.fetch("https://worker.test/mcp", { method: "POST", body: "{}" });
    expect(unauthorized.headers.get("www-authenticate")).toBe('Bearer resource_metadata="https://worker.test/.well-known/oauth-protected-resource/mcp", scope="mcp"');
  });

  it("resolves valid HTTPS client metadata and rejects unsafe or mismatched documents", async () => {
    const metadataId = "https://metadata-client.example/client.json";
    fetchMock.get("https://metadata-client.example").intercept({ path: "/client.json", method: "GET" }).reply(200, {
      client_id: metadataId, client_name: "Metadata Client", redirect_uris: ["https://metadata-client.example/callback"], token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"], response_types: ["code"], code_challenge_methods_supported: ["S256"], scope: "mcp",
    }, { headers: { "Content-Type": "application/json" } });
    expect((await SELF.fetch(authorizationUrl({ client_id: metadataId, redirect_uri: "https://metadata-client.example/callback" }))).status).toBe(200);

    const badId = "https://bad-metadata.example/client.json";
    fetchMock.get("https://bad-metadata.example").intercept({ path: "/client.json", method: "GET" }).reply(200, {
      client_id: "https://other.example/client.json", client_name: "Bad Client", redirect_uris: ["https://bad-metadata.example/callback"], token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"], response_types: ["code"], code_challenge_methods_supported: ["S256"],
    }, { headers: { "Content-Type": "application/json" } });
    expect((await SELF.fetch(authorizationUrl({ client_id: badId, redirect_uri: "https://bad-metadata.example/callback" }))).status).toBe(400);
    expect((await SELF.fetch(authorizationUrl({ client_id: "https://127.0.0.1/client.json", redirect_uri: redirectUri }))).status).toBe(400);
  });

  it("requires client_name specifically for Client ID Metadata Documents", async () => {
    const metadataId = "https://metadata-client.example/unnamed.json";
    fetchMock.get("https://metadata-client.example").intercept({ path: "/unnamed.json", method: "GET" }).reply(200, {
      client_id: metadataId, redirect_uris: ["https://metadata-client.example/callback"], token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"], response_types: ["code"], code_challenge_methods_supported: ["S256"],
    }, { headers: { "Content-Type": "application/json" } });
    expect((await SELF.fetch(authorizationUrl({ client_id: metadataId, redirect_uri: "https://metadata-client.example/callback" }))).status).toBe(400);

    const missingPkceId = "https://metadata-client.example/missing-pkce.json";
    fetchMock.get("https://metadata-client.example").intercept({ path: "/missing-pkce.json", method: "GET" }).reply(200, {
      client_id: missingPkceId, client_name: "Missing PKCE Declaration", redirect_uris: ["https://metadata-client.example/callback"], token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"], response_types: ["code"],
    }, { headers: { "Content-Type": "application/json" } });
    expect((await SELF.fetch(authorizationUrl({ client_id: missingPkceId, redirect_uri: "https://metadata-client.example/callback" }))).status).toBe(400);
  });

  it("checks live metadata URL policy before using a cached document", async () => {
    const metadataId = "https://metadata-client.example/cached.json";
    fetchMock.get("https://metadata-client.example").intercept({ path: "/cached.json", method: "GET" }).reply(200, {
      client_id: metadataId, client_name: "Cached Client", redirect_uris: ["https://metadata-client.example/callback"], token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"], response_types: ["code"], code_challenge_methods_supported: ["S256"],
    }, { headers: { "Content-Type": "application/json" } });
    const request = new Request(authorizationUrl({ client_id: metadataId, redirect_uri: "https://metadata-client.example/callback" }));
    expect((await handleOAuth(request, env)).status).toBe(200);
    const deallowedEnv = { ...env, OAUTH_CLIENT_METADATA_ALLOWED_ORIGINS: "[]" };
    expect((await handleOAuth(request, deallowedEnv))!.status).toBe(400);
    const neverAllowed = new Request(authorizationUrl({ client_id: "https://not-allowed.example/client.json" }));
    expect((await handleOAuth(neverAllowed, env))!.status).toBe(400);
  });

  it("rejects metadata redirects, encoded dot paths, and oversized bodies without network fallback", async () => {
    const redirectId = "https://metadata-client.example/redirect.json";
    fetchMock.get("https://metadata-client.example").intercept({ path: "/redirect.json", method: "GET" }).reply(302, "", { headers: { Location: "/client.json", "Content-Type": "application/json" } });
    expect((await SELF.fetch(authorizationUrl({ client_id: redirectId }))).status).toBe(400);

    const oversizedId = "https://metadata-client.example/large.json";
    fetchMock.get("https://metadata-client.example").intercept({ path: "/large.json", method: "GET" }).reply(200, "x".repeat(16_385), { headers: { "Content-Type": "application/json" } });
    expect((await SELF.fetch(authorizationUrl({ client_id: oversizedId }))).status).toBe(400);
    expect((await SELF.fetch(authorizationUrl({ client_id: "https://metadata-client.example/safe/%2e%2e/client.json" }))).status).toBe(400);
  });

  it("requires exactly one matching resource at authorize and token", async () => {
    for (const resource of [undefined, "https://wrong.example/mcp"]) {
      const url = new URL(authorizationUrl());
      if (resource === undefined) url.searchParams.delete("resource"); else url.searchParams.set("resource", resource);
      expect((await SELF.fetch(url)).status).toBe(400);
    }
    const duplicateAuthorize = new URL(authorizationUrl());
    duplicateAuthorize.searchParams.append("resource", "https://worker.test/mcp");
    expect((await SELF.fetch(duplicateAuthorize)).status).toBe(400);

    for (const resource of [undefined, "https://wrong.example/mcp", "duplicate"] as const) {
      const code = await issueCode();
      const body = new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId, redirect_uri: redirectUri });
      if (resource !== undefined) body.append("resource", resource === "duplicate" ? "https://worker.test/mcp" : resource);
      if (resource === "duplicate") body.append("resource", "https://worker.test/mcp");
      expect((await SELF.fetch("https://worker.test/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body })).status).toBe(400);
      expect((await exchange(code)).status).toBe(200);
    }
  });

  it("dynamically registers safe public clients without authorization-server PKCE metadata", async () => {
    const register = (body: unknown) => SELF.fetch("https://worker.test/register", { method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": crypto.randomUUID() }, body: JSON.stringify(body) });
    const valid = await register({ client_name: "Dynamic Client", redirect_uris: ["https://dynamic.example/callback"], token_endpoint_auth_method: "none", grant_types: ["authorization_code"], response_types: ["code"] });
    expect(valid.status).toBe(201);
    const registration = await valid.json<{ client_id: string; client_secret_expires_at?: number }>();
    expect(registration.client_id).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(registration).not.toHaveProperty("client_secret_expires_at");
    expect(registration).not.toHaveProperty("code_challenge_methods_supported");
    expect((await SELF.fetch(authorizationUrl({ client_id: registration.client_id, redirect_uri: "https://dynamic.example/callback" }))).status).toBe(200);
    expect((await SELF.fetch(authorizationUrl({ client_id: registration.client_id, redirect_uri: "https://dynamic.example/callback", code_challenge_method: "plain" }))).status).toBe(400);
    const unnamed = await register({ redirect_uris: ["https://unnamed.example/callback"], logo_uri: "https://unnamed.example/logo.png", arbitrary_extension: { accepted: true }, grant_types: ["authorization_code"], response_types: ["code"], code_challenge_methods_supported: ["S256"] });
    expect(unnamed.status).toBe(201);
    expect(await unnamed.json()).not.toHaveProperty("client_name");
    expect((await register({ redirect_uris: ["https://dynamic.example/callback#fragment"], grant_types: ["authorization_code"], response_types: ["code"], code_challenge_methods_supported: ["S256"] })).status).toBe(400);
    expect((await register({ redirect_uris: ["https://dynamic.example/callback"], token_endpoint_auth_method: "client_secret_basic", client_secret: "forbidden", grant_types: ["authorization_code"], response_types: ["code"], code_challenge_methods_supported: ["S256"] })).status).toBe(400);
  });

  it("accepts Hermes public-client registration metadata with refresh_token", async () => {
    const response = await SELF.fetch("https://worker.test/register", { method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": crypto.randomUUID() }, body: JSON.stringify({ redirect_uris: ["http://127.0.0.1:54321/callback"], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) });
    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({ grant_types: ["authorization_code"], response_types: ["code"], token_endpoint_auth_method: "none" });
  });

  it("allows a Hermes consent POST to redirect to its registered loopback callback", async () => {
    const loopback = "http://127.0.0.1:54322/callback";
    const registrationResponse = await SELF.fetch("https://worker.test/register", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": crypto.randomUUID() },
      body: JSON.stringify({ redirect_uris: [loopback], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }),
    });
    const registration = await registrationResponse.json<{ client_id: string }>();
    const authorization = new URL(authorizationUrl({ client_id: registration.client_id, redirect_uri: loopback, state: "hermes-state" }));
    const page = await SELF.fetch(authorization);
    expect(page.status).toBe(200);
    expect(page.headers.get("content-security-policy")).toContain(`form-action 'self' http://127.0.0.1:54322`);

    const submission = await SELF.fetch("https://worker.test/authorize/submit", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "CF-Connecting-IP": crypto.randomUUID() },
      body: new URLSearchParams({
        ...Object.fromEntries(authorization.searchParams),
        api_key: "tk_synthetic_api_key",
      }),
      redirect: "manual",
    });
    expect(submission.status).toBe(302);
    const callback = new URL(submission.headers.get("location")!);
    expect(callback.origin + callback.pathname).toBe(loopback);
    expect(callback.searchParams.get("code")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(callback.searchParams.get("state")).toBe("hermes-state");
  });

  it("rejects registration metadata with an unsupported grant", async () => {
    const response = await SELF.fetch("https://worker.test/register", { method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": crypto.randomUUID() }, body: JSON.stringify({ redirect_uris: ["http://127.0.0.1:54321/callback"], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token", "client_credentials"], response_types: ["code"] }) });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_client_metadata" });
  });

  it("enforces registration rate limits and recovers global capacity after expiry cleanup", async () => {
    const stub = env.OAUTH_STORE.get(env.OAUTH_STORE.idFromName("oauth"));
    const request = (ip: string) => SELF.fetch("https://worker.test/register", { method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip }, body: JSON.stringify({ redirect_uris: ["https://capacity.example/callback"], grant_types: ["authorization_code"], response_types: ["code"], code_challenge_methods_supported: ["S256"] }) });
    for (let index = 0; index < 100; index++) expect((await request(`capacity-${index}`)).status).toBe(201);
    let expiresAt = 0;
    await runInDurableObject(stub, async (_instance, state) => {
      const records = await state.storage.list<{ expiresAt?: number }>({ prefix: "dcr:" });
      const expiry = await state.storage.list({ prefix: "expiry:" });
      expect(await state.storage.get("dcr:count")).toBe(100);
      expect(records.size).toBe(101); // 100 records plus dcr:count.
      expect([...records.keys()].filter((key) => key !== "dcr:count")).toHaveLength(100);
      expect([...expiry.values()].filter((key) => typeof key === "string" && key.startsWith("dcr:"))).toHaveLength(100);
      expiresAt = Math.max(...[...records.entries()].filter(([key]) => key !== "dcr:count").map(([, record]) => record.expiresAt ?? 0));
    });
    expect((await request("capacity-overflow")).status).toBe(503);
    vi.useFakeTimers();
    vi.setSystemTime(expiresAt + 1);
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    await runInDurableObject(stub, async (_instance, state) => {
      expect(await state.storage.get("dcr:count")).toBe(0);
      expect((await state.storage.list({ prefix: "dcr:" })).size).toBe(1);
      expect((await state.storage.list({ prefix: "expiry:" })).size).toBe(0);
    });
    expect((await request("capacity-recovered")).status).toBe(201);
    await runInDurableObject(stub, async (_instance, state) => {
      expect(await state.storage.get("dcr:count")).toBe(1);
      expect((await state.storage.list({ prefix: "dcr:" })).size).toBe(2);
      expect((await state.storage.list({ prefix: "expiry:" })).size).toBe(1);
    });

    for (let attempt = 0; attempt < 5; attempt++) expect((await request("198.51.100.12")).status).not.toBe(429);
    const limited = await request("198.51.100.12");
    expect(limited.status).toBe(429);
    expect(await limited.json()).toMatchObject({ error: "slow_down" });
  }, 30_000);

  it("escapes state and rejects injected or mismatched redirect URIs", async () => {
    const payload = `\"><script>alert(1)</script>`;
    const page = await SELF.fetch(authorizationUrl({ state: payload }));
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).not.toContain(payload);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
    expect(page.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(page.headers.get("x-content-type-options")).toBe("nosniff");
    expect(page.headers.get("x-frame-options")).toBe("DENY");

    const mismatch = await SELF.fetch(authorizationUrl({ redirect_uri: "https://evil.example/callback" }));
    expect(mismatch.status).toBe(400);
    expect(mismatch.headers.get("location")).toBeNull();
    expect(await mismatch.json()).toMatchObject({ error: "invalid_request" });
  });

  it("shows the client, exact redirect details, scope, and capabilities on consent", async () => {
    const page = await SELF.fetch(authorizationUrl());
    const html = await page.text();
    expect(html).toContain("Client ID");
    expect(html).toContain(clientId);
    expect(html).toContain("Redirect origin");
    expect(html).toContain("https://client.example");
    expect(html).toContain("Redirect destination");
    expect(html).toContain(redirectUri);
    expect(html).toContain("Requested scope");
    expect(html).toContain("mcp");
    expect(html).toContain("read, create, update, complete, and delete");
  });

  it("throttles authorization submissions by edge-provided client IP before validation", async () => {
    const body = new URLSearchParams({
      response_type: "code", client_id: clientId, redirect_uri: redirectUri, state: "rate-test",
      code_challenge: "a".repeat(43), code_challenge_method: "S256", scope: "mcp", resource: "https://worker.test/mcp", api_key: "invalid-key",
    });
    const submit = () => SELF.fetch("https://worker.test/authorize/submit", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "CF-Connecting-IP": "203.0.113.45" },
      body,
      redirect: "manual",
    });
    for (let attempt = 0; attempt < 5; attempt++) expect((await submit()).status).not.toBe(429);
    const limited = await submit();
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toMatch(/^\d+$/);
    expect(await limited.json()).toMatchObject({ error: "slow_down" });
  });

  it("resets the edge-IP rate limit after its window", async () => {
    const connectingIp = "203.0.113.46";
    const body = new URLSearchParams({
      response_type: "code", client_id: clientId, redirect_uri: redirectUri, state: "reset-test",
      code_challenge: "a".repeat(43), code_challenge_method: "S256", scope: "mcp", resource: "https://worker.test/mcp",
    });
    const submit = () => SELF.fetch("https://worker.test/authorize/submit", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "CF-Connecting-IP": connectingIp },
      body,
    });
    for (let attempt = 0; attempt < 5; attempt++) expect((await submit()).status).not.toBe(429);
    expect((await submit()).status).toBe(429);
    const identity = await challenge(connectingIp);
    const stub = env.OAUTH_STORE.get(env.OAUTH_STORE.idFromName(`authorize-rate:${identity}`));
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.put("rate", { count: 6, resetsAt: Date.now() - 1 });
    });
    expect((await submit()).status).not.toBe(429);
  });

  it("falls back to a bounded local rate limit when the edge IP header is absent", async () => {
    const body = new URLSearchParams({
      response_type: "code", client_id: clientId, redirect_uri: redirectUri, state: "fallback-test",
      code_challenge: "a".repeat(43), code_challenge_method: "S256", scope: "mcp", resource: "https://worker.test/mcp",
    });
    const submit = () => SELF.fetch("https://worker.test/authorize/submit", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "oauth-fallback-test" },
      body,
    });
    for (let attempt = 0; attempt < 5; attempt++) expect((await submit()).status).not.toBe(429);
    const limited = await submit();
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toMatch(/^\d+$/);
    expect(await limited.json()).toMatchObject({ error: "slow_down" });
  });

  it("requires well-formed S256 PKCE", async () => {
    expect((await SELF.fetch(authorizationUrl({ code_challenge: "" }))).status).toBe(400);
    expect((await SELF.fetch(authorizationUrl({ code_challenge_method: "plain" }))).status).toBe(400);
    expect((await exchange("x".repeat(43), { code_verifier: "short" })).status).toBe(400);
  });

  it("binds a code to client and exact redirect URI and consumes it once", async () => {
    const code = await issueCode();
    expect((await exchange(code, { redirect_uri: "https://client.example/other" })).status).toBe(400);
    const replayRace = await Promise.all([exchange(code), exchange(code)]);
    expect(replayRace.map((response) => response.status).sort()).toEqual([200, 400]);
    const issued = replayRace.find((response) => response.status === 200)!;
    expect(issued.status).toBe(200);
    const token = await issued.json<{ access_token: string; expires_in: number; scope: string }>();
    expect(token.access_token).not.toContain("tk_test_api_key");
    expect(token.expires_in).toBe(3600);
    expect(token.scope).toBe("mcp");
    expect((await exchange(code)).status).toBe(400);
  });

  it("rejects incorrect PKCE without consuming the code", async () => {
    const code = await issueCode();
    expect((await exchange(code, { code_verifier: "z".repeat(64) })).status).toBe(400);
    expect((await exchange(code)).status).toBe(200);
  });

  it("enforces token revocation and rejects query-string API keys", async () => {
    const tokenResponse = await exchange(await issueCode());
    const { access_token: token } = await tokenResponse.json<{ access_token: string }>();
    const mcpBody = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" });
    expect((await SELF.fetch("https://worker.test/mcp", { method: "POST", headers: { Authorization: `Bearer ${token}` }, body: mcpBody })).status).toBe(200);
    expect((await SELF.fetch("https://worker.test/mcp?key=tk_test_api_key", { method: "POST", body: mcpBody })).status).toBe(400);

    await SELF.fetch("https://worker.test/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token }),
    });
    expect((await SELF.fetch("https://worker.test/mcp", { method: "POST", headers: { Authorization: `Bearer ${token}` }, body: mcpBody })).status).toBe(401);
    const stub = env.OAUTH_STORE.get(env.OAUTH_STORE.idFromName("oauth"));
    const storedKeys = await runInDurableObject(stub, async (_instance, state) => [...(await state.storage.list()).keys()]);
    expect(storedKeys.some((key) => key.startsWith("token:") || key.includes(":token:"))).toBe(false);
  });

  it("rejects expired codes and access tokens", async () => {
    const stub = env.OAUTH_STORE.get(env.OAUTH_STORE.idFromName("oauth"));
    const expiredCode = "e".repeat(43);
    await stub.fetch("https://oauth.internal/code", {
      method: "POST",
      body: JSON.stringify({ code: expiredCode, apiKey: "tk_expired", clientId, redirectUri, state: "", codeChallenge: await challenge(), scope: "mcp", resource: "https://worker.test/mcp", expiresAt: Date.now() - 1 }),
    });
    expect((await exchange(expiredCode)).status).toBe(400);

    const issued = await exchange(await issueCode());
    const { access_token: token } = await issued.json<{ access_token: string }>();
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 3_601_000);
    expect((await SELF.fetch("https://worker.test/mcp", { method: "POST", headers: { Authorization: `Bearer ${token}` }, body: "{}" })).status).toBe(401);
  });

  it("encrypts API keys at rest and alarm-cleans expired credentials", async () => {
    const stub = env.OAUTH_STORE.get(env.OAUTH_STORE.idFromName("oauth"));
    await exchange(await issueCode());
    const before = await runInDurableObject(stub, async (_instance, state) => JSON.stringify([...(await state.storage.list()).entries()]));
    expect(before).not.toContain("tk_test_api_key");
    expect(before).not.toContain("encryption-key");
    expect(before).toContain("ciphertext");

    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 3_601_000);
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    const remainingKeys = await runInDurableObject(stub, async (_instance, state) => [...(await state.storage.list()).keys()]);
    expect(remainingKeys.some((key) => key.startsWith("token:") || key.startsWith("code:") || key.startsWith("expiry:"))).toBe(false);
  });
});
