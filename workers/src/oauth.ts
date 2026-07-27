import { apiRequestUrl, normalizeTaskboiApiBaseUrl } from "./api-base-url";

const CODE_TTL_SECONDS = 300;
export const TOKEN_TTL_SECONDS = 3600;
const MAX_BODY_BYTES = 16_384;
const MAX_METADATA_BYTES = 16_384;
const MAX_REDIRECT_URIS = 10;
const METADATA_CACHE_SECONDS = 600;
export const DCR_TTL_SECONDS = 30 * 24 * 60 * 60;
export const MAX_DCR_REGISTRATIONS = 100;
const PKCE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;
const PKCE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const OPAQUE_PATTERN = /^[A-Za-z0-9_-]{20,256}$/;
const CLIENT_ID_PATTERN = /^[A-Za-z0-9._~-]{1,128}$/;
const ALLOWED_SCOPE = "mcp";

export interface OAuthClientConfig {
  client_id: string;
  redirect_uris: string[];
  scopes?: string[];
}

export interface OAuthEnv {
  TASKBOI_API_BASE_URL?: string;
  OAUTH_CLIENTS?: string;
  OAUTH_ENCRYPTION_KEY?: string;
  OAUTH_ISSUER?: string;
  OAUTH_CLIENT_METADATA_ALLOWED_ORIGINS?: string;
  OAUTH_STORE: DurableObjectNamespace;
}

interface StoredClient extends OAuthClientConfig { expiresAt?: number }

interface AuthorizationRequest {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  scope: string;
  resource: string;
}

interface CodeRecord extends AuthorizationRequest {
  apiKey: EncryptedValue;
  expiresAt: number;
}

interface TokenRecord {
  apiKey: EncryptedValue;
  clientId: string;
  scope: string;
  resource: string;
  expiresAt: number;
  revoked: boolean;
}

interface EncryptedValue { iv: string; ciphertext: string }

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_ATTEMPTS = 5;
const fallbackRateLimits = new Map<string, { count: number; resetsAt: number }>();

type Parameters = URLSearchParams | FormData;

const securityHeaders: Record<string, string> = {
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store", ...securityHeaders, ...extra },
  });
}

function oauthError(error: string, description: string, status = 400, retryAfter?: string): Response {
  return json({ error, error_description: description }, status, retryAfter ? { "Retry-After": retryAfter } : {});
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function requiredString(value: unknown, max: number): string | null {
  return isString(value) && value.length > 0 && value.length <= max ? value : null;
}

function unique(values: Parameters, name: string): string | null {
  const entries = values.getAll(name);
  return entries.length === 1 && isString(entries[0]) ? entries[0] : null;
}

function parseClients(raw: string | undefined): OAuthClientConfig[] {
  if (!raw) return [];
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error("OAUTH_CLIENTS must be valid JSON"); }
  if (!Array.isArray(parsed) || parsed.length > 50) throw new Error("OAUTH_CLIENTS must be an array of at most 50 clients");
  const clients = parsed.map((item) => {
    if (!item || typeof item !== "object") throw new Error("Invalid OAuth client configuration");
    const value = item as Record<string, unknown>;
    if (typeof value.client_id !== "string" || !CLIENT_ID_PATTERN.test(value.client_id)) throw new Error("Invalid OAuth client_id configuration");
    if (!validRedirectList(value.redirect_uris)) {
      throw new Error(`Invalid redirect URI configuration for ${value.client_id}`);
    }
    const scopes = value.scopes === undefined ? [ALLOWED_SCOPE] : value.scopes;
    if (!Array.isArray(scopes) || scopes.length === 0 || scopes.some((scope) => scope !== ALLOWED_SCOPE)) throw new Error(`Invalid scopes for ${value.client_id}`);
    return { client_id: value.client_id, redirect_uris: value.redirect_uris as string[], scopes: scopes as string[] };
  });
  if (new Set(clients.map((client) => client.client_id)).size !== clients.length) throw new Error("Duplicate OAuth client_id configuration");
  return clients;
}

function decodeEncryptionKey(raw: string | undefined): Uint8Array {
  if (!raw) throw new Error("OAUTH_ENCRYPTION_KEY secret is required");
  if (!/^[A-Za-z0-9+/]{43}=$/.test(raw)) throw new Error("OAUTH_ENCRYPTION_KEY must be canonical base64 encoding of exactly 32 bytes");
  let decoded: Uint8Array;
  try { decoded = Uint8Array.from(atob(raw), (character) => character.charCodeAt(0)); }
  catch { throw new Error("OAUTH_ENCRYPTION_KEY must be valid base64"); }
  if (decoded.byteLength !== 32 || btoa(String.fromCharCode(...decoded)) !== raw) {
    throw new Error("OAUTH_ENCRYPTION_KEY must be canonical base64 encoding of exactly 32 bytes");
  }
  return decoded;
}

export function validateOAuthConfiguration(env: OAuthEnv): void {
  normalizeTaskboiApiBaseUrl(env.TASKBOI_API_BASE_URL);
  parseClients(env.OAUTH_CLIENTS);
  decodeEncryptionKey(env.OAUTH_ENCRYPTION_KEY);
  issuer(env.OAUTH_ISSUER);
  parseMetadataAllowedOrigins(env.OAUTH_CLIENT_METADATA_ALLOWED_ORIGINS);
}

function parseMetadataAllowedOrigins(raw: string | undefined): Set<string> {
  if (!raw) return new Set();
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error("OAUTH_CLIENT_METADATA_ALLOWED_ORIGINS must be valid JSON"); }
  if (!Array.isArray(parsed) || parsed.length > 50) throw new Error("OAUTH_CLIENT_METADATA_ALLOWED_ORIGINS must be an array of at most 50 origins");
  const origins = parsed.map((value) => {
    if (typeof value !== "string") throw new Error("Invalid metadata allowed origin");
    let url: URL;
    try { url = new URL(value); } catch { throw new Error("Invalid metadata allowed origin"); }
    if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash || value !== url.origin || !isExternalMetadataHost(url.hostname)) throw new Error("Metadata allowed origins must be exact public HTTPS origins");
    return url.origin;
  });
  if (new Set(origins).size !== origins.length) throw new Error("Duplicate metadata allowed origin");
  return new Set(origins);
}

function issuer(raw: string | undefined): string {
  if (!raw) throw new Error("OAUTH_ISSUER binding is required");
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error("OAUTH_ISSUER must be an absolute HTTPS origin"); }
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash || raw !== url.origin) {
    throw new Error("OAUTH_ISSUER must be an absolute HTTPS origin without path, query, fragment, or credentials");
  }
  return url.origin;
}

function isSafeRedirect(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 2048 || value.includes("#") || value.includes("*")) return false;
  try {
    const uri = new URL(value);
    return (uri.protocol === "https:" && !!uri.hostname && !uri.username && !uri.password) ||
      (uri.protocol === "http:" && (uri.hostname === "127.0.0.1" || uri.hostname === "localhost") && !uri.username && !uri.password);
  } catch { return false; }
}

function validRedirectList(value: unknown): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.length <= MAX_REDIRECT_URIS &&
    new Set(value).size === value.length && value.every(isSafeRedirect);
}

function isExternalMetadataHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) return false;
  return host.includes(".");
}

function parseClientMetadata(value: unknown, expectedId?: string, requireMetadataDocumentProfile = false): OAuthClientConfig | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const data = value as Record<string, unknown>;
  const clientId = expectedId ?? (typeof data.client_id === "string" && OPAQUE_PATTERN.test(data.client_id) ? data.client_id : null);
  if (!clientId || (expectedId && data.client_id !== expectedId) || (requireMetadataDocumentProfile && !requiredString(data.client_name, 256)) ||
      (data.client_name !== undefined && !requiredString(data.client_name, 256)) || !validRedirectList(data.redirect_uris)) return null;
  if (data.token_endpoint_auth_method !== undefined && data.token_endpoint_auth_method !== "none") return null;
  const exactArray = (name: string, allowed: string) =>
    Array.isArray(data[name]) && data[name]!.length === 1 && data[name]![0] === allowed;
  const grantTypes = data.grant_types;
  const validGrantTypes = Array.isArray(grantTypes) && (grantTypes.length === 1 || grantTypes.length === 2) &&
    grantTypes.includes("authorization_code") && grantTypes.every((grant) => grant === "authorization_code" || grant === "refresh_token") &&
    new Set(grantTypes).size === grantTypes.length;
  if (!validGrantTypes || !exactArray("response_types", "code") ||
      (requireMetadataDocumentProfile && !exactArray("code_challenge_methods_supported", "S256"))) return null;
  if (data.scope !== undefined && data.scope !== ALLOWED_SCOPE) return null;
  return { client_id: clientId, redirect_uris: data.redirect_uris as string[], scopes: [ALLOWED_SCOPE] };
}

async function storedClient(env: OAuthEnv, clientId: string): Promise<OAuthClientConfig | null> {
  const response = await store(env).fetch("https://oauth.internal/client", { method: "POST", body: clientId });
  return response.ok ? response.json() as Promise<OAuthClientConfig> : null;
}

function metadataClientUrl(env: OAuthEnv, clientId: string): URL | null {
  let url: URL;
  try { url = new URL(clientId); } catch { return null; }
  const rawPath = clientId.match(/^https:\/\/[^/?#]+([^?#]*)/)?.[1] ?? "";
  const rawSegments = rawPath.split("/").filter(Boolean);
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname === "/" ||
      url.toString() !== clientId || rawSegments.length === 0 ||
      rawSegments.some((segment) => /^(?:\.|%2e){1,2}$/i.test(segment)) || !isExternalMetadataHost(url.hostname) ||
      !parseMetadataAllowedOrigins(env.OAUTH_CLIENT_METADATA_ALLOWED_ORIGINS).has(url.origin)) return null;
  return url;
}

async function fetchMetadataClient(env: OAuthEnv, clientId: string): Promise<OAuthClientConfig | null> {
  // Re-evaluate the complete URL policy and the current allowlist before cache
  // access so removing an origin revokes cached metadata immediately.
  const url = metadataClientUrl(env, clientId);
  if (!url) return null;
  const cached = await storedClient(env, clientId);
  if (cached) return cached;
  try {
    const response = await fetch(url.toString(), {
      redirect: "manual",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok || response.status >= 300 || response.headers.get("content-type")?.split(";", 1)[0].trim() !== "application/json") return null;
    const declared = Number(response.headers.get("content-length") || "0");
    if (declared > MAX_METADATA_BYTES) return null;
    const reader = response.body?.getReader();
    if (!reader) return null;
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_METADATA_BYTES) { await reader.cancel(); return null; }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const client = parseClientMetadata(JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes)), clientId, true);
    if (!client) return null;
    await store(env).fetch("https://oauth.internal/client-cache", { method: "POST", body: JSON.stringify({ ...client, expiresAt: Date.now() + METADATA_CACHE_SECONDS * 1000 }) });
    return client;
  } catch { return null; }
}

async function resolveClient(env: OAuthEnv, clientId: string, redirectUri: string): Promise<OAuthClientConfig | null> {
  const staticClient = parseClients(env.OAUTH_CLIENTS).find((entry) => entry.client_id === clientId);
  const client = staticClient ?? (clientId.startsWith("https://") ? await fetchMetadataClient(env, clientId) : await storedClient(env, clientId));
  return client?.redirect_uris.includes(redirectUri) ? client : null;
}

async function parseAuthorization(values: Parameters, env: OAuthEnv): Promise<AuthorizationRequest | Response> {
  const clientId = requiredString(unique(values, "client_id"), 2048);
  const redirectUri = requiredString(unique(values, "redirect_uri"), 2048);
  const responseType = requiredString(unique(values, "response_type"), 32);
  const stateEntries = values.getAll("state");
  const stateValue = stateEntries.length === 0 ? null : stateEntries.length === 1 ? stateEntries[0] : undefined;
  const state = stateValue === null ? "" : requiredString(stateValue, 512);
  const codeChallenge = requiredString(unique(values, "code_challenge"), 128);
  const method = requiredString(unique(values, "code_challenge_method"), 16);
  const scopeEntries = values.getAll("scope");
  const scopeValue = scopeEntries.length === 0 ? null : scopeEntries.length === 1 ? scopeEntries[0] : undefined;
  const scope = scopeValue === null ? ALLOWED_SCOPE : requiredString(scopeValue, 64);
  const resource = requiredString(unique(values, "resource"), 2048);
  if (!clientId || !redirectUri || !await resolveClient(env, clientId, redirectUri)) return oauthError("invalid_request", "Unknown client or redirect_uri", 400);
  if (responseType !== "code") return oauthError("unsupported_response_type", "response_type must be code");
  if (state === null) return oauthError("invalid_request", "state is too long");
  if (!codeChallenge || !PKCE_CHALLENGE_PATTERN.test(codeChallenge) || method !== "S256") return oauthError("invalid_request", "S256 PKCE is required");
  if (scope !== ALLOWED_SCOPE) return oauthError("invalid_scope", "Only the mcp scope is supported");
  if (resource !== `${issuer(env.OAUTH_ISSUER)}/mcp`) return oauthError("invalid_target", "Exactly one resource matching this MCP server is required");
  return { clientId, redirectUri, state, codeChallenge, scope, resource };
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]!);
}

function authPage(auth: AuthorizationRequest, error?: string): Response {
  const destination = new URL(auth.redirectUri);
  const authorizationPageHeaders = {
    ...securityHeaders,
    "Content-Security-Policy": securityHeaders["Content-Security-Policy"].replace(
      "form-action 'self'",
      `form-action 'self' ${destination.origin}`,
    ),
  };
  const hidden = (name: string, value: string) => `<input type="hidden" name="${name}" value="${escapeHtml(value)}">`;
  const body = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect Taskboi</title><style>body{font-family:system-ui,sans-serif;background:#f6f7f9;margin:0;min-height:100vh;display:grid;place-items:center}.card{background:#fff;border:1px solid #ddd;border-radius:12px;padding:2rem;width:min(30rem,calc(100% - 3rem));box-shadow:0 8px 30px #0002}h1{margin-top:0}.error,.warning{padding:.75rem;border-radius:6px}.error{color:#8b0000;background:#fee}.warning{color:#663c00;background:#fff4d6}dl{display:grid;grid-template-columns:8rem 1fr;gap:.5rem}dt{font-weight:700}dd{margin:0;overflow-wrap:anywhere}label{display:block;font-weight:600;margin:1.25rem 0 .4rem}input[type=password]{box-sizing:border-box;width:100%;padding:.8rem}button{width:100%;margin-top:1rem;padding:.8rem;background:#b7352b;color:#fff;border:0;border-radius:6px;font-weight:700}</style></head><body><main class="card"><h1>Connect Taskboi</h1><p>Review this authorization request before continuing.</p><dl><dt>Client ID</dt><dd>${escapeHtml(auth.clientId)}</dd><dt>Redirect origin</dt><dd>${escapeHtml(destination.origin)}</dd><dt>Redirect destination</dt><dd>${escapeHtml(auth.redirectUri)}</dd><dt>Requested scope</dt><dd>${escapeHtml(auth.scope)}</dd></dl><p class="warning"><strong>Capability warning:</strong> This client will be able to read, create, update, complete, and delete your Taskboi projects and tasks as you.</p>${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}<form action="/authorize/submit" method="post">${hidden("client_id", auth.clientId)}${hidden("redirect_uri", auth.redirectUri)}${hidden("state", auth.state)}${hidden("response_type", "code")}${hidden("code_challenge", auth.codeChallenge)}${hidden("code_challenge_method", "S256")}${hidden("scope", auth.scope)}<label for="api_key">Taskboi API key</label><input type="password" id="api_key" name="api_key" minlength="8" maxlength="512" autocomplete="off" required><button type="submit">Authorize access</button></form></main></body></html>`;
  return new Response(body.replace(hidden("scope", auth.scope), `${hidden("scope", auth.scope)}${hidden("resource", auth.resource)}`), { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...authorizationPageHeaders } });
}

function store(env: OAuthEnv): DurableObjectStub {
  return env.OAUTH_STORE.get(env.OAUTH_STORE.idFromName("oauth"));
}

async function submissionRateLimit(request: Request, env: OAuthEnv, clientId: string): Promise<Response | null> {
  const connectingIp = request.headers.get("CF-Connecting-IP")?.trim();
  if (connectingIp && connectingIp.length <= 64) {
    const identity = await sha256(connectingIp);
    const response = await env.OAUTH_STORE.get(env.OAUTH_STORE.idFromName(`authorize-rate:${identity}`)).fetch("https://oauth.internal/rate-limit", { method: "POST" });
    if (response.status !== 429) return null;
    return oauthError("slow_down", "Too many authorization attempts. Please try again later.", 429, response.headers.get("Retry-After") || "60");
  }

  // Local fallback avoids turning one missing edge header into a global client outage.
  const fingerprint = `${clientId}:${request.headers.get("User-Agent") || "unknown"}`.slice(0, 256);
  const now = Date.now();
  const entry = fallbackRateLimits.get(fingerprint);
  if (!entry || entry.resetsAt <= now) {
    if (!entry && fallbackRateLimits.size >= 1_000) fallbackRateLimits.delete(fallbackRateLimits.keys().next().value!);
    fallbackRateLimits.set(fingerprint, { count: 1, resetsAt: now + RATE_LIMIT_WINDOW_MS });
  }
  else if (++entry.count > RATE_LIMIT_ATTEMPTS) return oauthError("slow_down", "Too many authorization attempts. Please try again later.", 429, String(Math.max(1, Math.ceil((entry.resetsAt - now) / 1000))));
  if (fallbackRateLimits.size > 1_000) for (const [key, value] of fallbackRateLimits) if (value.resetsAt <= now) fallbackRateLimits.delete(key);
  return null;
}

async function readForm(request: Request): Promise<URLSearchParams | Response> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > MAX_BODY_BYTES) return oauthError("invalid_request", "Request body is too large", 413);
  const type = request.headers.get("content-type")?.split(";", 1)[0].trim();
  if (type !== "application/x-www-form-urlencoded") return oauthError("invalid_request", "application/x-www-form-urlencoded is required", 415);
  if (!request.body) return new URLSearchParams();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel();
        return oauthError("invalid_request", "Request body is too large", 413);
      }
      chunks.push(value);
    }
    const body = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
    return new URLSearchParams(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body));
  } catch { return oauthError("invalid_request", "Malformed request body"); }
}

async function readJson(request: Request): Promise<unknown | Response> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > MAX_BODY_BYTES) return oauthError("invalid_client_metadata", "Request body is too large", 413);
  if (request.headers.get("content-type")?.split(";", 1)[0].trim() !== "application/json") return oauthError("invalid_client_metadata", "application/json is required", 415);
  try {
    const text = await request.text();
    if (new TextEncoder().encode(text).byteLength > MAX_BODY_BYTES) return oauthError("invalid_client_metadata", "Request body is too large", 413);
    return JSON.parse(text);
  } catch { return oauthError("invalid_client_metadata", "Malformed client metadata"); }
}

async function registrationRateLimit(request: Request, env: OAuthEnv): Promise<Response | null> {
  const identity = request.headers.get("CF-Connecting-IP")?.trim() || `fallback:${request.headers.get("User-Agent") || "unknown"}`;
  const response = await env.OAUTH_STORE.get(env.OAUTH_STORE.idFromName(`register-rate:${await sha256(identity.slice(0, 64))}`))
    .fetch("https://oauth.internal/rate-limit", { method: "POST" });
  return response.status === 429 ? oauthError("slow_down", "Too many registration attempts. Please try again later.", 429, response.headers.get("Retry-After") || "60") : null;
}

export async function handleOAuth(request: Request, env: OAuthEnv): Promise<Response | null> {
  const url = new URL(request.url);
  const base = issuer(env.OAUTH_ISSUER);
  if ((url.pathname === "/.well-known/oauth-protected-resource" || url.pathname === "/.well-known/oauth-protected-resource/mcp") && request.method === "GET") {
    return json({ resource: `${base}/mcp`, authorization_servers: [base], scopes_supported: [ALLOWED_SCOPE] }, 200, { "Cache-Control": "public, max-age=3600" });
  }
  if (url.pathname === "/.well-known/oauth-authorization-server" && request.method === "GET") {
    return json({ issuer: base, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, registration_endpoint: `${base}/register`, response_types_supported: ["code"], grant_types_supported: ["authorization_code"], code_challenge_methods_supported: ["S256"], scopes_supported: [ALLOWED_SCOPE], token_endpoint_auth_methods_supported: ["none"], client_id_metadata_document_supported: true }, 200, { "Cache-Control": "public, max-age=3600" });
  }
  if (url.pathname === "/register" && request.method === "POST") {
    const limited = await registrationRateLimit(request, env); if (limited) return limited;
    const body = await readJson(request); if (body instanceof Response) return body;
    if (!body || typeof body !== "object" || Array.isArray(body)) return oauthError("invalid_client_metadata", "Invalid public client metadata");
    const data = body as Record<string, unknown>;
    if (data.client_secret !== undefined || (data.token_endpoint_auth_method !== undefined && data.token_endpoint_auth_method !== "none")) return oauthError("invalid_client_metadata", "Only public clients are supported");
    const clientId = randomToken(32);
    const client = parseClientMetadata({ ...data, client_id: clientId });
    if (!client) return oauthError("invalid_client_metadata", "A public authorization-code client with safe redirect_uris is required");
    const issuedAt = Math.floor(Date.now() / 1000);
    const expiresAt = Date.now() + DCR_TTL_SECONDS * 1000;
    const saved = await store(env).fetch("https://oauth.internal/register", { method: "POST", body: JSON.stringify({ ...client, expiresAt }) });
    if (saved.status === 429) return oauthError("server_error", "Client registration capacity is temporarily exhausted", 503);
    if (!saved.ok) return oauthError("server_error", "Client registration failed", 500);
    return json({ client_id: client.client_id, client_id_issued_at: issuedAt, registration_expires_at: Math.floor(expiresAt / 1000), ...(data.client_name === undefined ? {} : { client_name: data.client_name }), redirect_uris: client.redirect_uris, token_endpoint_auth_method: "none", grant_types: ["authorization_code"], response_types: ["code"], scope: ALLOWED_SCOPE }, 201);
  }
  if (url.pathname === "/authorize" && request.method === "GET") {
    const parsed = await parseAuthorization(url.searchParams, env);
    return parsed instanceof Response ? parsed : authPage(parsed);
  }
  if (url.pathname === "/authorize/submit" && request.method === "POST") {
    const form = await readForm(request);
    if (form instanceof Response) return form;
    const parsed = await parseAuthorization(form, env);
    if (parsed instanceof Response) return parsed;
    const limited = await submissionRateLimit(request, env, parsed.clientId);
    if (limited) return limited;
    const apiKey = requiredString(unique(form, "api_key"), 512);
    if (!apiKey || apiKey.length < 8) return authPage(parsed, "Invalid API key.");
    try {
      const validation = await fetch(apiRequestUrl(normalizeTaskboiApiBaseUrl(env.TASKBOI_API_BASE_URL), "/projects"), { headers: { Authorization: `Bearer ${apiKey}` } });
      if (!validation.ok) return authPage(parsed, "Invalid API key. Please check and try again.");
    } catch { return authPage(parsed, "API key validation is temporarily unavailable."); }
    const code = randomToken(32);
    const response = await store(env).fetch("https://oauth.internal/code", { method: "POST", body: JSON.stringify({ ...parsed, apiKey, code, expiresAt: Date.now() + CODE_TTL_SECONDS * 1000 }) });
    if (!response.ok) return oauthError("server_error", "Could not issue authorization code", 500);
    const redirect = new URL(parsed.redirectUri);
    redirect.searchParams.set("code", code);
    if (parsed.state) redirect.searchParams.set("state", parsed.state);
    return new Response(null, { status: 302, headers: { Location: redirect.toString(), "Cache-Control": "no-store", ...securityHeaders } });
  }
  if (url.pathname === "/token" && request.method === "POST") {
    const form = await readForm(request);
    if (form instanceof Response) return form;
    const grantType = requiredString(unique(form, "grant_type"), 32);
    const code = requiredString(unique(form, "code"), 256);
    const verifier = requiredString(unique(form, "code_verifier"), 128);
    const clientId = requiredString(unique(form, "client_id"), 2048);
    const redirectUri = requiredString(unique(form, "redirect_uri"), 2048);
    const resource = requiredString(unique(form, "resource"), 2048);
    if (grantType !== "authorization_code") return oauthError("unsupported_grant_type", "Only authorization_code is supported");
    if (!code || !OPAQUE_PATTERN.test(code) || !verifier || !PKCE_VERIFIER_PATTERN.test(verifier) || !clientId || !redirectUri || resource !== `${base}/mcp`) return oauthError("invalid_grant", "Invalid authorization code request");
    const result = await store(env).fetch("https://oauth.internal/exchange", { method: "POST", body: JSON.stringify({ code, verifier, clientId, redirectUri, resource }) });
    if (!result.ok) return oauthError("invalid_grant", "Code expired, already used, mismatched, or PKCE verification failed");
    return json(await result.json());
  }
  if (url.pathname === "/revoke" && request.method === "POST") {
    const form = await readForm(request);
    if (form instanceof Response) return form;
    const token = requiredString(unique(form, "token"), 256);
    if (token && OPAQUE_PATTERN.test(token)) await store(env).fetch("https://oauth.internal/revoke", { method: "POST", body: token });
    return new Response(null, { status: 200, headers: { "Cache-Control": "no-store", ...securityHeaders } });
  }
  return null;
}

export async function resolveAccessToken(env: OAuthEnv, token: string): Promise<{ apiKey: string; scope: string; resource: string } | null> {
  if (!OPAQUE_PATTERN.test(token)) return null;
  const response = await store(env).fetch("https://oauth.internal/introspect", { method: "POST", body: token });
  const result = response.ok ? await response.json() as { apiKey: string; scope: string; resource: string } : null;
  return result?.resource === `${issuer(env.OAUTH_ISSUER)}/mcp` ? result : null;
}

function randomToken(bytes: number): string {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return base64Url(data);
}

function base64Url(data: Uint8Array): string {
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(value: string): Promise<string> {
  return base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}

export class OAuthStore implements DurableObject {
  constructor(private readonly state: DurableObjectState, private readonly env: OAuthEnv) {}

  private expiryKey(expiresAt: number, recordKey: string): string {
    return `expiry:${String(expiresAt).padStart(13, "0")}:${recordKey}`;
  }

  private async encryptionKey(): Promise<CryptoKey> {
    return crypto.subtle.importKey("raw", decodeEncryptionKey(this.env.OAUTH_ENCRYPTION_KEY), "AES-GCM", false, ["encrypt", "decrypt"]);
  }

  private async encrypt(value: string): Promise<EncryptedValue> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await this.encryptionKey(), new TextEncoder().encode(value));
    return { iv: base64Url(iv), ciphertext: base64Url(new Uint8Array(ciphertext)) };
  }

  private async decrypt(value: EncryptedValue): Promise<string> {
    const decode = (input: string) => Uint8Array.from(atob(input.replace(/-/g, "+").replace(/_/g, "/")), (character) => character.charCodeAt(0));
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: decode(value.iv) }, await this.encryptionKey(), decode(value.ciphertext));
    return new TextDecoder().decode(plaintext);
  }

  private async scheduleCleanup(): Promise<void> {
    const next = await this.state.storage.list<string>({ prefix: "expiry:", limit: 1 });
    const first = next.keys().next().value as string | undefined;
    if (first) await this.state.storage.setAlarm(Math.max(Date.now(), Number(first.slice(7, 20))));
    else await this.state.storage.deleteAlarm();
  }

  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (request.method !== "POST") return new Response(null, { status: 405 });
    if (path === "/code") {
      const record = await request.json<CodeRecord & { code: string }>();
      const recordKey = `code:${await sha256(record.code)}`;
      const stored: CodeRecord = { ...record, apiKey: await this.encrypt(record.apiKey as unknown as string) };
      await this.state.storage.put({ [recordKey]: stored, [this.expiryKey(record.expiresAt, recordKey)]: recordKey });
      await this.scheduleCleanup();
      return new Response(null, { status: 204 });
    }
    if (path === "/exchange") {
      const input = await request.json<{ code: string; verifier: string; clientId: string; redirectUri: string; resource: string }>();
      const codeKey = `code:${await sha256(input.code)}`;
      const verifierHash = await sha256(input.verifier);
      const issued = await this.state.storage.transaction(async (txn) => {
        const code = await txn.get<CodeRecord>(codeKey);
        if (!code) return null;
        if (code.expiresAt <= Date.now()) {
          await txn.delete([codeKey, this.expiryKey(code.expiresAt, codeKey)]);
          return null;
        }
        if (code.clientId !== input.clientId || code.redirectUri !== input.redirectUri || code.resource !== input.resource || code.codeChallenge !== verifierHash) return null;
        await txn.delete([codeKey, this.expiryKey(code.expiresAt, codeKey)]);
        const rawToken = randomToken(32);
        const tokenKey = `token:${await sha256(rawToken)}`;
        const token: TokenRecord = { apiKey: code.apiKey, clientId: code.clientId, scope: code.scope, resource: code.resource, expiresAt: Date.now() + TOKEN_TTL_SECONDS * 1000, revoked: false };
        await txn.put({ [tokenKey]: token, [this.expiryKey(token.expiresAt, tokenKey)]: tokenKey });
        return { access_token: rawToken, token_type: "Bearer", expires_in: TOKEN_TTL_SECONDS, scope: token.scope };
      });
      await this.scheduleCleanup();
      return issued ? json(issued) : new Response(null, { status: 400 });
    }
    if (path === "/introspect") {
      const key = `token:${await sha256(await request.text())}`;
      const token = await this.state.storage.get<TokenRecord>(key);
      if (!token || token.revoked || !token.scope.split(" ").includes(ALLOWED_SCOPE)) return new Response(null, { status: 401 });
      if (token.expiresAt <= Date.now()) {
        await this.state.storage.delete([key, this.expiryKey(token.expiresAt, key)]);
        await this.scheduleCleanup();
        return new Response(null, { status: 401 });
      }
      return json({ apiKey: await this.decrypt(token.apiKey), scope: token.scope, resource: token.resource });
    }
    if (path === "/revoke") {
      const key = `token:${await sha256(await request.text())}`;
      await this.state.storage.transaction(async (txn) => {
        const token = await txn.get<TokenRecord>(key);
        if (token) await txn.delete([key, this.expiryKey(token.expiresAt, key)]);
      });
      await this.scheduleCleanup();
      return new Response(null, { status: 204 });
    }
    if (path === "/rate-limit") {
      const now = Date.now();
      const bucket = await this.state.storage.get<{ count: number; resetsAt: number }>("rate");
      const current = !bucket || bucket.resetsAt <= now ? { count: 1, resetsAt: now + RATE_LIMIT_WINDOW_MS } : { ...bucket, count: bucket.count + 1 };
      await this.state.storage.put("rate", current);
      await this.state.storage.setAlarm(current.resetsAt);
      if (current.count > RATE_LIMIT_ATTEMPTS) return new Response(null, { status: 429, headers: { "Retry-After": String(Math.max(1, Math.ceil((current.resetsAt - now) / 1000))) } });
      return new Response(null, { status: 204 });
    }
    if (path === "/register") {
      const client = await request.json<StoredClient>();
      const key = `dcr:${await sha256(client.client_id)}`;
      const saved = await this.state.storage.transaction(async (txn) => {
        const count = await txn.get<number>("dcr:count") ?? 0;
        if (count >= MAX_DCR_REGISTRATIONS) return false;
        await txn.put({ [key]: client, [this.expiryKey(client.expiresAt!, key)]: key, "dcr:count": count + 1 });
        return true;
      });
      if (!saved) return new Response(null, { status: 429 });
      await this.scheduleCleanup();
      return new Response(null, { status: 204 });
    }
    if (path === "/client-cache") {
      const client = await request.json<StoredClient>();
      const key = `metadata:${await sha256(client.client_id)}`;
      await this.state.storage.put({ [key]: client, [this.expiryKey(client.expiresAt!, key)]: key });
      await this.scheduleCleanup();
      return new Response(null, { status: 204 });
    }
    if (path === "/client") {
      const hash = await sha256(await request.text());
      const client = await this.state.storage.get<StoredClient>([`dcr:${hash}`, `metadata:${hash}`]).then((values) => values.get(`dcr:${hash}`) ?? values.get(`metadata:${hash}`));
      if (!client || (client.expiresAt !== undefined && client.expiresAt <= Date.now())) return new Response(null, { status: 404 });
      return json({ client_id: client.client_id, redirect_uris: client.redirect_uris, scopes: client.scopes });
    }
    return new Response(null, { status: 404 });
  }

  async alarm(): Promise<void> {
    const rate = await this.state.storage.get<{ resetsAt: number }>("rate");
    if (rate && rate.resetsAt <= Date.now()) await this.state.storage.delete("rate");
    const end = `expiry:${String(Date.now()).padStart(13, "0")}:\uffff`;
    const due = await this.state.storage.list<string>({ prefix: "expiry:", end });
    const keys: string[] = [];
    let expiredDcr = 0;
    for (const [expiryKey, recordKey] of due) { keys.push(expiryKey, recordKey); if (recordKey.startsWith("dcr:")) expiredDcr++; }
    if (keys.length) await this.state.storage.transaction(async (txn) => {
      await txn.delete(keys);
      if (expiredDcr) await txn.put("dcr:count", Math.max(0, (await txn.get<number>("dcr:count") ?? 0) - expiredDcr));
    });
    await this.scheduleCleanup();
  }
}
