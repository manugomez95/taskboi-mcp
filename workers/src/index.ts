// Taskboi MCP Worker - Remote MCP server with OAuth 2.0 Authorization Code + PKCE

import {
  handleTaskboiMcpRequest,
  HANDSHAKE_PROTOCOL_VERSION,
  LEGACY_PROTOCOL_VERSION,
  MODERN_PROTOCOL_VERSION,
  SUPPORTED_PROTOCOL_VERSIONS,
  type SupportedProtocolVersion,
  type TaskboiOperations,
} from "./protocol";
import { TaskboiApiClient } from "./api-client";
import {
  handleOAuth,
  OAuthStore,
  resolveAccessToken,
  parseMcpAllowedOrigins,
  validateOAuthConfiguration,
  type OAuthEnv,
} from "./oauth";

export { OAuthStore };

interface Env extends OAuthEnv {}

export interface WorkerDependencies {
  validateConfiguration(env: Env): void;
  handleOAuth(request: Request, env: Env): Promise<Response | null>;
  authorize(env: Env, token: string): Promise<{ apiKey: string } | null>;
  operations(apiKey: string, env: Env): TaskboiOperations;
}

const defaultDependencies: WorkerDependencies = {
  validateConfiguration: validateOAuthConfiguration,
  handleOAuth,
  authorize: resolveAccessToken,
  operations: (apiKey, env) =>
    new TaskboiApiClient(apiKey, env.TASKBOI_API_BASE_URL!),
};

const responseHeaders = {
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers":
    "Content-Type, Authorization, MCP-Protocol-Version, Mcp-Method, Mcp-Name",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

function headersFor(origin?: string): Record<string, string> {
  return origin
    ? { ...responseHeaders, "Access-Control-Allow-Origin": origin, Vary: "Origin" }
    : responseHeaders;
}

export function createWorker(dependencies: WorkerDependencies = defaultDependencies) {
  return {
    async fetch(request: Request, env: Env): Promise<Response> {
      const url = new URL(request.url);
      const origin = request.headers.get("Origin");
      let allowedOrigin: string | undefined;

      try {
        dependencies.validateConfiguration(env);
      } catch (error) {
        console.error(
          "OAuth configuration error",
          error instanceof Error ? error.message : "unknown",
        );
        return Response.json(
          { error: "server_error" },
          { status: 500, headers: responseHeaders },
        );
      }

      if (url.pathname === "/mcp" && origin !== null) {
        let configuredOrigins: Set<string>;
        try {
          configuredOrigins = parseMcpAllowedOrigins(env.MCP_ALLOWED_ORIGINS);
          if (env.OAUTH_ISSUER) configuredOrigins.add(new URL(env.OAUTH_ISSUER).origin);
        } catch {
          return Response.json(
            { jsonrpc: "2.0", error: { code: -32000, message: "Invalid Origin" } },
            { status: 403, headers: responseHeaders },
          );
        }
        if (!configuredOrigins.has(origin)) {
          return Response.json(
            { jsonrpc: "2.0", error: { code: -32000, message: "Invalid Origin" } },
            { status: 403, headers: responseHeaders },
          );
        }
        allowedOrigin = origin;
      }
      const corsHeaders = headersFor(allowedOrigin);

      if (request.method === "OPTIONS") {
        return new Response(null, { headers: corsHeaders });
      }

      let oauthResponse: Response | null;
      try {
        oauthResponse = await dependencies.handleOAuth(request, env);
      } catch (error) {
        console.error(
          "OAuth configuration or storage error",
          error instanceof Error ? error.message : "unknown",
        );
        return Response.json(
          { error: "server_error" },
          { status: 500, headers: corsHeaders },
        );
      }
      if (oauthResponse) return oauthResponse;

      if (url.pathname === "/" || url.pathname === "/health") {
        return Response.json(
          { status: "ok", name: "Taskboi MCP Server", version: "1.0.0" },
          { headers: corsHeaders },
        );
      }

      if (url.pathname === "/mcp" && request.method === "POST") {
        if (url.searchParams.has("key")) {
          return Response.json(
            {
              jsonrpc: "2.0",
              error: {
                code: -32600,
                message: "API keys are not accepted in query strings",
              },
            },
            { status: 400, headers: corsHeaders },
          );
        }

        const authHeader = request.headers.get("Authorization");
        const match = authHeader?.match(/^Bearer ([A-Za-z0-9_-]+)$/);
        const authorization = match
          ? await dependencies.authorize(env, match[1])
          : null;
        if (!authorization) {
          const resourceMetadata =
            `${env.OAUTH_ISSUER}/.well-known/oauth-protected-resource/mcp`;
          return Response.json(
            {
              jsonrpc: "2.0",
              error: { code: -32000, message: "Unauthorized" },
            },
            {
              status: 401,
              headers: {
                ...corsHeaders,
                "WWW-Authenticate":
                  `Bearer resource_metadata="${resourceMetadata}", scope="mcp"`,
              },
            },
          );
        }

        try {
          const body: unknown = await request.json();
          const protocolVersion = request.headers.get("MCP-Protocol-Version");
          const value = body && typeof body === "object"
            ? body as {
              id?: number | string;
              method?: unknown;
              params?: { name?: unknown; uri?: unknown; _meta?: Record<string, unknown> };
            }
            : {};
          const error = (
            code: number,
            message: string,
            status = 400,
            data?: Record<string, unknown>,
          ) =>
            Response.json(
              {
                jsonrpc: "2.0",
                ...(value.id !== undefined ? { id: value.id } : {}),
                error: { code, message, ...(data ? { data } : {}) },
              },
              { status, headers: corsHeaders },
            );

          if (protocolVersion === HANDSHAKE_PROTOCOL_VERSION ||
              protocolVersion === LEGACY_PROTOCOL_VERSION) {
            const response = await handleTaskboiMcpRequest(
              body,
              dependencies.operations(authorization.apiKey, env),
              protocolVersion as SupportedProtocolVersion,
            );
            if (response === null) {
              return new Response(null, { status: 202, headers: corsHeaders });
            }
            return Response.json(response, { headers: corsHeaders });
          }

          if (protocolVersion !== MODERN_PROTOCOL_VERSION) {
            if (protocolVersion === null) {
              return error(-32020, "Header mismatch: MCP-Protocol-Version header is required");
            }
            return error(
              -32022,
              "Unsupported protocol version",
              400,
              {
                supported: [...SUPPORTED_PROTOCOL_VERSIONS],
                requested: protocolVersion,
              },
            );
          }

          const bodyVersion =
            value.params?._meta?.["io.modelcontextprotocol/protocolVersion"];
          if (bodyVersion !== MODERN_PROTOCOL_VERSION) {
            return error(
              -32020,
              "Header mismatch: MCP-Protocol-Version header does not match request _meta",
            );
          }
          if (typeof value.method !== "string") {
            return error(-32020, "Header mismatch: request method is missing");
          }
          const methodHeader = request.headers.get("Mcp-Method");
          if (methodHeader !== value.method) {
            return error(
              -32020,
              methodHeader === null
                ? "Header mismatch: Mcp-Method header is required"
                : "Header mismatch: Mcp-Method header does not match request method",
            );
          }

          const nameSource = value.method === "resources/read"
            ? value.params?.uri
            : ["tools/call", "prompts/get"].includes(value.method)
              ? value.params?.name
              : undefined;
          if (nameSource !== undefined) {
            const nameHeader = request.headers.get("Mcp-Name");
            if (nameHeader === null) {
              return error(-32020, "Header mismatch: Mcp-Name header is required");
            }
            let decodedName = nameHeader;
            if (nameHeader.startsWith("=?base64?") && nameHeader.endsWith("?=")) {
              try {
                const encoded = nameHeader.slice(9, -2);
                const bytes = Uint8Array.from(atob(encoded), (character) =>
                  character.charCodeAt(0));
                decodedName = new TextDecoder("utf-8", {
                  fatal: true,
                  ignoreBOM: false,
                }).decode(bytes);
              } catch {
                return error(-32020, "Header mismatch: Mcp-Name header is malformed");
              }
            }
            if (typeof nameSource !== "string" || decodedName !== nameSource) {
              return error(
                -32020,
                "Header mismatch: Mcp-Name header does not match request name",
              );
            }
          } else if (request.headers.has("Mcp-Name")) {
            return error(
              -32020,
              "Header mismatch: Mcp-Name header has no corresponding request name",
            );
          }

          const response = await handleTaskboiMcpRequest(
            body,
            dependencies.operations(authorization.apiKey, env),
            MODERN_PROTOCOL_VERSION,
          );
          if (response === null) {
            return new Response(null, { status: 202, headers: corsHeaders });
          }
          const status = response.error?.code === -32601 ? 404 : 200;
          return Response.json(response, { status, headers: corsHeaders });
        } catch {
          return Response.json(
            {
              jsonrpc: "2.0",
              error: { code: -32700, message: "Parse error" },
            },
            { status: 400, headers: corsHeaders },
          );
        }
      }

      return Response.json(
        { error: "Not found" },
        { status: 404, headers: corsHeaders },
      );
    },
  };
}

export default createWorker();
