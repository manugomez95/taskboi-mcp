// Taskboi MCP Worker - Remote MCP server with OAuth 2.0 Authorization Code + PKCE

import {
  handleTaskboiMcpRequest,
  type TaskboiOperations,
} from "./protocol";
import { TaskboiApiClient } from "./api-client";
import {
  handleOAuth,
  OAuthStore,
  resolveAccessToken,
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

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

export function createWorker(dependencies: WorkerDependencies = defaultDependencies) {
  return {
    async fetch(request: Request, env: Env): Promise<Response> {
      const url = new URL(request.url);

      try {
        dependencies.validateConfiguration(env);
      } catch (error) {
        console.error(
          "OAuth configuration error",
          error instanceof Error ? error.message : "unknown",
        );
        return Response.json(
          { error: "server_error" },
          { status: 500, headers: corsHeaders },
        );
      }

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
          const response = await handleTaskboiMcpRequest(
            body,
            dependencies.operations(authorization.apiKey, env),
          );
          if (response === null) {
            return new Response(null, { status: 202, headers: corsHeaders });
          }
          return Response.json(response, { headers: corsHeaders });
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
