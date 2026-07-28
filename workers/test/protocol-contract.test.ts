import { describe, expect, it } from "vitest";
import { createWorker, type WorkerDependencies } from "../src/index";
import {
  HANDSHAKE_PROTOCOL_VERSION,
  LEGACY_PROTOCOL_VERSION,
  MODERN_PROTOCOL_VERSION,
  SUPPORTED_PROTOCOL_VERSIONS,
  type TaskboiOperations,
} from "../src/protocol";

const projectId = "11111111-1111-4111-8111-111111111111";
const project = { id: projectId, name: "Inbox" };

function fakeOperations(): TaskboiOperations {
  return new Proxy({
    async listProjects() {
      return [project];
    },
    async getProject() {
      throw new Error("project unavailable");
    },
  }, {
    get(target, property) {
      if (property in target) return target[property as keyof typeof target];
      return async () => {
        throw new Error(`unexpected operation: ${String(property)}`);
      };
    },
  }) as TaskboiOperations;
}

const dependencies: WorkerDependencies = {
  validateConfiguration() {},
  async handleOAuth() { return null; },
  async authorize() { return { apiKey: "unused" }; },
  operations() { return fakeOperations(); },
};
const worker = createWorker(dependencies);

async function responseFor(
  body: unknown,
  headers: Record<string, string> = {
    "MCP-Protocol-Version": LEGACY_PROTOCOL_VERSION,
  },
): Promise<Response> {
  return worker.fetch(
    new Request("https://worker.test/mcp", {
      method: "POST",
      headers: {
        Authorization: "Bearer test",
        "Content-Type": "application/json",
        ...headers,
      },
      body: JSON.stringify(body),
    }),
    {} as never,
  );
}

async function call(body: unknown): Promise<{ status: number; json: any }> {
  const response = await responseFor(body);
  return { status: response.status, json: await response.json() };
}

describe("actual Worker HTTP handler MCP contract", () => {
  const modernBody = (
    id: number,
    method: string,
    params: Record<string, unknown> = {},
  ) => ({
    jsonrpc: "2.0",
    id,
    method,
    params: {
      ...params,
      _meta: {
        "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": { name: "contract-test", version: "1" },
        "io.modelcontextprotocol/clientCapabilities": {},
      },
    },
  });

  const modernResponse = (
    body: ReturnType<typeof modernBody>,
    extraHeaders: Record<string, string> = {},
  ) => responseFor(body, {
    "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
    "Mcp-Method": body.method,
    ...extraHeaders,
  });

  it("serves authenticated modern discovery with server identity and cache hints", async () => {
    const body = modernBody(10, "server/discover");
    const response = await modernResponse(body);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      jsonrpc: "2.0",
      id: 10,
      result: {
        resultType: "complete",
        supportedVersions: [...SUPPORTED_PROTOCOL_VERSIONS],
        capabilities: { tools: {} },
        ttlMs: 300_000,
        cacheScope: "public",
        _meta: {
          "io.modelcontextprotocol/serverInfo": {
            name: "Taskboi",
            version: "1.0.0",
          },
        },
      },
    });

    const unauthorized = await worker.fetch(new Request("https://worker.test/mcp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
        "Mcp-Method": "server/discover",
      },
      body: JSON.stringify(body),
    }), {} as never);
    expect(unauthorized.status).toBe(401);
  });

  it("allows the required modern MCP headers in CORS preflight", async () => {
    const response = await worker.fetch(new Request("https://worker.test/mcp", {
      method: "OPTIONS",
    }), {} as never);
    expect(response.status).toBe(200);
    expect(response.headers.get("Access-Control-Allow-Headers")).toBe(
      "Content-Type, Authorization, MCP-Protocol-Version, Mcp-Method, Mcp-Name",
    );
  });

  it("handles modern tools/list and tools/call directly without initialize", async () => {
    const listResponse = await modernResponse(modernBody(11, "tools/list"));
    expect(listResponse.status).toBe(200);
    const list = await listResponse.json() as any;
    expect(list.result.resultType).toBe("complete");
    expect(list.result.tools).toHaveLength(16);
    expect(list.result.ttlMs).toBe(300_000);
    expect(list.result.cacheScope).toBe("public");

    const callBody = modernBody(12, "tools/call", {
      name: "list_projects",
      arguments: {},
    });
    const callResponse = await modernResponse(callBody, {
      "Mcp-Name": "list_projects",
    });
    expect(callResponse.status).toBe(200);
    const result = (await callResponse.json() as any).result;
    expect(result.resultType).toBe("complete");
    expect(JSON.parse(result.content[0].text)).toEqual({ projects: [project] });
  });

  it("retains base64-encoded Mcp-Name matching and malformed-name rejection", async () => {
    const body = modernBody(13, "tools/call", {
      name: "list_projects",
      arguments: {},
    });
    const matched = await modernResponse(body, {
      "Mcp-Name": "=?base64?bGlzdF9wcm9qZWN0cw==?=",
    });
    expect(matched.status).toBe(200);

    const malformed = await modernResponse(body, {
      "Mcp-Name": "=?base64?%%%?=",
    });
    expect(malformed.status).toBe(400);
    expect((await malformed.json() as any).error).toEqual({
      code: -32020,
      message: "Header mismatch: Mcp-Name header is malformed",
    });
  });

  it.each([
    {
      name: "missing protocol header",
      body: modernBody(20, "tools/list"),
      headers: { "Mcp-Method": "tools/list" },
      message: "Header mismatch: MCP-Protocol-Version header is required",
    },
    {
      name: "protocol header/body mismatch",
      body: modernBody(21, "tools/list"),
      headers: {
        "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
        "Mcp-Method": "tools/list",
      },
      mutate: (body: any) => {
        body.params._meta["io.modelcontextprotocol/protocolVersion"] = "2025-11-25";
      },
      message: "Header mismatch: MCP-Protocol-Version header does not match request _meta",
    },
    {
      name: "missing method header",
      body: modernBody(22, "tools/list"),
      headers: { "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION },
      message: "Header mismatch: Mcp-Method header is required",
    },
    {
      name: "mismatched method header",
      body: modernBody(23, "tools/list"),
      headers: {
        "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
        "Mcp-Method": "tools/call",
      },
      message: "Header mismatch: Mcp-Method header does not match request method",
    },
    {
      name: "missing name header",
      body: modernBody(24, "tools/call", { name: "list_projects", arguments: {} }),
      headers: {
        "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
        "Mcp-Method": "tools/call",
      },
      message: "Header mismatch: Mcp-Name header is required",
    },
    {
      name: "mismatched name header",
      body: modernBody(25, "tools/call", { name: "list_projects", arguments: {} }),
      headers: {
        "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
        "Mcp-Method": "tools/call",
        "Mcp-Name": "get_inbox",
      },
      message: "Header mismatch: Mcp-Name header does not match request name",
    },
  ])("deterministically rejects $name", async ({ body, headers, mutate, message }) => {
    mutate?.(body);
    const response = await responseFor(body, headers);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      jsonrpc: "2.0",
      id: body.id,
      error: { code: -32020, message },
    });
  });

  it("rejects unsupported versions distinctly", async () => {
    const response = await responseFor(modernBody(26, "tools/list"), {
      "MCP-Protocol-Version": "1900-01-01",
      "Mcp-Method": "tools/list",
    });
    expect(response.status).toBe(400);
    expect((await response.json() as any).error).toEqual({
      code: -32022,
      message: "Unsupported protocol version",
      data: {
        supported: [...SUPPORTED_PROTOCOL_VERSIONS],
        requested: "1900-01-01",
      },
    });
  });

  it.each([
    HANDSHAKE_PROTOCOL_VERSION,
    LEGACY_PROTOCOL_VERSION,
  ])("selects and echoes the supported handshake version %s", async (version) => {
    const response = await responseFor({
      jsonrpc: "2.0",
      id: 30,
      method: "initialize",
      params: {
        protocolVersion: version,
        capabilities: {},
        clientInfo: { name: "legacy-test", version: "1" },
      },
    }, { "MCP-Protocol-Version": version });
    expect(response.status).toBe(200);
    const initialized = await response.json() as any;
    expect(initialized.result.protocolVersion).toBe(version);
    expect(initialized.result.resultType).toBeUndefined();
  });

  it("continues to reject headerless requests", async () => {
    const headerless = await responseFor(
      { jsonrpc: "2.0", id: 31, method: "tools/list", params: {} },
      {},
    );
    expect(headerless.status).toBe(400);
    expect((await headerless.json() as any).error.code).toBe(-32020);
  });

  it("allows missing Origin for native clients and exact configured browser origins", async () => {
    const body = { jsonrpc: "2.0", id: 32, method: "tools/list", params: {} };
    const native = await responseFor(body);
    expect(native.status).toBe(200);
    expect(native.headers.get("Access-Control-Allow-Origin")).toBeNull();

    const allowed = await worker.fetch(new Request("https://worker.test/mcp", {
      method: "POST",
      headers: {
        Authorization: "Bearer test",
        "Content-Type": "application/json",
        Origin: "https://app.example",
        "MCP-Protocol-Version": LEGACY_PROTOCOL_VERSION,
      },
      body: JSON.stringify(body),
    }), {
      OAUTH_ISSUER: "https://worker.test",
      MCP_ALLOWED_ORIGINS: JSON.stringify(["https://app.example"]),
    } as never);
    expect(allowed.status).toBe(200);
    expect(allowed.headers.get("Access-Control-Allow-Origin")).toBe("https://app.example");
    expect(allowed.headers.get("Vary")).toBe("Origin");
  });

  it("rejects an unconfigured Origin before authorization", async () => {
    const response = await worker.fetch(new Request("https://worker.test/mcp", {
      method: "POST",
      headers: {
        Origin: "https://evil.example",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 33, method: "tools/list" }),
    }), { OAUTH_ISSUER: "https://worker.test" } as never);
    expect(response.status).toBe(403);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(await response.json()).toEqual({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Invalid Origin" },
    });
  });

  it.each([
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
    "roots/list_changed",
  ])("returns an empty HTTP 202 for the %s notification", async (method) => {
    const response = await responseFor({
      jsonrpc: "2.0",
      method,
      params: {},
    });
    expect(response.status).toBe(202);
    expect(await response.text()).toBe("");
    expect(response.headers.get("content-type")).toBeNull();
  });

  it("exposes the complete shared tool list", async () => {
    const { json } = await call({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
    expect(json.result.tools).toHaveLength(16);
    expect(json.result.tools.map(({ name }: { name: string }) => name)).toEqual([
      "list_projects", "get_inbox", "get_project", "create_project", "update_project",
      "delete_project", "list_tasks", "get_task", "get_today_tasks", "get_upcoming_tasks",
      "get_subtasks", "create_task", "update_task",
      "complete_task", "uncomplete_task", "delete_task",
    ]);
    expect(json.result.tools.find(({ name }: { name: string }) => name === "get_project")
      .inputSchema.properties.id.format).toBe("uuid");
    expect(json.result.tools.some(({ name }: { name: string }) =>
      name === "get_my_tasks" || name === "get_tasks_by_assignee")).toBe(false);
    for (const name of ["create_project", "update_project", "create_task", "update_task"]) {
      const tool = json.result.tools.find((candidate: { name: string }) =>
        candidate.name === name);
      expect(Object.keys(tool.inputSchema.properties)).not.toContain("defaultAssignee");
      expect(Object.keys(tool.inputSchema.properties)).not.toContain("assignedTo");
    }
  });

  it("maps validation, success, and application errors exactly like stdio", async () => {
    const invalid = (await call({
      jsonrpc: "2.0", id: 2, method: "tools/call",
      params: { name: "get_project", arguments: { id: "not-a-uuid" } },
    })).json.result;
    expect(invalid.isError).toBe(true);
    expect(invalid.content[0].text).toMatch(/^Error: Invalid arguments for get_project:/);

    const success = (await call({
      jsonrpc: "2.0", id: 3, method: "tools/call",
      params: { name: "list_projects", arguments: {} },
    })).json.result;
    expect(JSON.parse(success.content[0].text)).toEqual({ projects: [project] });

    expect((await call({
      jsonrpc: "2.0", id: 4, method: "tools/call",
      params: { name: "get_project", arguments: { id: projectId } },
    })).json.result).toEqual({
      content: [{ type: "text", text: "Error: project unavailable" }],
      isError: true,
    });
  });

  it("preserves SDK unknown and malformed request errors", async () => {
    expect((await call({
      jsonrpc: "2.0", id: 5, method: "unknown/method", params: {},
    })).json).toEqual({
      jsonrpc: "2.0", id: 5, error: { code: -32601, message: "Method not found" },
    });

    expect((await call({
      jsonrpc: "2.0", id: 6, method: "tools/call", params: { arguments: {} },
    })).json).toEqual({
      jsonrpc: "2.0",
      id: 6,
      error: {
        code: -32603,
        message: "[\n  {\n    \"expected\": \"string\",\n    \"code\": \"invalid_type\",\n    \"path\": [\n      \"params\",\n      \"name\"\n    ],\n    \"message\": \"Invalid input: expected string, received undefined\"\n  }\n]",
      },
    });
  });
});
