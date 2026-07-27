import { describe, expect, it } from "vitest";
import { createWorker, type WorkerDependencies } from "../src/index";
import type { TaskboiOperations } from "../src/protocol";

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

async function responseFor(body: unknown): Promise<Response> {
  return worker.fetch(
    new Request("https://worker.test/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer test", "Content-Type": "application/json" },
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
