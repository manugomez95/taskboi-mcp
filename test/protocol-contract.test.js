import assert from "node:assert/strict";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  CallToolResultSchema,
  ListToolsResultSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createTaskboiServer } from "../dist/server.js";

const projectId = "11111111-1111-4111-8111-111111111111";
const project = { id: projectId, name: "Inbox" };

function fakeOperations() {
  return new Proxy(
    {
      async listProjects() {
        return [project];
      },
      async getProject() {
        throw new Error("project unavailable");
      },
    },
    {
      get(target, property) {
        if (property in target) return target[property];
        return async () => {
          throw new Error(`unexpected operation: ${String(property)}`);
        };
      },
    },
  );
}

async function configuredPair() {
  const server = createTaskboiServer(fakeOperations());
  const client = new Client({ name: "contract-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return { client, clientTransport, server };
}

async function rawRequest(transport, request) {
  return new Promise(async (resolve, reject) => {
    const previousMessage = transport.onmessage;
    const previousError = transport.onerror;
    transport.onmessage = (message) => {
      transport.onmessage = previousMessage;
      transport.onerror = previousError;
      resolve(message);
    };
    transport.onerror = reject;
    await transport.send(request);
  });
}

test("configured stdio Server exposes the complete shared tool list", async (t) => {
  const { client, server } = await configuredPair();
  t.after(() => Promise.all([client.close(), server.close()]));
  const result = await client.request({ method: "tools/list", params: {} }, ListToolsResultSchema);
  assert.equal(result.tools.length, 16);
  assert.deepEqual(result.tools.map(({ name }) => name), [
    "list_projects", "get_inbox", "get_project", "create_project", "update_project",
    "delete_project", "list_tasks", "get_task", "get_today_tasks", "get_upcoming_tasks",
    "get_subtasks", "create_task", "update_task",
    "complete_task", "uncomplete_task", "delete_task",
  ]);
  assert.equal(result.tools.find(({ name }) => name === "get_project").inputSchema.properties.id.format, "uuid");
  assert.equal(
    result.tools.some(({ name }) =>
      name === "get_my_tasks" || name === "get_tasks_by_assignee"),
    false,
  );
  for (const name of ["create_project", "update_project", "create_task", "update_task"]) {
    const tool = result.tools.find((candidate) => candidate.name === name);
    assert.ok(tool);
    assert.equal(
      Object.keys(tool.inputSchema.properties).some((property) =>
        property === "defaultAssignee" || property === "assignedTo"),
      false,
    );
  }
});

test("configured stdio Server maps validation, success, and application errors", async (t) => {
  const { client, server } = await configuredPair();
  t.after(() => Promise.all([client.close(), server.close()]));

  const invalid = await client.request(
    { method: "tools/call", params: { name: "get_project", arguments: { id: "not-a-uuid" } } },
    CallToolResultSchema,
  );
  assert.equal(invalid.isError, true);
  assert.match(invalid.content[0].text, /^Error: Invalid arguments for get_project:/);

  const success = await client.request(
    { method: "tools/call", params: { name: "list_projects", arguments: {} } },
    CallToolResultSchema,
  );
  assert.deepEqual(JSON.parse(success.content[0].text), { projects: [project] });

  const failure = await client.request(
    { method: "tools/call", params: { name: "get_project", arguments: { id: projectId } } },
    CallToolResultSchema,
  );
  assert.deepEqual(failure, {
    content: [{ type: "text", text: "Error: project unavailable" }],
    isError: true,
  });
});

test("configured stdio Server preserves SDK unknown and malformed request errors", async (t) => {
  const { client, clientTransport, server } = await configuredPair();
  t.after(() => Promise.all([client.close(), server.close()]));

  assert.deepEqual(await rawRequest(clientTransport, {
    jsonrpc: "2.0", id: 40, method: "unknown/method", params: {},
  }), {
    jsonrpc: "2.0", id: 40, error: { code: -32601, message: "Method not found" },
  });

  assert.deepEqual(await rawRequest(clientTransport, {
    jsonrpc: "2.0", id: 41, method: "tools/call", params: { arguments: {} },
  }), {
    jsonrpc: "2.0",
    id: 41,
    error: {
      code: -32603,
      message: "[\n  {\n    \"expected\": \"string\",\n    \"code\": \"invalid_type\",\n    \"path\": [\n      \"params\",\n      \"name\"\n    ],\n    \"message\": \"Invalid input: expected string, received undefined\"\n  }\n]",
    },
  });
});
