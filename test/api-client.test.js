import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

import { apiRequestUrl, normalizeTaskboiApiBaseUrl } from "taskboi-mcp/api-base-url";
import { taskboiTools } from "taskboi-mcp/protocol";
import { TaskboiApiClient } from "../dist/api-client.js";

const baseUrl = "https://api.example.invalid/functions/v1/mcp-api";

test("resolves the API base URL helpers through the built package subpath", () => {
  assert.equal(
    normalizeTaskboiApiBaseUrl("https://API.EXAMPLE.INVALID:443/functions/v1/mcp-api"),
    baseUrl,
  );
});

test("resolves the portable protocol through the built package subpath", () => {
  assert.equal(taskboiTools.length, 16);
});

test("portable protocol has no MCP SDK runtime dependency", async () => {
  assert.doesNotMatch(
    await readFile(new URL("../dist/protocol.js", import.meta.url), "utf8"),
    /@modelcontextprotocol\/sdk/,
  );
});

test("normalizes the mandatory API base URL", () => {
  assert.equal(normalizeTaskboiApiBaseUrl("https://API.EXAMPLE.INVALID:443/functions/v1/mcp-api"), baseUrl);
});

test("rejects missing and unsafe API base URLs", () => {
  for (const value of [undefined, "", " ", ` ${baseUrl}`, `${baseUrl}/`,
    "http://api.example.invalid/functions/v1/mcp-api",
    "https://user@api.example.invalid/functions/v1/mcp-api",
    "https://api.example.invalid/functions/v1/other", `${baseUrl}?x=1`, `${baseUrl}#fragment`]) {
    assert.throws(() => normalizeTaskboiApiBaseUrl(value), /TASKBOI_API_BASE_URL/);
  }
});

test("builds requests only from non-escaping relative paths", () => {
  assert.equal(apiRequestUrl(baseUrl, "/projects?limit=1"), `${baseUrl}/projects?limit=1`);
  for (const path of ["https://evil.example.test/x", "//evil.example.test/x", "/../x",
    "/%2e%2e/x", "/safe%2f..%2fx", "/safe\\..\\x"]) {
    assert.throws(() => apiRequestUrl(baseUrl, path), /path/);
  }
});

test("API client uses the injected base URL", async () => {
  const originalFetch = globalThis.fetch;
  let requested;
  globalThis.fetch = async (input) => {
    requested = String(input);
    return new Response(JSON.stringify({ projects: [] }), { headers: { "Content-Type": "application/json" } });
  };
  try {
    await new TaskboiApiClient("tk_test", baseUrl).listProjects();
    assert.equal(requested, `${baseUrl}/projects`);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("public MCP production source contains no prior hosted API endpoint", async () => {
  const priorHost = ["qagfzbwvlrmmdyrpuyvi", "supabase", "co"].join(".");
  for (const directory of [new URL("../src/", import.meta.url), new URL("../workers/src/", import.meta.url)]) {
    for (const name of await readdir(directory)) {
      if (name.endsWith(".ts")) {
        assert.doesNotMatch(await readFile(new URL(name, directory), "utf8"), new RegExp(priorHost));
      }
    }
  }
});
