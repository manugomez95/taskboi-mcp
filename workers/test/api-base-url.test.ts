import { describe, expect, it } from "vitest";
import { apiRequestUrl, normalizeTaskboiApiBaseUrl } from "../src/api-base-url";

const baseUrl = "https://api.example.invalid/functions/v1/mcp-api";

describe("TASKBOI_API_BASE_URL binding", () => {
  it("normalizes a canonical absolute HTTPS endpoint", () => {
    expect(normalizeTaskboiApiBaseUrl("https://API.EXAMPLE.INVALID:443/functions/v1/mcp-api")).toBe(baseUrl);
  });

  it.each([
    undefined,
    "",
    " ",
    ` ${baseUrl}`,
    `${baseUrl}/`,
    "http://api.example.invalid/functions/v1/mcp-api",
    "https://user:pass@api.example.invalid/functions/v1/mcp-api",
    "https://api.example.invalid/functions/v1/wrong",
    `${baseUrl}?query=yes`,
    `${baseUrl}#fragment`,
  ])("rejects a missing or unsafe binding: %s", (value) => {
    expect(() => normalizeTaskboiApiBaseUrl(value)).toThrow(/TASKBOI_API_BASE_URL/);
  });

  it("rejects absolute and path-escaping API request inputs", () => {
    expect(apiRequestUrl(baseUrl, "/projects")).toBe(`${baseUrl}/projects`);
    for (const path of ["https://evil.example.test/x", "//evil.example.test/x", "/../x", "/%2e%2e/x"]) {
      expect(() => apiRequestUrl(baseUrl, path)).toThrow(/path/);
    }
  });
});
