const MCP_API_PATH = "/functions/v1/mcp-api";

export function normalizeTaskboiApiBaseUrl(value: string | undefined): string {
  if (value === undefined || value.trim() === "") throw new Error("TASKBOI_API_BASE_URL binding is required");
  if (value !== value.trim()) throw new Error("TASKBOI_API_BASE_URL must not contain surrounding whitespace");
  let url: URL;
  try { url = new URL(value); }
  catch { throw new Error("TASKBOI_API_BASE_URL must be an absolute HTTPS URL"); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash ||
      url.pathname !== MCP_API_PATH || value.endsWith("/")) {
    throw new Error(`TASKBOI_API_BASE_URL must be an absolute HTTPS URL with exactly ${MCP_API_PATH}`);
  }
  return `${url.origin}${MCP_API_PATH}`;
}

export function apiRequestUrl(baseUrl: string, path: string): string {
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\")) {
    throw new Error("Taskboi API request path must be a root-relative path");
  }
  const [pathname] = path.split(/[?#]/, 1);
  for (const segment of pathname.split("/")) {
    let decoded: string;
    try { decoded = decodeURIComponent(segment); }
    catch { throw new Error("Taskboi API request path contains invalid encoding"); }
    if (decoded === "." || decoded === ".." || decoded.includes("/")) {
      throw new Error("Taskboi API request path must not escape the API base path");
    }
  }
  const url = new URL(`${baseUrl}${path}`);
  if (url.origin + url.pathname !== `${baseUrl}${pathname}`) {
    throw new Error("Taskboi API request path must not escape the API base path");
  }
  return url.toString();
}
