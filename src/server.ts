// Taskboi MCP Server

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { TaskboiApiClient } from "./api-client.js";
import {
  dispatchTaskboiTool,
  taskboiTools,
  type TaskboiOperations,
} from "./protocol.js";

export function createTaskboiServer(operations: TaskboiOperations): Server {
  const server = new Server(
    { name: "Taskboi", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: taskboiTools }));
  server.setRequestHandler(CallToolRequestSchema, async ({ params }) =>
    dispatchTaskboiTool(params.name, params.arguments, operations));
  return server;
}

export async function createServer(): Promise<void> {
  // Get API key from environment
  const apiKey = process.env.TASKBOI_API_KEY;
  const apiBaseUrl = process.env.TASKBOI_API_BASE_URL;

  if (!apiKey) {
    console.error("Error: TASKBOI_API_KEY environment variable is required");
    console.error("");
    console.error("To get your API key:");
    console.error("1. Open Taskboi app");
    console.error("2. Go to Settings > API Keys");
    console.error("3. Generate a new API key");
    console.error("");
    console.error("Then set it in your MCP client configuration:");
    console.error('  "env": { "TASKBOI_API_KEY": "tk_your_key_here" }');
    process.exit(1);
  }

  if (!apiBaseUrl) {
    console.error("Error: TASKBOI_API_BASE_URL environment variable is required");
    process.exit(1);
  }

  // Create API client
  const client = new TaskboiApiClient(apiKey, apiBaseUrl);

  const server = createTaskboiServer(client);

  // Connect via stdio
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Handle shutdown
  process.on("SIGINT", async () => {
    await server.close();
    process.exit(0);
  });

  process.on("SIGTERM", async () => {
    await server.close();
    process.exit(0);
  });
}
