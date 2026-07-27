#!/usr/bin/env node

// Taskboi MCP Server Entry Point

import { createServer } from "./server.js";

createServer().catch((error) => {
  console.error("Failed to start Taskboi MCP server:", error);
  process.exit(1);
});
