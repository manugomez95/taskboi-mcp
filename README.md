# Taskboi MCP

Public, deploy-source-only MCP integrations for Taskboi:

- A portable Node.js stdio server in the repository root.
- A remote OAuth-enabled Cloudflare Worker in [`workers/`](workers/).

Cloning this repository gives you source code only. It does not create a
Taskboi Cloud account, provision a hosted API, register OAuth clients, or deploy
infrastructure. Use configuration supplied by your Taskboi Cloud account, or
provide equivalent configuration for an API and Worker environment you operate.

## Stdio server

### Install and build from source

```sh
npm ci
npm run build
```

Run the built server with:

```sh
TASKBOI_API_KEY=your-key \
TASKBOI_API_BASE_URL=https://api.example.invalid/functions/v1/mcp-api \
node dist/index.js
```

`TASKBOI_API_KEY` and `TASKBOI_API_BASE_URL` are required. The base URL has no
default and must be an absolute HTTPS URL with the exact path
`/functions/v1/mcp-api`, without credentials, query, fragment, surrounding
whitespace, or a trailing slash. The `.invalid` hostname above is inert; replace
it with the endpoint supplied by Taskboi Cloud or by your self-hosting operator.

For an MCP client, point the command at this checkout:

```json
{
  "mcpServers": {
    "taskboi": {
      "command": "node",
      "args": ["/absolute/path/to/taskboi-mcp/dist/index.js"],
      "env": {
        "TASKBOI_API_KEY": "your-key",
        "TASKBOI_API_BASE_URL": "https://api.example.invalid/functions/v1/mcp-api"
      }
    }
  }
}
```

Never commit the real values. An installed npm package can instead be launched
with its `taskboi-mcp` binary, but this repository's automation does not publish
packages.

## Remote Worker

The Worker exposes the same MCP operations over Streamable HTTP and protects
them with OAuth 2.0 Authorization Code flow and S256 PKCE. Operators must supply
their own Cloudflare environment and runtime bindings. See
[`workers/README.md`](workers/README.md) for configuration, local verification,
and deployment guidance.

Taskboi Cloud is a separately provisioned hosted service. Self-hosting the
Worker does not grant API access or create Cloud accounts, endpoints, secrets,
or OAuth registrations.

## Available tools

Projects: `list_projects`, `get_inbox`, `get_project`, `create_project`,
`update_project`, and `delete_project`.

Tasks: `list_tasks`, `get_task`, `get_today_tasks`, `get_upcoming_tasks`,
`get_subtasks`, `create_task`, `update_task`, `complete_task`,
`uncomplete_task`, and `delete_task`.

Task recurrence uses RRULE strings such as `FREQ=DAILY`,
`FREQ=WEEKLY;BYDAY=MO,WE,FR`, or `FREQ=DAILY;INTERVAL=2`. Priority values are
`0` (none), `1` (urgent), `2` (high), `3` (normal), and `4` (low).

## Development

```sh
npm ci
npm test
npm audit --omit=dev --audit-level=high

cd workers
npm ci
npm test
npm run typecheck
npm run build
npm audit --omit=dev --audit-level=high
```

The Worker build is a dry run and writes only ignored local output. Generated
builds, bundles, tarballs, and credentials must not be committed. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
