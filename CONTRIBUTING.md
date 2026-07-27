# Contributing

Thanks for helping improve the public Taskboi MCP integration.

## Development setup

Use Node.js 18 or later. Install and verify the stdio package from the repository
root:

```sh
npm ci
npm run build
npm test
npm audit --omit=dev --audit-level=high
```

Verify the remote Worker separately:

```sh
cd workers
npm ci
npm test
npm run typecheck
npm run build
npm audit --omit=dev --audit-level=high
```

The Worker build is a local Wrangler dry run. Repository automation never
publishes the npm package, creates release assets, or deploys a Worker.

## Pull requests

Keep changes focused, add tests for behavior changes, and update both transport
implementations when their shared protocol changes. Never commit credentials,
real operator endpoints, hosted client allowlists, generated `dist` directories,
Worker bundles, or npm tarballs.

By contributing, you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
