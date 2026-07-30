# Contributing

Thanks for helping improve the public Taskboi MCP integration.

## Development setup

Use Node.js 18 or later. Install both packages, then run the canonical
technical-health check from the repository root:

```sh
npm ci
npm --prefix workers ci
npm run check
```

The check covers stdio and Worker tests and builds, Worker type-checking,
production dependency audits, and workflow policy. The Worker build is a local
Wrangler dry run. The current toolchain has no robust unused-dependency
analysis, so review suspected unused dependencies manually rather than relying
on this command to detect them. Repository automation never publishes the npm
package, creates release assets, or deploys a Worker.

## Pull requests

Keep changes focused, add tests for behavior changes, and update both transport
implementations when their shared protocol changes. Never commit credentials,
real operator endpoints, hosted client allowlists, generated `dist` directories,
Worker bundles, or npm tarballs.

By contributing, you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
