import assert from "node:assert/strict";
import { cpSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import test from "node:test";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const npm = process.platform === "win32" ? "npm.cmd" : "npm";

test("a fresh build packs only public runtime files", (t) => {
  const fixture = mkdtempSync(join(tmpdir(), "taskboi-mcp-package-"));
  const packDestination = join(fixture, "packed");
  mkdirSync(packDestination);
  t.after(() => rmSync(fixture, { force: true, recursive: true }));

  for (const entry of [
    "LICENSE",
    "README.md",
    "bin",
    "package-lock.json",
    "package.json",
    "scripts",
    "src",
    "tsconfig.json",
  ]) {
    cpSync(join(packageRoot, entry), join(fixture, entry), { recursive: true });
  }

  execFileSync(npm, ["ci", "--ignore-scripts"], {
    cwd: fixture,
    stdio: "pipe",
  });
  execFileSync(npm, ["run", "build"], { cwd: fixture, stdio: "pipe" });
  const packed = JSON.parse(execFileSync(
    npm,
    ["pack", "--json", "--pack-destination", packDestination],
    { cwd: fixture, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  ));
  const files = packed[0].files.map(({ path }) => path).sort();

  for (const expected of [
    "LICENSE",
    "README.md",
    "bin/taskboi-mcp.js",
    "dist/index.d.ts",
    "dist/index.js",
    "dist/protocol.d.ts",
    "dist/protocol.js",
    "package.json",
  ]) {
    assert.ok(files.includes(expected), `package is missing ${expected}`);
  }

  for (const excludedPrefix of [
    "src/",
    "test/",
    "scripts/",
    "workers/",
    ".github/",
    "tsconfig.json",
    ".dev.vars",
  ]) {
    assert.ok(
      !files.some((path) => path === excludedPrefix || path.startsWith(excludedPrefix)),
      `package contains excluded ${excludedPrefix}`,
    );
  }

  assert.ok(files.every((path) => !path.includes("private")));
  assert.ok(files.every((path) => !path.startsWith("dist/tools/")));
});
