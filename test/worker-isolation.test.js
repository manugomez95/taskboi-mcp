import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cp, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("Worker protocol stays in lockstep with the stdio protocol", async () => {
  const rootProtocol = await readFile(new URL("../src/protocol.ts", import.meta.url), "utf8");
  const workerProtocol = await readFile(
    new URL("../workers/src/protocol.ts", import.meta.url),
    "utf8",
  );
  assert.equal(workerProtocol, rootProtocol);
});

test("Worker installs and checks from an isolated workers-only copy", async (t) => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "taskboi-worker-"));
  const isolatedWorker = join(temporaryRoot, "workers");
  t.after(() => rm(temporaryRoot, { recursive: true, force: true }));

  await cp(new URL("../workers", import.meta.url), isolatedWorker, {
    recursive: true,
    filter(source) {
      return !source.includes(`${join("workers", "node_modules")}`) &&
        !source.includes(`${join("workers", "dist")}`);
    },
  });

  execFileSync("npm", ["ci"], {
    cwd: isolatedWorker,
    encoding: "utf8",
    stdio: "pipe",
  });
  for (const script of ["test", "typecheck", "build"]) {
    execFileSync("npm", ["run", script], {
      cwd: isolatedWorker,
      encoding: "utf8",
      stdio: "pipe",
    });
  }
});
