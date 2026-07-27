import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const workflowDirectory = new URL("../.github/workflows/", import.meta.url);
const workflows = readdirSync(workflowDirectory)
  .filter((name) => /\.ya?ml$/.test(name))
  .map((name) => [name, readFileSync(new URL(name, workflowDirectory), "utf8")]);

if (workflows.length === 0) throw new Error("No GitHub Actions workflows found");

const forbidden = [
  [/\bnpm\s+publish\b/i, "npm publishing"],
  [/\bgh\s+release\b/i, "GitHub release assets"],
  [/\bsoftprops\/action-gh-release\b/i, "GitHub release action"],
  [/\bactions\/upload-release-asset\b/i, "GitHub release asset action"],
  [/\bcloudflare\/wrangler-action\b/i, "Worker deployment action"],
  [/\bwrangler\s+(?:deploy|publish)\b(?![^\n]*--dry-run)/i, "Worker deployment command"],
];

for (const [name, contents] of workflows) {
  for (const [pattern, description] of forbidden) {
    if (pattern.test(contents)) {
      throw new Error(`${name} contains forbidden ${description}`);
    }
  }
}

console.log(`Workflow policy passed for ${workflows.length} workflow files`);
