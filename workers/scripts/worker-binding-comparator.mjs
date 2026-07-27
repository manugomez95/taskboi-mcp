const SECRET_VALUE_KEYS = new Set(["text", "value"]);
// One-time migration exception for the compromised, obsolete OAuth client secret.
// Keep this as a single exact name: every other active binding must survive unchanged.
const ONE_TIME_REMOVABLE_BINDING = "OAUTH_CLIENT_SECRET";

export function isDurableObjectMigrationUploadError(output) {
  return /\[code:\s*10211\]/i.test(output);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function comparableBinding(binding) {
  if (typeof binding.type !== "string" || !binding.type.includes("secret")) return canonicalize(binding);
  return canonicalize(Object.fromEntries(Object.entries(binding).filter(([key]) => !SECRET_VALUE_KEYS.has(key))));
}

export function assertBindingsPreserved(activeBindings, candidateBindings) {
  if (!Array.isArray(activeBindings) || !Array.isArray(candidateBindings)) throw new Error("Binding data must be arrays");
  const index = (bindings, label) => {
    const result = new Map();
    for (const binding of bindings) {
      if (!binding || typeof binding !== "object" || Array.isArray(binding) || typeof binding.name !== "string" || !binding.name) {
        throw new Error(`${label} contains an invalid binding`);
      }
      if (result.has(binding.name)) throw new Error(`${label} contains duplicate binding ${binding.name}`);
      result.set(binding.name, binding);
    }
    return result;
  };
  const active = index(activeBindings, "Active version");
  const candidate = index(candidateBindings, "Candidate version");
  for (const [name, oldBinding] of active) {
    const newBinding = candidate.get(name);
    if (!newBinding) {
      if (name === ONE_TIME_REMOVABLE_BINDING) continue;
      throw new Error(`Candidate is missing binding ${name}`);
    }
    if (JSON.stringify(comparableBinding(oldBinding)) !== JSON.stringify(comparableBinding(newBinding))) {
      throw new Error(`Candidate changed binding ${name}`);
    }
  }
}

export function assertRequiredOAuthBindings(bindings) {
  if (!Array.isArray(bindings)) throw new Error("Version JSON lacks bindings");
  const byName = new Map(bindings.map((binding) => [binding?.name, binding]));
  if (byName.get("OAUTH_STORE")?.type !== "durable_object_namespace") throw new Error("Version lacks OAUTH_STORE Durable Object binding");
  if (byName.get("OAUTH_ISSUER")?.type !== "plain_text") throw new Error("Version lacks plaintext OAUTH_ISSUER");
  if (byName.get("TASKBOI_API_BASE_URL")?.type !== "plain_text") throw new Error("Version lacks plaintext TASKBOI_API_BASE_URL");
  if (byName.get("OAUTH_ENCRYPTION_KEY")?.type !== "secret_text") throw new Error("Version lacks secret OAUTH_ENCRYPTION_KEY");
}
