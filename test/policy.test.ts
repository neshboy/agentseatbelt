import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { evaluate, loadPolicy } from "../src/policy";

describe("policy evaluation", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "agentseatbelt-policy-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function writePolicy(yaml: string): string {
    const path = join(dir, "policy.yaml");
    writeFileSync(path, yaml, "utf8");
    return path;
  }

  it("allows a command matched by name", () => {
    const path = writePolicy(`
version: 1
default: deny
rules:
  - description: "allow git"
    command: git
    action: allow
`);
    const policy = loadPolicy(path);
    const result = evaluate(policy, "git", ["status"], "/repo");
    expect(result.action).toBe("allow");
  });

  it("denies by default when default is deny and nothing matches", () => {
    const path = writePolicy(`
version: 1
default: deny
rules:
  - command: git
    action: allow
`);
    const policy = loadPolicy(path);
    const result = evaluate(policy, "curl", ["http://example.com"], "/repo");
    expect(result.action).toBe("deny");
    expect(result.reason).toMatch(/default/i);
  });

  it("denies sudo regardless of allow-listed default", () => {
    const path = writePolicy(`
version: 1
default: allow
rules:
  - description: "block sudo"
    command: sudo
    action: deny
`);
    const policy = loadPolicy(path);
    const result = evaluate(policy, "sudo", ["rm", "-rf", "/"], "/repo");
    expect(result.action).toBe("deny");
  });

  it("denies rm -rf via an args_pattern rule", () => {
    const path = writePolicy(`
version: 1
default: allow
rules:
  - description: "block recursive force delete"
    command: rm
    args_pattern: "-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r"
    action: deny
`);
    const policy = loadPolicy(path);
    const denied = evaluate(policy, "rm", ["-rf", "/tmp/whatever"], "/repo");
    expect(denied.action).toBe("deny");

    const allowed = evaluate(policy, "rm", ["file.txt"], "/repo");
    expect(allowed.action).toBe("allow");
  });

  it("matches cwd_glob against the working directory", () => {
    const path = writePolicy(`
version: 1
default: allow
rules:
  - description: "deny outside sandbox"
    cwd_glob: "/sandbox/**"
    action: deny
`);
    const policy = loadPolicy(path);
    const inside = evaluate(policy, "git", ["status"], "/sandbox/project");
    expect(inside.action).toBe("deny");

    const outside = evaluate(policy, "git", ["status"], "/home/user/project");
    expect(outside.action).toBe("allow");
  });

  it("first matching rule wins over later rules", () => {
    const path = writePolicy(`
version: 1
default: deny
rules:
  - description: "allow all git"
    command: git
    action: allow
  - description: "deny all git (should never trigger)"
    command: git
    action: deny
`);
    const policy = loadPolicy(path);
    const result = evaluate(policy, "git", ["push"], "/repo");
    expect(result.action).toBe("allow");
  });

  it("resolves to ask for rules with action ask", () => {
    const path = writePolicy(`
version: 1
default: deny
rules:
  - description: "ask before npm install"
    command: npm
    args_pattern: "install"
    action: ask
`);
    const policy = loadPolicy(path);
    const result = evaluate(policy, "npm", ["install"], "/repo");
    expect(result.action).toBe("ask");
  });

  it("rejects a policy file with an invalid action", () => {
    const path = writePolicy(`
version: 1
default: deny
rules:
  - command: git
    action: maybe
`);
    expect(() => loadPolicy(path)).toThrow();
  });

  it("rejects a rule with no match conditions", () => {
    const path = writePolicy(`
version: 1
default: deny
rules:
  - action: allow
`);
    expect(() => loadPolicy(path)).toThrow();
  });
});
