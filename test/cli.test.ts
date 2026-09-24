import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const CLI_PATH = resolve(process.cwd(), "dist", "cli.js");

function runCli(args: string[], cwd: string) {
  return spawnSync(process.execPath, [CLI_PATH, ...args], {
    cwd,
    encoding: "utf8",
    // Explicitly no stdin, so any policy that requires an interactive
    // confirmation should observe a non-TTY and fail closed.
    input: "",
  });
}

describe("agentseatbelt CLI (end-to-end against the built dist/cli.js)", () => {
  let dir: string;
  let policyPath: string;
  let logPath: string;
  let markerPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "agentseatbelt-cli-"));
    policyPath = join(dir, "policy.yaml");
    logPath = join(dir, "audit.log.jsonl");
    markerPath = join(dir, "marker.txt");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("runs an allowed command and passes through its real stdout and exit code", () => {
    writeFileSync(
      policyPath,
      `
version: 1
default: deny
rules:
  - description: "allow node"
    command: node
    action: allow
`,
      "utf8",
    );

    const script = `console.log('hello-from-allowed-child'); process.exit(3);`;
    const result = runCli(["run", "--policy", policyPath, "--log", logPath, "--", "node", "-e", script], dir);

    expect(result.stdout).toContain("hello-from-allowed-child");
    expect(result.status).toBe(3); // the wrapped command's own real exit code, passed through

    const logLines = readFileSync(logPath, "utf8").trim().split("\n");
    expect(logLines.length).toBe(1);
    const entry = JSON.parse(logLines[0]);
    expect(entry.decision).toBe("allow");
    expect(entry.exitCode).toBe(3);
  });

  it("never spawns a denied command (its side effect never happens) and exits non-zero", () => {
    writeFileSync(
      policyPath,
      `
version: 1
default: deny
rules:
  - description: "allow git only; node is not allow-listed so it falls through to the default deny"
    command: git
    action: allow
`,
      "utf8",
    );

    const script = `require('fs').writeFileSync(${JSON.stringify(markerPath)}, 'should-not-exist');`;
    const result = runCli(["run", "--policy", policyPath, "--log", logPath, "--", "node", "-e", script], dir);

    expect(result.status).not.toBe(0);
    expect(existsSync(markerPath)).toBe(false); // the side effect the denied command WOULD have produced

    const logLines = readFileSync(logPath, "utf8").trim().split("\n");
    expect(logLines.length).toBe(1);
    const entry = JSON.parse(logLines[0]);
    expect(entry.decision).toBe("deny");
    expect(entry.exitCode).toBeNull();
  });

  it("fails closed (denies) an 'ask' rule when there is no interactive TTY", () => {
    writeFileSync(
      policyPath,
      `
version: 1
default: ask
rules: []
`,
      "utf8",
    );
    const script = `require('fs').writeFileSync(${JSON.stringify(markerPath)}, 'should-not-exist');`;
    const result = runCli(["run", "--policy", policyPath, "--log", logPath, "--", "node", "-e", script], dir);

    expect(result.status).not.toBe(0);
    expect(existsSync(markerPath)).toBe(false);

    const entry = JSON.parse(readFileSync(logPath, "utf8").trim().split("\n")[0]);
    expect(entry.decision).toBe("ask-deny");
  });

  it("passes through the wrapped command's own non-zero failure exit code on allow", () => {
    writeFileSync(
      policyPath,
      `
version: 1
default: allow
rules: []
`,
      "utf8",
    );
    const result = runCli(["run", "--policy", policyPath, "--log", logPath, "--", "node", "-e", "process.exit(7)"], dir);
    expect(result.status).toBe(7);

    const entry = JSON.parse(readFileSync(logPath, "utf8").trim().split("\n")[0]);
    expect(entry.decision).toBe("allow");
    expect(entry.exitCode).toBe(7);
  });

  it("verify-log reports OK on an untampered chain and detects a hand-edited tampered copy", () => {
    writeFileSync(
      policyPath,
      `
version: 1
default: allow
rules: []
`,
      "utf8",
    );
    // Build up a small real chain via three real runs.
    runCli(["run", "--policy", policyPath, "--log", logPath, "--", "node", "-e", "process.exit(0)"], dir);
    runCli(["run", "--policy", policyPath, "--log", logPath, "--", "node", "-e", "process.exit(0)"], dir);
    runCli(["run", "--policy", policyPath, "--log", logPath, "--", "node", "-e", "process.exit(1)"], dir);

    const clean = runCli(["verify-log", logPath], dir);
    expect(clean.status).toBe(0);
    expect(clean.stdout).toMatch(/OK/);

    // Hand-tamper: flip the recorded exit code of the first entry, as an
    // attacker rewriting history to hide a failure/denial would.
    const lines = readFileSync(logPath, "utf8").trim().split("\n");
    const tampered = JSON.parse(lines[0]);
    tampered.exitCode = 99;
    lines[0] = JSON.stringify(tampered);
    writeFileSync(logPath, lines.join("\n") + "\n", "utf8");

    const dirty = runCli(["verify-log", logPath], dir);
    expect(dirty.status).not.toBe(0);
    expect(dirty.stderr).toMatch(/tampered/i);
  });

  it("init scaffolds a starter policy file", () => {
    const initDir = mkdtempSync(join(tmpdir(), "agentseatbelt-init-"));
    try {
      const result = runCli(["init"], initDir);
      expect(result.status).toBe(0);
      expect(existsSync(join(initDir, ".agentseatbelt", "policy.yaml"))).toBe(true);
    } finally {
      rmSync(initDir, { recursive: true, force: true });
    }
  });
});
