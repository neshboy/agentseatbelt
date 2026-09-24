import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { appendAuditEntry, GENESIS_HASH, getLastHash, verifyLog } from "../src/audit";

describe("audit log hash chain", () => {
  let dir: string;
  let logPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "agentseatbelt-audit-"));
    logPath = join(dir, "audit.log.jsonl");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("starts a fresh chain from the genesis hash", () => {
    expect(getLastHash(logPath)).toEqual({ seq: 0, hash: GENESIS_HASH });
  });

  it("writes entries that link to each other by hash and verifies clean", () => {
    let { hash, seq } = getLastHash(logPath);
    const e1 = appendAuditEntry(
      logPath,
      { cwd: "/tmp", command: "git", args: ["status"], decision: "allow", reason: "matched rule", exitCode: 0 },
      hash,
      seq + 1,
    );
    expect(e1.prevHash).toBe(GENESIS_HASH);

    ({ hash, seq } = getLastHash(logPath));
    const e2 = appendAuditEntry(
      logPath,
      { cwd: "/tmp", command: "rm", args: ["-rf", "/"], decision: "deny", reason: "matched deny rule", exitCode: null },
      hash,
      seq + 1,
    );
    expect(e2.prevHash).toBe(e1.hash);
    expect(e2.seq).toBe(2);

    const result = verifyLog(logPath);
    expect(result.ok).toBe(true);
    expect(result.totalEntries).toBe(2);
  });

  it("detects tampering with a prior entry's field", () => {
    let { hash, seq } = getLastHash(logPath);
    appendAuditEntry(
      logPath,
      { cwd: "/tmp", command: "git", args: ["status"], decision: "allow", reason: "matched rule", exitCode: 0 },
      hash,
      seq + 1,
    );
    ({ hash, seq } = getLastHash(logPath));
    appendAuditEntry(
      logPath,
      { cwd: "/tmp", command: "npm", args: ["install"], decision: "allow", reason: "matched rule", exitCode: 0 },
      hash,
      seq + 1,
    );

    // Sanity check: untampered log verifies fine.
    expect(verifyLog(logPath).ok).toBe(true);

    // Hand-edit the first line: change the logged decision from allow to
    // deny without recomputing the hash, exactly like an attacker trying
    // to rewrite history would (naively) do.
    const lines = readFileSync(logPath, "utf8").split("\n").filter((l) => l.length > 0);
    const tamperedFirst = JSON.parse(lines[0]);
    tamperedFirst.decision = "deny";
    tamperedFirst.exitCode = null;
    lines[0] = JSON.stringify(tamperedFirst);
    writeFileSync(logPath, lines.join("\n") + "\n", "utf8");

    const result = verifyLog(logPath);
    expect(result.ok).toBe(false);
    expect(result.failedAtLine).toBe(1);
    expect(result.error).toMatch(/tampered/i);
  });

  it("detects a deleted entry (chain gap)", () => {
    let { hash, seq } = getLastHash(logPath);
    appendAuditEntry(
      logPath,
      { cwd: "/tmp", command: "git", args: ["status"], decision: "allow", reason: "r1", exitCode: 0 },
      hash,
      seq + 1,
    );
    ({ hash, seq } = getLastHash(logPath));
    appendAuditEntry(
      logPath,
      { cwd: "/tmp", command: "git", args: ["log"], decision: "allow", reason: "r2", exitCode: 0 },
      hash,
      seq + 1,
    );
    ({ hash, seq } = getLastHash(logPath));
    appendAuditEntry(
      logPath,
      { cwd: "/tmp", command: "git", args: ["diff"], decision: "allow", reason: "r3", exitCode: 0 },
      hash,
      seq + 1,
    );

    const lines = readFileSync(logPath, "utf8").split("\n").filter((l) => l.length > 0);
    // Remove the middle entry, as an attacker trying to erase one decision
    // from history while keeping the rest would attempt.
    const rewritten = [lines[0], lines[2]].join("\n") + "\n";
    writeFileSync(logPath, rewritten, "utf8");

    const result = verifyLog(logPath);
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/broken hash chain/i);
  });

  it("reports ok on a missing log file's absence distinctly (no entries yet)", () => {
    const result = verifyLog(logPath);
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/not found/i);
  });
});
