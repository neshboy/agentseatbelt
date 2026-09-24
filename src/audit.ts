import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

/** Hash used as the "previous hash" of the very first entry in a log. */
export const GENESIS_HASH = "0".repeat(64);

export type Decision = "allow" | "deny" | "ask-allow" | "ask-deny";

export interface AuditEntryInput {
  cwd: string;
  command: string;
  args: string[];
  decision: Decision;
  reason: string;
  /** Real process exit code, or null if the wrapped command never spawned. */
  exitCode: number | null;
}

export interface AuditEntry extends AuditEntryInput {
  seq: number;
  timestamp: string;
  prevHash: string;
  hash: string;
}

/**
 * Deterministically serialize an object for hashing: keys are sorted so the
 * hash does not depend on property insertion order, only on values.
 */
function canonicalize(obj: Record<string, unknown>): string {
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = (obj as Record<string, unknown>)[key];
  }
  return JSON.stringify(sorted);
}

function computeHash(prevHash: string, entryWithoutHash: Record<string, unknown>): string {
  const payload = canonicalize({ ...entryWithoutHash, prevHash });
  return createHash("sha256").update(payload).digest("hex");
}

/** Read the seq/hash of the last entry in the log, or the genesis values if the log doesn't exist yet. */
export function getLastHash(logPath: string): { seq: number; hash: string } {
  if (!existsSync(logPath)) {
    return { seq: 0, hash: GENESIS_HASH };
  }
  const content = readFileSync(logPath, "utf8");
  const lines = content.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) {
    return { seq: 0, hash: GENESIS_HASH };
  }
  const last = JSON.parse(lines[lines.length - 1]) as AuditEntry;
  return { seq: last.seq, hash: last.hash };
}

/**
 * Append one new entry to the hash-chained audit log. The caller must supply
 * the previous entry's hash and the next sequence number (see getLastHash).
 */
export function appendAuditEntry(
  logPath: string,
  input: AuditEntryInput,
  prevHash: string,
  seq: number,
): AuditEntry {
  const timestamp = new Date().toISOString();
  const base = { seq, timestamp, ...input };
  const hash = computeHash(prevHash, base);
  const entry: AuditEntry = { ...base, prevHash, hash };

  const dir = dirname(logPath);
  if (dir && dir !== ".") {
    mkdirSync(dir, { recursive: true });
  }
  appendFileSync(logPath, JSON.stringify(entry) + "\n", "utf8");
  return entry;
}

export interface VerifyResult {
  ok: boolean;
  totalEntries: number;
  error?: string;
  failedAtLine?: number;
  failedAtSeq?: number;
}

/**
 * Recompute the hash chain of an audit log from scratch and confirm that
 * every entry's stored hash matches what we recompute, and that every
 * entry's prevHash matches the previous entry's stored hash. Any edit to
 * any prior line (including editing, reordering, or deleting entries)
 * will break this chain and be reported here.
 */
export function verifyLog(logPath: string): VerifyResult {
  if (!existsSync(logPath)) {
    return { ok: false, totalEntries: 0, error: `Log file not found: ${logPath}` };
  }
  const content = readFileSync(logPath, "utf8");
  const lines = content.split("\n").filter((l) => l.trim().length > 0);

  let expectedPrevHash = GENESIS_HASH;
  for (let i = 0; i < lines.length; i++) {
    let entry: AuditEntry;
    try {
      entry = JSON.parse(lines[i]) as AuditEntry;
    } catch {
      return {
        ok: false,
        totalEntries: lines.length,
        error: `Line ${i + 1} is not valid JSON.`,
        failedAtLine: i + 1,
      };
    }

    const { hash: storedHash, ...rest } = entry;

    if (rest.prevHash !== expectedPrevHash) {
      return {
        ok: false,
        totalEntries: lines.length,
        error: `Broken hash chain at line ${i + 1} (seq ${entry.seq}): prevHash does not match the previous entry's hash.`,
        failedAtLine: i + 1,
        failedAtSeq: entry.seq,
      };
    }

    const recomputed = computeHash(rest.prevHash, rest);
    if (recomputed !== storedHash) {
      return {
        ok: false,
        totalEntries: lines.length,
        error: `Tampered entry detected at line ${i + 1} (seq ${entry.seq}): stored hash does not match the recomputed hash.`,
        failedAtLine: i + 1,
        failedAtSeq: entry.seq,
      };
    }

    expectedPrevHash = storedHash;
  }

  return { ok: true, totalEntries: lines.length };
}
