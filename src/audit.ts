import { createHash } from "node:crypto";
import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readSync, readFileSync, statSync, unlinkSync } from "node:fs";
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

/**
 * Read just enough of the end of the file to contain the last full line,
 * growing the read window until a preceding newline is found (or the whole
 * file has been read). This keeps getLastHash() proportional to the length
 * of the last line rather than the whole log, so it stays cheap even for a
 * long-running session's growing audit log.
 */
function readLastLine(logPath: string, size: number): string {
  const fd = openSync(logPath, "r");
  try {
    let windowSize = Math.min(size, 4096);
    while (true) {
      const buf = Buffer.alloc(windowSize);
      const start = size - windowSize;
      const bytesRead = readSync(fd, buf, 0, windowSize, start);
      const chunk = buf.toString("utf8", 0, bytesRead);
      const trimmed = chunk.replace(/\n+$/, "");
      const lastNewline = trimmed.lastIndexOf("\n");
      if (lastNewline !== -1) {
        return trimmed.slice(lastNewline + 1);
      }
      if (windowSize >= size) {
        return trimmed;
      }
      windowSize = Math.min(windowSize * 2, size);
    }
  } finally {
    closeSync(fd);
  }
}

/** Read the seq/hash of the last entry in the log, or the genesis values if the log doesn't exist yet. */
export function getLastHash(logPath: string): { seq: number; hash: string } {
  if (!existsSync(logPath)) {
    return { seq: 0, hash: GENESIS_HASH };
  }
  const size = statSync(logPath).size;
  if (size === 0) {
    return { seq: 0, hash: GENESIS_HASH };
  }
  const lastLine = readLastLine(logPath, size).trim();
  if (lastLine.length === 0) {
    return { seq: 0, hash: GENESIS_HASH };
  }
  const last = JSON.parse(lastLine) as AuditEntry;
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

const LOCK_RETRY_DELAY_MS = 20;
const LOCK_TIMEOUT_MS = 5000;

function sleepSync(ms: number): void {
  // Atomics.wait blocks the current thread synchronously without spinning
  // the CPU, unlike a busy-loop on Date.now().
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Acquire an exclusive, cross-process advisory lock on `<logPath>.lock`.
 * Lock acquisition relies on O_EXCL (fs "wx" flag), which atomically fails
 * with EEXIST if another process already holds the lock, so this is safe
 * even when two separate `agentseatbelt run` processes attempt this at
 * the same instant. Callers must invoke the returned release function
 * (typically in a `finally` block) once done.
 */
function acquireLock(logPath: string, timeoutMs = LOCK_TIMEOUT_MS): () => void {
  const lockPath = `${logPath}.lock`;
  const dir = dirname(logPath);
  if (dir && dir !== ".") {
    mkdirSync(dir, { recursive: true });
  }
  const deadline = Date.now() + timeoutMs;
  while (true) {
    try {
      const fd = openSync(lockPath, "wx");
      closeSync(fd);
      return () => {
        try {
          unlinkSync(lockPath);
        } catch {
          // Already removed (or never fully created); nothing else to do.
        }
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") {
        throw err;
      }
      if (Date.now() >= deadline) {
        throw new Error(
          `agentseatbelt: timed out waiting for audit log lock (${lockPath}). ` +
            `If no other agentseatbelt process is actually running, delete this stale lock file and retry.`,
        );
      }
      sleepSync(LOCK_RETRY_DELAY_MS);
    }
  }
}

/**
 * Read the current chain tip and append one new entry as a single
 * lock-serialized operation. This is the safe entry point for concurrent
 * callers (e.g. multiple `agentseatbelt run` invocations against the same
 * log, or one process still awaiting an `ask` confirmation while another
 * appends): it re-reads the true last hash/seq under the lock immediately
 * before computing and appending the new entry, so two processes can never
 * read the same prevHash/seq and append colliding entries into the hash
 * chain.
 */
export function appendAuditEntryLocked(logPath: string, input: AuditEntryInput): AuditEntry {
  const release = acquireLock(logPath);
  try {
    const { hash: prevHash, seq: prevSeq } = getLastHash(logPath);
    return appendAuditEntry(logPath, input, prevHash, prevSeq + 1);
  } finally {
    release();
  }
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
