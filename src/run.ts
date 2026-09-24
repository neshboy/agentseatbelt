import spawn from "cross-spawn";
import { existsSync } from "node:fs";
import { appendAuditEntry, getLastHash, Decision } from "./audit";
import { evaluate, loadPolicy } from "./policy";
import { confirm, isInteractive } from "./prompt";

export interface RunOptions {
  command: string;
  args: string[];
  cwd: string;
  policyPath: string;
  logPath: string;
}

// Exit codes used when the wrapped command never actually spawned, i.e.
// AgentSeatbelt itself made a policy decision rather than passing through
// the wrapped command's own exit code. These are chosen to be unlikely
// collisions with common program exit codes, but callers who need a
// guarantee should treat the audit log as the source of truth, not the
// exit code alone.
export const EXIT_USAGE_ERROR = 2;
export const EXIT_POLICY_ERROR = 13;
export const EXIT_DENIED = 10;
export const EXIT_ASK_DECLINED = 11;
export const EXIT_ASK_NONINTERACTIVE = 12;

export async function runCommand(opts: RunOptions): Promise<number> {
  const { command, args, cwd, policyPath, logPath } = opts;

  if (!existsSync(policyPath)) {
    console.error(`agentseatbelt: policy file not found: ${policyPath}`);
    console.error(`Run 'agentseatbelt init' to create a starter policy.`);
    return EXIT_POLICY_ERROR;
  }

  let policy;
  try {
    policy = loadPolicy(policyPath);
  } catch (err) {
    console.error(`agentseatbelt: failed to load policy: ${(err as Error).message}`);
    return EXIT_POLICY_ERROR;
  }

  const decision = evaluate(policy, command, args, cwd);
  const { hash: prevHash, seq: prevSeq } = getLastHash(logPath);

  const record = (decisionLabel: Decision, exitCode: number | null) => {
    appendAuditEntry(logPath, { cwd, command, args, decision: decisionLabel, reason: decision.reason, exitCode }, prevHash, prevSeq + 1);
  };

  if (decision.action === "deny") {
    record("deny", null);
    console.error(`agentseatbelt: DENIED - ${describe(command, args)}`);
    console.error(`  reason: ${decision.reason}`);
    return EXIT_DENIED;
  }

  if (decision.action === "ask") {
    if (!isInteractive()) {
      record("ask-deny", null);
      console.error(`agentseatbelt: DENIED (non-interactive, cannot confirm) - ${describe(command, args)}`);
      console.error(`  reason: ${decision.reason}; policy requires confirmation but no TTY is available, failing closed.`);
      return EXIT_ASK_NONINTERACTIVE;
    }
    const approved = await confirm(
      `agentseatbelt: allow "${describe(command, args)}" in ${cwd}?\n  reason: ${decision.reason}\n  Proceed? (y/N) `,
    );
    if (!approved) {
      record("ask-deny", null);
      console.error("agentseatbelt: DENIED (user declined confirmation)");
      return EXIT_ASK_DECLINED;
    }
    const exitCode = await spawnChild(command, args, cwd);
    record("ask-allow", exitCode);
    return exitCode;
  }

  // action === "allow"
  const exitCode = await spawnChild(command, args, cwd);
  record("allow", exitCode);
  return exitCode;
}

function describe(command: string, args: string[]): string {
  return [command, ...args].join(" ");
}

function spawnChild(command: string, args: string[], cwd: string): Promise<number> {
  return new Promise((resolve) => {
    // cross-spawn resolves Windows .cmd/.bat shims (npm, npx, etc.) and
    // quotes arguments correctly, without the escaping/quoting hazards of
    // Node's built-in `shell: true` option.
    const child = spawn(command, args, { cwd, stdio: "inherit" });
    child.on("error", (err: NodeJS.ErrnoException) => {
      console.error(`agentseatbelt: failed to run '${command}': ${err.message}`);
      resolve(127);
    });
    child.on("exit", (code, signal) => {
      if (code !== null) {
        resolve(code);
      } else {
        resolve(signal ? 128 : 1);
      }
    });
  });
}
