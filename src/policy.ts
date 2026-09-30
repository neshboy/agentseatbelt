import { readFileSync } from "node:fs";
import { basename, extname } from "node:path";
import { load } from "js-yaml";
import { minimatch } from "minimatch";

export type Action = "allow" | "deny" | "ask";

const VALID_ACTIONS: Action[] = ["allow", "deny", "ask"];

export interface PolicyRule {
  description?: string;
  /** Exact match against the command name (argv[0]), e.g. "git", or a list of names. */
  command?: string | string[];
  /** Regex tested against the command name. */
  command_pattern?: string;
  /** Regex tested against "<command> <args...>" joined with spaces. */
  args_pattern?: string;
  /** Glob tested against the working directory the command would run in. */
  cwd_glob?: string;
  action: Action;
}

export interface Policy {
  version: number;
  /** Action applied when no rule matches. Defaults to "deny" (fail closed). */
  default: Action;
  rules: PolicyRule[];
}

export function loadPolicy(path: string): Policy {
  const raw = readFileSync(path, "utf8");
  const parsed = load(raw) as unknown;

  if (!parsed || typeof parsed !== "object") {
    throw new Error(`Policy file ${path} is empty or is not a valid YAML mapping.`);
  }
  const obj = parsed as Record<string, unknown>;

  if (obj.rules !== undefined && !Array.isArray(obj.rules)) {
    throw new Error(`Policy file ${path}: 'rules' must be an array if present.`);
  }
  const rules = (obj.rules as PolicyRule[] | undefined) ?? [];

  const defaultAction = (obj.default as Action | undefined) ?? "deny";
  if (!VALID_ACTIONS.includes(defaultAction)) {
    throw new Error(`Policy file ${path}: 'default' must be one of allow|deny|ask, got '${String(defaultAction)}'.`);
  }

  for (const [i, rule] of rules.entries()) {
    if (!rule || typeof rule !== "object" || !VALID_ACTIONS.includes(rule.action)) {
      throw new Error(
        `Policy file ${path}: rule #${i + 1} must have an 'action' of allow|deny|ask, got ${JSON.stringify(rule)}.`,
      );
    }
    if (
      rule.command === undefined &&
      rule.command_pattern === undefined &&
      rule.args_pattern === undefined &&
      rule.cwd_glob === undefined
    ) {
      throw new Error(
        `Policy file ${path}: rule #${i + 1} has no match conditions (command / command_pattern / args_pattern / cwd_glob).`,
      );
    }
  }

  return {
    version: (obj.version as number | undefined) ?? 1,
    default: defaultAction,
    rules,
  };
}

export interface EvalResult {
  action: Action;
  reason: string;
  ruleIndex: number | null;
}

/**
 * Evaluate a command against a policy. Rules are checked in order; the
 * first rule that matches wins. If no rule matches, the policy's default
 * action applies (fail closed: the built-in default is "deny").
 */
export function evaluate(policy: Policy, command: string, args: string[], cwd: string): EvalResult {
  const commandLine = [command, ...args].join(" ");

  for (let i = 0; i < policy.rules.length; i++) {
    const rule = policy.rules[i];
    if (ruleMatches(rule, command, cwd, commandLine)) {
      const desc = rule.description ?? `rule #${i + 1} (${rule.action})`;
      return { action: rule.action, reason: `matched ${desc}`, ruleIndex: i };
    }
  }

  return { action: policy.default, reason: "no rule matched; applied policy default", ruleIndex: null };
}

// Windows executable suffixes that should be ignored when comparing a
// path-qualified invocation (e.g. "RM.EXE") against a bare rule name
// (e.g. "rm").
const WINDOWS_EXECUTABLE_EXTENSIONS = new Set([".exe", ".cmd", ".bat", ".com", ".ps1"]);

/**
 * Normalize a command/rule name for name-based matching: strip any
 * directory component (so "/bin/rm", "./rm", and "rm" are equivalent) and,
 * on Windows, strip a trailing .exe/.cmd/.bat/.com/.ps1 suffix and
 * lower-case the result (so "RM.EXE" matches "rm").
 */
function normalizeCommandForMatch(command: string): string {
  let base = basename(command);
  if (process.platform === "win32") {
    const ext = extname(base).toLowerCase();
    if (WINDOWS_EXECUTABLE_EXTENSIONS.has(ext)) {
      base = base.slice(0, base.length - ext.length);
    }
    base = base.toLowerCase();
  }
  return base;
}

function ruleMatches(rule: PolicyRule, command: string, cwd: string, commandLine: string): boolean {
  if (rule.command !== undefined) {
    const names = Array.isArray(rule.command) ? rule.command : [rule.command];
    // Match the raw string first (so unusual rule names that are themselves
    // path-qualified still work as written), then fall back to comparing
    // normalized basenames, so a rule written as `command: rm` also catches
    // path-qualified or differently-cased invocations of the exact same
    // binary, e.g. "/bin/rm", "./rm", or "RM.EXE" on Windows. This keeps a
    // rule from silently failing to match (and falling through to the
    // policy default) just because of how the command happened to be
    // spelled on argv[0].
    const normalizedCommand = normalizeCommandForMatch(command);
    const matches = names.some((name) => name === command || normalizeCommandForMatch(name) === normalizedCommand);
    if (!matches) return false;
  }
  if (rule.command_pattern !== undefined) {
    // Note: unlike `command`, this is tested against the raw command string
    // exactly as given (no basename/path normalization), so a pattern like
    // "^rm$" will not match "/bin/rm". Write the pattern to account for a
    // possible path prefix (e.g. "(^|/)rm$") if that matters for your rule.
    if (!new RegExp(rule.command_pattern).test(command)) return false;
  }
  if (rule.args_pattern !== undefined) {
    if (!new RegExp(rule.args_pattern).test(commandLine)) return false;
  }
  if (rule.cwd_glob !== undefined) {
    const normalizedCwd = cwd.replace(/\\/g, "/");
    if (!minimatch(normalizedCwd, rule.cwd_glob, { dot: true })) return false;
  }
  return true;
}
