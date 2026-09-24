import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export const DEFAULT_POLICY_PATH = ".agentseatbelt/policy.yaml";

const STARTER_POLICY = `# AgentSeatbelt policy file
#
# Rules are evaluated top-to-bottom; the FIRST matching rule wins.
# If no rule matches, the top-level 'default' action applies.
#
# action: allow | deny | ask
#   allow - run the command immediately
#   deny  - never run the command; logged and reported as denied
#   ask   - prompt for a real y/n confirmation before running
#           (interactive terminals only; if there is no TTY this
#           fails closed and denies automatically)
#
# Match conditions on a rule (all given conditions must hold):
#   command:         exact command name, or list of names, e.g. [git, npm]
#   command_pattern: regex tested against the command name
#   args_pattern:    regex tested against "<command> <args...>" joined
#                     with spaces, e.g. to catch "rm -rf" or "sudo"
#   cwd_glob:        glob tested against the working directory the
#                     command would run in

version: 1

# Fail closed: anything not explicitly allowed below requires confirmation.
default: ask

rules:
  - description: "allow common read-only / everyday commands"
    command: [git, ls, pwd, cat, node, echo]
    action: allow

  - description: "never allow sudo"
    command: sudo
    action: deny

  - description: "never allow recursive force delete (rm -rf / rm -fr)"
    command: rm
    args_pattern: "-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r"
    action: deny
`;

export function initCommand(force: boolean): number {
  const path = DEFAULT_POLICY_PATH;
  if (existsSync(path) && !force) {
    console.error(`agentseatbelt: ${path} already exists. Use --force to overwrite.`);
    return 1;
  }
  const dir = dirname(path);
  if (dir && dir !== ".") {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(path, STARTER_POLICY, "utf8");
  console.log(`agentseatbelt: wrote starter policy to ${path}`);
  return 0;
}
