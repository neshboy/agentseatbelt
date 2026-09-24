#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { initCommand } from "./init";
import { runCommand } from "./run";
import { verifyLogCommand } from "./verifyLogCommand";

const DEFAULT_POLICY_PATH = ".agentseatbelt/policy.yaml";
const DEFAULT_LOG_PATH = ".agentseatbelt/audit.log.jsonl";

const HELP = `AgentSeatbelt - policy-enforced command wrapper for AI coding agents

Usage:
  agentseatbelt run [--policy <path>] [--log <path>] -- <command> [args...]
  agentseatbelt verify-log [<path>]
  agentseatbelt init [--force]
  agentseatbelt --help
  agentseatbelt --version

Defaults:
  policy file : ${DEFAULT_POLICY_PATH}
  audit log   : ${DEFAULT_LOG_PATH}

Examples:
  agentseatbelt init
  agentseatbelt run -- git status
  agentseatbelt run --policy .agentseatbelt/policy.yaml -- npm install
  agentseatbelt verify-log .agentseatbelt/audit.log.jsonl
`;

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const sub = argv[0];

  if (sub === "--help" || sub === "-h") {
    console.log(HELP);
    return 0;
  }
  if (sub === "--version" || sub === "-v") {
    const pkgPath = join(__dirname, "..", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version: string };
    console.log(pkg.version);
    return 0;
  }
  if (sub === undefined) {
    console.log(HELP);
    return 2;
  }

  switch (sub) {
    case "run": {
      const rest = argv.slice(1);
      const sepIndex = rest.indexOf("--");
      if (sepIndex === -1) {
        console.error("agentseatbelt run: missing '--' separator before the command to run.");
        console.error("Usage: agentseatbelt run [--policy <path>] [--log <path>] -- <command> [args...]");
        return 2;
      }
      const options = rest.slice(0, sepIndex);
      const commandParts = rest.slice(sepIndex + 1);
      if (commandParts.length === 0) {
        console.error("agentseatbelt run: no command given after '--'.");
        return 2;
      }

      let policyPath = DEFAULT_POLICY_PATH;
      let logPath = DEFAULT_LOG_PATH;
      for (let i = 0; i < options.length; i++) {
        if (options[i] === "--policy") {
          policyPath = options[++i];
        } else if (options[i] === "--log") {
          logPath = options[++i];
        } else {
          console.error(`agentseatbelt run: unknown option '${options[i]}'.`);
          return 2;
        }
      }

      const [command, ...cmdArgs] = commandParts;
      return runCommand({ command, args: cmdArgs, cwd: process.cwd(), policyPath, logPath });
    }
    case "verify-log": {
      const logPath = argv[1] ?? DEFAULT_LOG_PATH;
      return verifyLogCommand(logPath);
    }
    case "init": {
      const force = argv.includes("--force");
      return initCommand(force);
    }
    default: {
      console.error(`agentseatbelt: unknown command '${sub}'.\n`);
      console.log(HELP);
      return 2;
    }
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error("agentseatbelt: unexpected error:", err instanceof Error ? err.message : err);
    process.exit(1);
  });
