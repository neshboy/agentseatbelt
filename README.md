# AgentSeatbelt

<img src="docs/assets/demo.svg" alt="agentseatbelt denying a real rm -rf command and verifying its audit log" width="700" />

<sub>A real recorded terminal session - real allowed command, real denied command, real audit-log verification.</sub>

**AgentSeatbelt puts a policy check between your AI coding agent and your shell.** Instead of letting an
agent framework run arbitrary commands directly, it runs them through AgentSeatbelt, which checks each
command against a declarative allow/deny policy file *before* executing anything, and writes a
tamper-evident, hash-chained audit log of every decision — allowed, denied, or asked-for-confirmation.

No command runs before AgentSeatbelt decides it should. Every decision is logged in a chain you can verify
after the fact. That's the whole pitch.

## What it is NOT (read this before you rely on it)

AgentSeatbelt is **process-level policy enforcement at the point where the agent chooses to shell out
through this wrapper.** It is **not a kernel-level sandbox**. It cannot:

- stop a determined, uncooperative process from doing anything once it has actually started running (e.g.
  it cannot stop a process it allowed from later calling something the policy would have denied);
- contain a command that doesn't go through AgentSeatbelt in the first place — if your agent framework has
  another way to execute code (a raw shell tool, an eval, a different subprocess call) that doesn't route
  through `agentseatbelt run`, this provides zero protection for that path;
- see inside a command to know what it will really do — a rule like `command: git` allows *all* of git,
  including `git push --force` or `git clean -fdx`, unless you write a more specific rule.

Think of it as a seatbelt, not a cage: it's a policy checkpoint and an audit trail for the commands an
agent runs *through it*, enforced with ordinary OS process privileges. It is only as good as the policy you
write and the discipline of routing every shell-out through it. Treat it as one layer in a defense-in-depth
setup, not a substitute for running agents in an actually sandboxed/contained environment (containers, VMs,
restricted OS users, etc.) when the stakes call for one.

## Install / quick start

```bash
git clone <this-repo>
cd agentseatbelt
npm install
npm run build
npm link   # optional: puts `agentseatbelt` on your PATH globally
```

Scaffold a starter policy in your project:

```bash
agentseatbelt init
# wrote starter policy to .agentseatbelt/policy.yaml
```

Run a command through it:

```bash
agentseatbelt run -- git status
```

Wire it into an agent framework by replacing whatever shells out (`exec`, `subprocess.run`,
`child_process.spawn`, ...) with a call to `agentseatbelt run -- <command> [args...]`.

## Example policy

Policies live in YAML (default path: `.agentseatbelt/policy.yaml`, override with `--policy`). Rules are
checked top-to-bottom; the **first matching rule wins**. If nothing matches, the top-level `default` action
applies — the recommended and built-in default is `deny`/`ask`, never a silent allow.

```yaml
version: 1
default: ask   # anything not explicitly covered below requires confirmation

rules:
  - description: "allow read-only git and everyday commands"
    command: [git, ls, pwd, cat, node, echo]
    action: allow

  - description: "never allow sudo"
    command: sudo
    action: deny

  - description: "never allow recursive force delete (rm -rf / rm -fr)"
    command: rm
    args_pattern: "-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r"
    action: deny

  - description: "only touch the project sandbox directory"
    cwd_glob: "/home/*/sandboxes/**"
    action: allow
```

Match conditions available on a rule (all given conditions on a rule must hold for it to match):

| field             | meaning                                                              |
|-------------------|-----------------------------------------------------------------------|
| `command`         | exact command name, or a list of names, e.g. `[git, npm]`             |
| `command_pattern` | regex tested against the command name                                 |
| `args_pattern`    | regex tested against `"<command> <args...>"` joined with spaces       |
| `cwd_glob`        | glob tested against the working directory the command would run in   |
| `action`          | `allow`, `deny`, or `ask`                                              |

`ask` prompts for a real y/n confirmation on an interactive terminal. **If there is no interactive TTY
(the common case for an unattended agent), `ask` denies automatically — it never silently allows on
ambiguity.** This is a deliberate fail-closed design choice.

## Exit codes

`agentseatbelt run` passes through the *wrapped command's own real exit code* whenever the command actually
runs (allowed, or `ask` approved) — so `0` means the command ran and succeeded, and any other code is
whatever the command itself returned. When AgentSeatbelt decides the command should never run at all, it
uses one of its own reserved codes so you can tell "AgentSeatbelt stopped this" apart from "the tool ran
and failed":

| exit code | meaning                                                                    |
|-----------|-----------------------------------------------------------------------------|
| `0`       | command ran; its own exit code was `0`                                     |
| *(other)* | command ran; its own exit code passed through unchanged                    |
| `2`       | AgentSeatbelt CLI usage error (bad invocation) — command never ran         |
| `10`      | denied by policy — command never ran                                       |
| `11`      | `ask` rule, user declined confirmation — command never ran                 |
| `12`      | `ask` rule, no interactive TTY available, failed closed — command never ran |
| `13`      | policy file missing or invalid — command never ran                         |
| `20`      | (`verify-log` only) audit log is missing, invalid, or tampered             |
| `127`     | command name could not be found/spawned by the OS                          |

The audit log is the authoritative record of *why* — always check it when a code alone isn't enough,
since a wrapped command could in principle exit with the same number AgentSeatbelt reserves for a denial.

## The audit log

Every decision — allow, deny, or ask (approved or declined) — is appended as one line of JSON to an
append-only log (default path: `.agentseatbelt/audit.log.jsonl`, override with `--log`). Each entry embeds
the SHA-256 hash of the *previous* entry, so the file forms a hash chain: editing, deleting, or reordering
any past entry breaks the chain from that point forward.

Real example, generated by actually running the policy above:

```bash
$ agentseatbelt run --policy policy.yaml --log audit.log.jsonl -- echo "hello from an allowed command"
hello from an allowed command

$ agentseatbelt run --policy policy.yaml --log audit.log.jsonl -- rm -rf ./build-output
agentseatbelt: DENIED - rm -rf ./build-output
  reason: matched never allow recursive force delete (rm -rf / rm -fr)

$ agentseatbelt run --policy policy.yaml --log audit.log.jsonl -- sudo apt-get install foo
agentseatbelt: DENIED - sudo apt-get install foo
  reason: matched never allow sudo

$ cat audit.log.jsonl
{"seq":1,"timestamp":"2026-09-24T07:09:31.967Z","cwd":"/home/user/my-project","command":"echo","args":["hello from an allowed command"],"decision":"allow","reason":"matched allow read-only git and everyday commands","exitCode":0,"prevHash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"c504637e18127455b5641ce6d6dd6b0f6b30390048eeb7c392ae8c96e15e427a"}
{"seq":2,"timestamp":"2026-09-24T07:09:32.457Z","cwd":"/home/user/my-project","command":"rm","args":["-rf","./build-output"],"decision":"deny","reason":"matched never allow recursive force delete (rm -rf / rm -fr)","exitCode":null,"prevHash":"c504637e18127455b5641ce6d6dd6b0f6b30390048eeb7c392ae8c96e15e427a","hash":"ba74c57e4c046f8ba287f8b8208dfe276b1f2129dcf643efa3694f6bebd48175"}
{"seq":3,"timestamp":"2026-09-24T07:09:32.948Z","cwd":"/home/user/my-project","command":"sudo","args":["apt-get","install","foo"],"decision":"deny","reason":"matched never allow sudo","exitCode":null,"prevHash":"ba74c57e4c046f8ba287f8b8208dfe276b1f2129dcf643efa3694f6bebd48175","hash":"a83e520357e6b8bf6db0bd982332becda6bba5d6dd84d11292f31a04f771e0e1"}

$ agentseatbelt verify-log audit.log.jsonl
OK: audit.log.jsonl
  3 entries verified, hash chain intact.
```

Now hand-edit the first line (e.g. to hide the fact that a command was ever run) and re-verify:

```bash
$ agentseatbelt verify-log audit.log.jsonl
TAMPERED OR INVALID: audit.log.jsonl
  Tampered entry detected at line 1 (seq 1): stored hash does not match the recomputed hash.
```

(exits with code `20`.) This is a real, tested behavior — see `test/audit.test.ts` and `test/cli.test.ts`
for the automated versions of exactly this scenario, including a "deleted entry" tamper (chain gap) case.

Note that this hash chain proves **the log wasn't edited after being written by this tool** — it does not
by itself prove which commands actually ran outside of what this tool observed (see Limitations above).

## CLI reference

```
agentseatbelt run [--policy <path>] [--log <path>] -- <command> [args...]
agentseatbelt verify-log [<path>]
agentseatbelt init [--force]
agentseatbelt --help
agentseatbelt --version
```

Defaults: policy file `.agentseatbelt/policy.yaml`, audit log `.agentseatbelt/audit.log.jsonl`.

## Development

```bash
npm install
npm run build     # compile TypeScript to dist/
npm test          # builds, then runs the vitest suite against the built CLI
```

The test suite (`test/audit.test.ts`, `test/policy.test.ts`, `test/cli.test.ts`) covers:

- an allowed command actually spawning, with its real stdout and real exit code passed through;
- a denied command never spawning, verified by checking that a file the command would have written does
  not exist;
- an `ask` rule failing closed (denying) when there is no interactive TTY;
- the hash-chained audit log being written correctly and `verify-log` both confirming a clean chain and
  detecting hand-edited/tampered and entry-deleted logs.

## Limitations, spelled out

- **Not a sandbox.** This enforces policy at the moment a command is *launched* through AgentSeatbelt. It
  has no way to constrain what an allowed process does once it's running (filesystem access, network
  access, further subprocesses it spawns directly instead of through this wrapper, etc.).
  For real containment, pair this with OS-level sandboxing (containers, restricted users, VMs).
  Alternatives to consider for that kind of enforcement include a kernel-level sandbox, `chroot`, or
  Linux namespaces/`seccomp`.
  AgentSeatbelt's job is the decision-and-audit layer sitting in front of that, not a replacement for it.
- **Only as good as the policy.** A permissive rule (`command: git` with no `args_pattern`) allows every
  subcommand and flag of that binary. Policy authors are responsible for writing rules that actually
  match their threat model — AgentSeatbelt gives you the mechanism, not a pre-built complete policy.
- **`ask` requires the agent to actually be attended.** In a fully unattended pipeline, `ask` behaves
  identically to `deny` (fail closed) rather than blocking forever, which is the safe choice but means
  `ask` rules are only useful when a human is at the keyboard.
- **Exit code reservation is a convention, not a guarantee.** Because a wrapped command's own exit code is
  passed straight through, it can in theory collide with a reserved AgentSeatbelt code (e.g. a script that
  itself exits `10`). The audit log entry, not the process exit code, is the authoritative record of what
  AgentSeatbelt actually decided.
- **No built-in policy-file integrity protection.** The audit *log* is hash-chained; the *policy file*
  itself is not signed and is only as trustworthy as the filesystem permissions protecting it.

## License

MIT, see [LICENSE](./LICENSE).
