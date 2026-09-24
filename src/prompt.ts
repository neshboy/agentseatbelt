import { createInterface } from "node:readline";

/** True only when both stdin and stdout are real interactive terminals. */
export function isInteractive(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY);
}

/**
 * Ask the user a real y/n question on the real terminal. Anything other
 * than an explicit "y"/"yes" (case-insensitive) is treated as "no" —
 * ambiguous or empty input never silently approves.
 */
export function confirm(question: string): Promise<boolean> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      const normalized = answer.trim().toLowerCase();
      resolve(normalized === "y" || normalized === "yes");
    });
  });
}
