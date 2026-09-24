import { verifyLog } from "./audit";

export const EXIT_TAMPERED = 20;

export function verifyLogCommand(logPath: string): number {
  const result = verifyLog(logPath);
  if (result.ok) {
    console.log(`OK: ${logPath}`);
    console.log(`  ${result.totalEntries} entries verified, hash chain intact.`);
    return 0;
  }
  console.error(`TAMPERED OR INVALID: ${logPath}`);
  console.error(`  ${result.error}`);
  return EXIT_TAMPERED;
}
