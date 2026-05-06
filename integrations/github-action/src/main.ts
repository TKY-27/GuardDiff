import process from "node:process";
import { runAction } from "./lib.js";

runAction().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`GuardDiff action failed: ${message}\n`);
  process.exitCode = 1;
});
