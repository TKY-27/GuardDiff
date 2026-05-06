import type { ScanResult } from "../types/index.js";

export class JsonReporter {
  render(result: ScanResult): string {
    return JSON.stringify(
      {
        version: "2.0",
        result
      },
      null,
      2
    );
  }
}
