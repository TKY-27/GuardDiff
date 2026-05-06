import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { Readable } from "node:stream";

import { afterEach, describe, expect, it, vi } from "vitest";

import { runDiffCommand } from "./diff.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../");

describe("runDiffCommand", () => {
  const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

  afterEach(() => {
    writeSpy.mockClear();
  });

  it("reports a leaked api key from a patch file", async () => {
    const code = await runDiffCommand({
      file: path.join(repoRoot, "examples/leaked-api-key/openai.diff"),
      format: "json"
    });

    expect(code).toBe(1);
    const output = writeSpy.mock.calls.at(-1)?.[0];
    expect(String(output)).toContain("secret/openai-key");
  });

  it("reports a leaked api key from stdin", async () => {
    const patch = `diff --git a/src/openai.ts b/src/openai.ts
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/openai.ts
@@ -0,0 +1 @@
+export const client = new OpenAI({ apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456" });
`;

    const code = await runDiffCommand(
      {
        stdin: true,
        format: "json"
      },
      Readable.from([patch])
    );

    expect(code).toBe(1);
    const output = writeSpy.mock.calls.at(-1)?.[0];
    expect(String(output)).toContain("secret/openai-key");
  });
});
