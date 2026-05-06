import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
      include: ["src/engine/**/*.ts", "src/parser/**/*.ts", "src/entropy/shannon.ts"],
      exclude: ["src/**/*.test.ts", "src/test-helpers.ts"],
      thresholds: {
        "src/engine/**/*.ts": {
          lines: 80
        },
        "src/parser/**/*.ts": {
          lines: 80
        },
        "src/entropy/shannon.ts": {
          lines: 95
        }
      }
    }
  }
});
