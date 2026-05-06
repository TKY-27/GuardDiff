import type { FileDiff, Finding, GuardDiffConfig, Rule, RuleContext } from "../types/index.js";

export class ScanEngine {
  constructor(
    private readonly rules: Rule[],
    private readonly config: GuardDiffConfig
  ) {}

  async scan(fileDiffs: FileDiff[]): Promise<Finding[]> {
    const results = await Promise.all(
      fileDiffs.map(async (fileDiff) => {
        const findingsByRule = await Promise.all(
          this.rules
            .filter((rule) => rule.enabled)
            .filter((rule) => this.shouldRunRule(rule, fileDiff))
            .map(async (rule) => {
              const ctx: RuleContext = { fileDiff, config: this.config };
              try {
                return rule.detect(ctx);
              } catch (error) {
                const message = error instanceof Error ? error.message : String(error);
                console.error(`Rule ${rule.id} failed: ${message}`);
                return [];
              }
            })
        );

        return findingsByRule.flat();
      })
    );

    return results.flat();
  }

  private shouldRunRule(rule: Rule, fileDiff: FileDiff): boolean {
    if (!fileDiff.isBinary) {
      return true;
    }

    return rule.id === "config/env-committed";
  }
}
