import { JsonReporter, MarkdownReporter, SarifReporter, TerminalReporter, builtInRules } from "@guarddiff/core";
import type { Rule, ScanResult } from "@guarddiff/core";

export type OutputFormat = "terminal" | "json" | "sarif" | "markdown";

export function renderResult(
  result: ScanResult,
  format: OutputFormat,
  options: { color?: boolean; quiet?: boolean; verbose?: boolean } = {},
  rules: Rule[] = builtInRules
): string {
  switch (format) {
    case "json":
      return new JsonReporter().render(result);
    case "sarif":
      return new SarifReporter().render(result, rules);
    case "markdown":
      return new MarkdownReporter().render(result);
    case "terminal":
    default:
      return new TerminalReporter().render(result, options);
  }
}
