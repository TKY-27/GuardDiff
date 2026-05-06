import { compareSeverity } from "../engine/policy-evaluator.js";
import type { Finding, ScanResult, Severity } from "../types/index.js";

export interface TerminalReporterOptions {
  verbose?: boolean;
  quiet?: boolean;
  color?: boolean;
  width?: number;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export class TerminalReporter {
  render(result: ScanResult, options: TerminalReporterOptions = {}): string {
    const color = buildColorizer(options);
    const width = getOutputWidth(options);
    const divider = "━".repeat(width);
    const findings = options.verbose ? result.findings : result.findings.filter((finding) => !finding.suppressed);
    const sorted = [...findings].sort((left, right) => compareSeverity(right.severity, left.severity));
    if (options.quiet) {
      if (sorted.length === 0) {
        return "No active findings.";
      }

      return sorted.map((finding) => renderFinding(finding, color, width)).join("\n\n");
    }

    const activeFindings = result.findings.filter((finding) => !finding.suppressed);
    const activeCounts = countBySeverity(activeFindings);
    const firstActiveFinding = activeFindings[0];
    const lines: string[] = [
      `GuardDiff v${result.guarddiffVersion}`,
      "",
      `${renderScanLabel(result.inputType)}... ${result.stats.filesScanned} files, ${result.stats.linesScanned} lines`,
      "",
      divider
    ];

    for (const finding of sorted) {
      lines.push("", renderFinding(finding, color, width), "", divider);
    }

    if (sorted.length === 0) {
      lines.push("", "No active findings.", "", divider);
    }

    lines.push(
      "",
      "Summary:",
      `  ${activeCounts.critical} critical  ${activeCounts.high} high  ${activeCounts.medium} medium  ${activeCounts.low} low`
    );
    if (result.stats.suppressedFindings > 0) {
      lines.push(renderSuppressedSummary(result.stats.suppressedFindings, Boolean(options.verbose)));
    }
    lines.push("", renderPolicyLine(result, activeFindings, color), "");
    lines.push(renderActionLine(result, color));

    if (!result.passed && firstActiveFinding) {
      lines.push("", `To suppress: add  # guarddiff-ignore: ${firstActiveFinding.ruleId}  to the line`);
    }

    return lines.join("\n");
  }
}

function renderFinding(finding: Finding, color: Colorizer, width: number): string {
  const suppressedHint = finding.suppressed ? `  (${formatSuppressReason(finding.suppressReason)})` : "";
  const lines = [
    `  ${renderSeverity(finding.severity, color)}  ${finding.ruleId}${suppressedHint}`,
    `  File: ${finding.filePath}:${finding.lineStart}`,
    "",
    wrapText(finding.message, { firstPrefix: "  ", nextPrefix: "  ", width })
  ];

  if (finding.matchedContent) {
    lines.push("", wrapText(finding.matchedContent, { firstPrefix: "  > ", nextPrefix: "    ", width }));
  }
  if (finding.explanation) {
    lines.push("", "  なぜ危険か:", wrapText(finding.explanation, { firstPrefix: "  ", nextPrefix: "  ", width }));
  }
  if (finding.remediation) {
    lines.push("", "  修正方法:", wrapText(finding.remediation, { firstPrefix: "  ", nextPrefix: "  ", width }));
  }
  if (finding.docsUrl) {
    lines.push("", `  詳細: ${finding.docsUrl}`);
  }

  return lines.join("\n");
}

function renderSeverity(severity: Severity, color: Colorizer): string {
  const label = severity.toUpperCase();
  switch (severity) {
    case "critical":
      return `${color.red("●")} ${color.red(label)}`;
    case "high":
      return `${color.magenta("▲")} ${color.magenta(label)}`;
    case "medium":
      return `${color.yellow("◆")} ${color.yellow(label)}`;
    case "low":
      return `${color.blue("●")} ${color.blue(label)}`;
    case "info":
      return `${color.cyan("i")} ${color.cyan(label)}`;
  }
}

function renderScanLabel(inputType: ScanResult["inputType"]): string {
  switch (inputType) {
    case "staged":
      return "Scanning staged changes";
    case "path":
      return "Scanning path";
    case "stdin":
      return "Scanning stdin diff";
    case "diff":
      return "Scanning diff";
  }
}

function renderPolicyLine(result: ScanResult, activeFindings: Finding[], color: Colorizer): string {
  if (result.passed) {
    return `Policy: ${color.green("PASS")} (no blocking findings detected)`;
  }

  const highestSeverity = activeFindings.sort((left, right) => compareSeverity(right.severity, left.severity))[0]?.severity;
  return `Policy: ${color.red("FAIL")}${highestSeverity ? ` (${highestSeverity} findings detected)` : ""}`;
}

function renderActionLine(result: ScanResult, color: Colorizer): string {
  if (result.passed) {
    return `${color.green("✓")} Passed. No blocking issues found.`;
  }

  return `${color.red("✗")} Blocked. Fix policy-level issues before committing.`;
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0])) as Record<Severity, number>;
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }

  return counts;
}

function wrapText(
  text: string,
  options: {
    firstPrefix: string;
    nextPrefix: string;
    width: number;
  }
): string {
  return text
    .split(/\r?\n/)
    .flatMap((line) => wrapLine(line, options))
    .join("\n");
}

function wrapLine(
  line: string,
  options: {
    firstPrefix: string;
    nextPrefix: string;
    width: number;
  }
): string[] {
  const output: string[] = [];
  let remaining = line;
  let prefix = options.firstPrefix;

  while (remaining.length + prefix.length > options.width) {
    const available = Math.max(20, options.width - prefix.length);
    const breakpoint = findBreakpoint(remaining, available);
    output.push(`${prefix}${remaining.slice(0, breakpoint).trimEnd()}`);
    remaining = remaining.slice(breakpoint).trimStart();
    prefix = options.nextPrefix;
  }

  output.push(`${prefix}${remaining}`);
  return output;
}

function findBreakpoint(text: string, maxLength: number): number {
  const breakpoint = text.lastIndexOf(" ", maxLength);
  if (breakpoint > 0) {
    return breakpoint;
  }

  return maxLength;
}

function formatSuppressReason(reason?: string): string {
  if (!reason) {
    return "suppressed";
  }
  if (reason.startsWith("inline_suppression:")) {
    return "suppressed by inline guarddiff-ignore";
  }

  return `suppressed by ${reason.replaceAll("_", " ")}`;
}

function pluralize(word: string, count: number): string {
  return count === 1 ? word : `${word}s`;
}

function renderSuppressedSummary(count: number, verbose: boolean): string {
  if (verbose) {
    return `  ${count} suppressed ${pluralize("finding", count)} shown because --verbose is enabled`;
  }

  return `  ${count} ${pluralize("finding", count)} suppressed (use -v to show)`;
}

function getOutputWidth(options: TerminalReporterOptions): number {
  return Math.max(40, Math.min(options.width ?? process.stdout.columns ?? 80, 120));
}

type ColorName = "red" | "green" | "yellow" | "blue" | "magenta" | "cyan";
type Colorizer = Record<ColorName, (text: string) => string>;

function buildColorizer(options: TerminalReporterOptions): Colorizer {
  const enabled = options.color !== false && process.env.NO_COLOR === undefined;
  const wrap = (code: number, text: string): string => (enabled ? `\u001B[${code}m${text}\u001B[0m` : text);

  return {
    red: (text) => wrap(31, text),
    green: (text) => wrap(32, text),
    yellow: (text) => wrap(33, text),
    blue: (text) => wrap(34, text),
    magenta: (text) => wrap(35, text),
    cyan: (text) => wrap(36, text)
  };
}
