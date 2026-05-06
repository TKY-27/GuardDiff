import { minimatch } from "minimatch";

export interface IgnoreRule {
  pattern: string;
  negated: boolean;
  directoryOnly: boolean;
  anchored: boolean;
  hasSlash: boolean;
}

const MINIMATCH_OPTIONS = { dot: true, nocase: false, nocomment: true, nonegate: true };

export function parseIgnorePatterns(patterns: Iterable<string>): IgnoreRule[] {
  const rules: IgnoreRule[] = [];

  for (const rawLine of patterns) {
    const rule = parseIgnoreLine(rawLine);
    if (rule) {
      rules.push(rule);
    }
  }

  return rules;
}

export function parseGuardDiffIgnore(content: string): IgnoreRule[] {
  return parseIgnorePatterns(content.split(/\r?\n/));
}

export function isPathIgnored(filePath: string, patterns: Iterable<string> | IgnoreRule[]): boolean {
  const rules = areIgnoreRules(patterns) ? patterns : parseIgnorePatterns(patterns);
  const normalizedPath = normalizePath(filePath);
  let ignored = false;

  for (const rule of rules) {
    if (matchesRule(normalizedPath, rule)) {
      ignored = !rule.negated;
    }
  }

  return ignored;
}

export function filterIgnoredFileDiffs<T extends { filePath: string; originalPath?: string }>(fileDiffs: T[], patterns: Iterable<string>): T[] {
  const rules = parseIgnorePatterns(patterns);
  if (rules.length === 0) {
    return fileDiffs;
  }

  return fileDiffs.filter((fileDiff) => {
    const candidate = fileDiff.filePath || fileDiff.originalPath;
    return candidate ? !isPathIgnored(candidate, rules) : true;
  });
}

function parseIgnoreLine(rawLine: string): IgnoreRule | null {
  let line = trimTrailingSpaces(rawLine);
  if (line.length === 0 || line.startsWith("#")) {
    return null;
  }

  if (line.startsWith("\\#")) {
    line = line.slice(1);
  }

  let negated = false;
  if (line.startsWith("\\!")) {
    line = line.slice(1);
  } else if (line.startsWith("!")) {
    negated = true;
    line = line.slice(1);
  }

  if (line.length === 0) {
    return null;
  }

  const directoryOnly = line.endsWith("/");
  const anchored = line.startsWith("/");
  const pattern = normalizePath(line)
    .replace(/^\/+/, "")
    .replace(/\/+$/, "");

  if (pattern.length === 0) {
    return null;
  }

  return {
    pattern,
    negated,
    directoryOnly,
    anchored,
    hasSlash: pattern.includes("/")
  };
}

function matchesRule(filePath: string, rule: IgnoreRule): boolean {
  if (rule.anchored || rule.hasSlash) {
    return matchesAnchoredPattern(filePath, rule);
  }

  return matchesUnanchoredPattern(filePath, rule);
}

function matchesAnchoredPattern(filePath: string, rule: IgnoreRule): boolean {
  if (rule.directoryOnly) {
    return minimatch(filePath, `${rule.pattern}/**`, MINIMATCH_OPTIONS);
  }

  return (
    minimatch(filePath, rule.pattern, MINIMATCH_OPTIONS) ||
    minimatch(filePath, `${rule.pattern}/**`, MINIMATCH_OPTIONS)
  );
}

function matchesUnanchoredPattern(filePath: string, rule: IgnoreRule): boolean {
  const parts = filePath.split("/");
  const basename = parts.at(-1) ?? filePath;
  const parentParts = parts.slice(0, -1);

  if (rule.directoryOnly) {
    return parentParts.some((part) => minimatch(part, rule.pattern, MINIMATCH_OPTIONS));
  }

  if (minimatch(basename, rule.pattern, MINIMATCH_OPTIONS)) {
    return true;
  }

  return parts.some((part, index) => index < parts.length - 1 && minimatch(part, rule.pattern, MINIMATCH_OPTIONS));
}

function trimTrailingSpaces(value: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === " ") {
    let backslashes = 0;
    for (let index = end - 2; index >= 0 && value[index] === "\\"; index -= 1) {
      backslashes += 1;
    }

    if (backslashes % 2 === 1) {
      break;
    }
    end -= 1;
  }

  return value.slice(0, end).replace(/\\ /g, " ");
}

function normalizePath(filePath: string): string {
  return filePath.replaceAll("\\", "/").replace(/^\.\//, "");
}

function areIgnoreRules(patterns: Iterable<string> | IgnoreRule[]): patterns is IgnoreRule[] {
  return Array.isArray(patterns) && (patterns.length === 0 || typeof patterns[0] === "object");
}
