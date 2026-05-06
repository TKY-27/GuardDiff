import path from "node:path";

import type { Finding, Rule, RuleContext } from "../../types/index.js";

const LIFECYCLE_SCRIPTS = new Set([
  "preinstall",
  "install",
  "postinstall",
  "prepublish",
  "prepublishOnly",
  "prepare",
  "prepack",
  "postpack"
]);

const SCRIPT_LINE_PATTERN = /^\s*"([^"]+)"\s*:\s*"((?:\\.|[^"\\])*)"/;

const DANGEROUS_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /\b(?:curl|wget)\b[^|;&\n]*(?:\|\s*(?:sh|bash|zsh)|[;&]\s*(?:sh|bash|zsh)\b)/i,
    reason: "リモートコードをダウンロードして shell で実行する"
  },
  {
    pattern: /\b(?:sh|bash|zsh)\s+-c\b.*\b(?:curl|wget)\b/i,
    reason: "リモートコードを取得する shell コマンドを実行する"
  },
  {
    pattern: /\bnode\s+-e\b.*\b(?:child_process|execSync|exec|spawnSync|spawn)\b/i,
    reason: "子プロセスを起動できる inline Node.js を実行する"
  },
  {
    pattern: /\b(?:python|python3|ruby|perl)\s+-e\b.*\b(?:system|exec|popen|subprocess)\b/i,
    reason: "コマンド実行可能な inline interpreter code を実行する"
  },
  {
    pattern: /\brm\s+-rf\s+(?:\/|~|\$HOME|\*)\b/i,
    reason: "破壊的な再帰削除を実行する"
  }
];

export const packageJsonDangerousScriptRule: Rule = {
  id: "config/package-json-dangerous-script",
  title: "Dangerous package.json Lifecycle Script",
  category: "config",
  severity: "critical",
  defaultConfidence: "likely",
  description: "package.json lifecycle script が危険なコマンドを実行しています。",
  enabled: true,
  ruleVersion: "1.0.0",
  detect(ctx: RuleContext): Finding[] {
    if (path.basename(ctx.fileDiff.filePath) !== "package.json") {
      return [];
    }

    const findings = detectFromAddedLines(ctx);
    if (findings.length > 0 || !ctx.fileDiff.rawContent || !isWholeFileScan(ctx)) {
      return findings;
    }

    return detectFromPackageJson(ctx);
  }
};

function isWholeFileScan(ctx: RuleContext): boolean {
  return ctx.fileDiff.isNew && ctx.fileDiff.hunks.every((hunk) => hunk.lines.every((line) => line.type === "add"));
}

function detectFromAddedLines(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const hunk of ctx.fileDiff.hunks) {
    for (const line of hunk.lines) {
      if (line.type !== "add") {
        continue;
      }

      const parsed = parseScriptLine(line.content);
      if (!parsed || !LIFECYCLE_SCRIPTS.has(parsed.name)) {
        continue;
      }

      const dangerous = findDangerousPattern(parsed.command);
      if (!dangerous) {
        continue;
      }

      findings.push(buildFinding(ctx, parsed.name, parsed.command, dangerous.reason, line.lineNumber));
    }
  }

  return findings;
}

function detectFromPackageJson(ctx: RuleContext): Finding[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(ctx.fileDiff.rawContent ?? "{}");
  } catch {
    return [];
  }

  if (!isRecord(parsed) || !isRecord(parsed.scripts)) {
    return [];
  }

  const findings: Finding[] = [];
  for (const [name, value] of Object.entries(parsed.scripts)) {
    if (!LIFECYCLE_SCRIPTS.has(name) || typeof value !== "string") {
      continue;
    }

    const dangerous = findDangerousPattern(value);
    if (!dangerous) {
      continue;
    }

    findings.push(buildFinding(ctx, name, value, dangerous.reason, locateScriptLine(ctx.fileDiff.rawContent ?? "", name)));
  }

  return findings;
}

function parseScriptLine(content: string): { name: string; command: string } | null {
  const match = content.match(SCRIPT_LINE_PATTERN);
  if (!match) {
    return null;
  }

  return {
    name: match[1],
    command: decodeJsonString(match[2])
  };
}

function decodeJsonString(value: string): string {
  try {
    return JSON.parse(`"${value}"`) as string;
  } catch {
    return value;
  }
}

function findDangerousPattern(command: string): { reason: string } | null {
  if (/\$\{?[A-Z0-9_]+\}?/.test(command) && !/\b(?:curl|wget|rm\s+-rf|node\s+-e|python3?\s+-e|ruby\s+-e|perl\s+-e)\b/i.test(command)) {
    return null;
  }

  for (const dangerous of DANGEROUS_PATTERNS) {
    if (dangerous.pattern.test(command)) {
      return dangerous;
    }
  }

  return null;
}

function buildFinding(
  ctx: RuleContext,
  scriptName: string,
  command: string,
  reason: string,
  lineNumber: number
): Finding {
  return {
    ruleId: packageJsonDangerousScriptRule.id,
    title: packageJsonDangerousScriptRule.title,
    severity: "critical",
    confidence: "likely",
    category: packageJsonDangerousScriptRule.category,
    filePath: ctx.fileDiff.filePath,
    lineStart: lineNumber,
    lineEnd: lineNumber,
    matchedContent: `"${scriptName}": "${command.slice(0, 120)}"`,
    message: `package.json の ${scriptName} script が危険なコマンドを実行します。`,
    explanation:
      `npm lifecycle script は install や publish のタイミングで自動実行されます。この script は ${reason}ため、` +
      "依存先や開発者環境で任意コード実行につながる可能性があります。",
    remediation:
      "lifecycle script からリモートコード実行や inline shell 実行を取り除き、必要な処理はレビュー可能なローカルスクリプトへ分離してください。",
    docsUrl: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md"
  };
}

function locateScriptLine(content: string, scriptName: string): number {
  const pattern = new RegExp(`^\\s*"${escapeRegExp(scriptName)}"\\s*:`, "m");
  const index = content.split(/\r?\n/).findIndex((line) => pattern.test(line));
  return index >= 0 ? index + 1 : 1;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
