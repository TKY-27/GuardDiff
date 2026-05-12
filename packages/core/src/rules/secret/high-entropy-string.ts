import { calculateShannonEntropy } from "../../entropy/shannon.js";
import type { Finding, Rule, RuleContext } from "../../types/index.js";

const MIN_LENGTH = 32;
const MIN_ENTROPY = 4.5;
const CONTEXT_KEYWORDS = [
  "secret",
  "key",
  "token",
  "password",
  "credential",
  "api_key",
  "apikey",
  "access_key",
  "private_key",
  "auth",
  "passwd",
  "pwd"
];
const DUMMY_PATTERNS = [
  /your[-_]?key/i,
  /example/i,
  /placeholder/i,
  /change[-_]?me/i,
  /xxx+/i,
  /\*{4,}/,
  /^[a-f0-9]{32}$/i,
  /localhost/i
];
const TOKEN_PATTERN = /["']([A-Za-z0-9+/_=-]{32,})["']/g;

export const highEntropyStringRule: Rule = {
  id: "secret/high-entropy",
  title: "High-Entropy Secret-Like String Detected",
  category: "secret",
  severity: "medium",
  defaultConfidence: "possible",
  description: "高エントロピー文字列が追加されています。",
  enabled: true,
  ruleVersion: "0.1.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add") {
          continue;
        }

        const lowered = line.content.toLowerCase();
        if (!CONTEXT_KEYWORDS.some((keyword) => lowered.includes(keyword))) {
          continue;
        }

        for (const match of line.content.matchAll(TOKEN_PATTERN)) {
          const candidate = match[1];
          if (!looksSecretLike(candidate)) {
            continue;
          }

          findings.push({
            ruleId: this.id,
            title: this.title,
            severity: "medium",
            confidence: "possible",
            category: this.category,
            filePath: ctx.fileDiff.filePath,
            lineStart: line.lineNumber,
            lineEnd: line.lineNumber,
            matchedContent: maskCandidate(candidate),
            message: "高エントロピーな秘密情報らしき文字列が追加されています。",
            explanation:
              "十分にランダムで長い文字列が秘密情報の文脈で追加される場合、実キーやトークンの直書きである可能性があります。",
            remediation: "環境変数やシークレットマネージャーに移し、必要ならこの行だけ inline suppression を付けてください。",
            docsUrl: "https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md"
          });
        }
      }
    }

    return findings;
  }
};

function looksSecretLike(candidate: string): boolean {
  if (candidate.length < MIN_LENGTH) {
    return false;
  }

  if (!/^[A-Za-z0-9+/_=-]+$/.test(candidate)) {
    return false;
  }

  if (DUMMY_PATTERNS.some((pattern) => pattern.test(candidate))) {
    return false;
  }

  return calculateShannonEntropy(candidate) >= MIN_ENTROPY;
}

function maskCandidate(candidate: string): string {
  return `${candidate.slice(0, 4)}****${candidate.slice(-4)}`;
}
