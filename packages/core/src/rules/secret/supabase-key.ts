import type { Finding, Rule, RuleContext } from "../../types/index.js";
import { maskSecret } from "./anthropic-key.js";

const JWT_PREFIX = /eyJhbGciOiJIUzI1NiJ9[A-Za-z0-9._-]+/g;
const CONTEXT_PATTERN = /(supabase|service_role|serviceRole|anonKey|supabaseKey)/i;

export const supabaseKeyRule: Rule = {
  id: "secret/supabase-key",
  title: "Supabase Key Detected",
  category: "secret",
  severity: "critical",
  defaultConfidence: "possible",
  description: "Supabase キーがコードに含まれています。",
  enabled: true,
  ruleVersion: "1.0.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add" || !CONTEXT_PATTERN.test(line.content)) {
          continue;
        }

        for (const match of line.content.matchAll(JWT_PREFIX)) {
          const raw = match[0];
          findings.push({
            ruleId: this.id,
            title: this.title,
            severity: this.severity,
            confidence: this.defaultConfidence,
            category: this.category,
            filePath: ctx.fileDiff.filePath,
            lineStart: line.lineNumber,
            lineEnd: line.lineNumber,
            matchedContent: maskSecret(raw),
            message: "Supabase キーらしき JWT がコードに含まれています。",
            explanation: "特に service role key は RLS を迂回できるため、コミットすると DB 全体の露出につながるおそれがあります。",
            remediation: "公開用 anon key と管理用 key を分離し、管理用 key は絶対にクライアントコードへ入れないでください。",
            docsUrl: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md"
          });
        }
      }
    }
    return findings;
  }
};
