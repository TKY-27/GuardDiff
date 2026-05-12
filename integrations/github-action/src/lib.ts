import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import {
  DEFAULT_CONFIG,
  DiffParser,
  MarkdownReporter,
  SarifReporter,
  TerminalReporter,
  attachRawContent,
  buildRuleSet,
  parseGuardDiffConfig,
  runScan,
  withFailOnOverride,
  type GuardDiffConfig,
  type Rule,
  type RuleCategory,
  type ScanResult,
  type Severity
} from "../../../packages/core/src/index.js";

const ACTION_VERSION = "0.1.0";
const COMMENT_MARKER = "<!-- guarddiff-report -->";
const CONFIG_NAME = "guarddiff.config.yaml";
const IGNORE_NAME = ".guarddiffignore";
const DEFAULT_SARIF_FILE = "guarddiff-results.sarif";
const DEFAULT_RULE_REGISTRY_URL = "https://raw.githubusercontent.com/TKY-27/GuardDiff/main/docs/site/rules/manifest.json";
const RULE_UPDATE_TIMEOUT_MS = 3000;
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const CATEGORIES: RuleCategory[] = ["secret", "diff", "config", "permission", "mcp"];

interface RuleUpdateNotice {
  id: string;
  type: "new" | "updated";
  currentVersion?: string;
  latestVersion: string;
  title?: string;
  docsUrl?: string;
  summary?: string;
}

export async function runAction(): Promise<void> {
  const failOn = parseSeverityInput(readInput("fail-on") || "high");
  const shouldPostComment = parseBooleanInput(readInput("post-comment"), true);
  const shouldWriteSarif = parseBooleanInput(readInput("sarif"), false);
  const shouldAnnotate = parseBooleanInput(readInput("annotations"), true);
  const shouldCheckRuleUpdates = parseBooleanInput(readInput("rules-update-check"), process.env.CI === "true");
  const allowRulePacks = parseBooleanInput(readInput("allow-rule-packs"), false);
  const allowInlineSuppressions = parseBooleanInput(readInput("allow-inline-suppressions"), false);
  const rulesRegistryUrl = readInput("rules-registry-url") || DEFAULT_RULE_REGISTRY_URL;
  const sarifFile = readInput("sarif-file") || DEFAULT_SARIF_FILE;
  const configInput = readInput("config") || CONFIG_NAME;
  const workingDirectory = process.cwd();

  if (!isInsideGitWorkTree(workingDirectory)) {
    throw new Error("GitHub Action must run inside a git work tree.");
  }

  const baseRef = resolveBaseRef();
  const trustedConfigRef = resolvePullRequestBaseSha();
  const { config, rootDir } = loadConfig(workingDirectory, configInput, trustedConfigRef);
  const effectiveConfig = withFailOnOverride(config, failOn);
  assertRulePacksAllowed(effectiveConfig, allowRulePacks);
  const rules = buildRuleSet(effectiveConfig, allowRulePacks ? await loadRulePacks(effectiveConfig, rootDir) : []);
  const diff = getDiffAgainstBase(rootDir, baseRef);
  const fileDiffs = enrichDiffsWithContent(new DiffParser().parse(diff), rootDir);
  const result = await runScan({
    fileDiffs,
    config: effectiveConfig,
    inputType: "diff",
    ignorePaths: loadIgnorePatterns(rootDir, workingDirectory, trustedConfigRef),
    suppressions: {
      inline: allowInlineSuppressions
    },
    rules,
    version: ACTION_VERSION
  });
  const ruleUpdateNotices = shouldCheckRuleUpdates ? await checkRuleUpdates(rules, rulesRegistryUrl) : [];

  process.stdout.write(`${new TerminalReporter().render(result)}\n`);
  emitRuleUpdateNotices(ruleUpdateNotices);

  if (shouldAnnotate) {
    annotateFindings(result);
  }

  if (shouldWriteSarif) {
    const sarifPath = path.resolve(rootDir, sarifFile);
    fs.mkdirSync(path.dirname(sarifPath), { recursive: true });
    fs.writeFileSync(sarifPath, new SarifReporter().render(result, rules), "utf8");
  }

  setOutputs(result, ruleUpdateNotices);

  if (shouldPostComment) {
    await upsertPullRequestComment(result, ruleUpdateNotices);
  }

  if (!result.passed) {
    process.exitCode = 1;
  }
}

function assertRulePacksAllowed(config: GuardDiffConfig, allowRulePacks: boolean): void {
  const packNames = config.rules?.packs ?? [];
  if (allowRulePacks || packNames.length === 0) {
    return;
  }

  throw new Error(
    "External GuardDiff rule packs are disabled in the GitHub Action by default because they execute code from the checked-out repository. Set allow-rule-packs: true only for trusted branches."
  );
}

function readInput(name: string): string {
  const key = `INPUT_${name.replace(/ /g, "_").toUpperCase()}`;
  const normalizedKey = key.replace(/-/g, "_");
  return (process.env[key] ?? process.env[normalizedKey] ?? "").trim();
}

function parseBooleanInput(value: string, defaultValue: boolean): boolean {
  if (value.length === 0) {
    return defaultValue;
  }

  return value.toLowerCase() === "true";
}

function parseSeverityInput(value: string): Severity {
  if (!SEVERITIES.includes(value as Severity)) {
    throw new Error(`invalid fail-on severity: ${value}`);
  }

  return value as Severity;
}

function loadConfig(startDir: string, explicitPath?: string, trustedRef?: string): { config: GuardDiffConfig; rootDir: string } {
  if (trustedRef) {
    const requestedPath = explicitPath ?? CONFIG_NAME;
    const resolved = path.resolve(startDir, requestedPath);
    const relativePath = path.relative(startDir, resolved);
    const content = readRepoFileAtRef(startDir, trustedRef, relativePath);

    if (content !== undefined) {
      return {
        config: parseGuardDiffConfig(content),
        rootDir: path.dirname(resolved)
      };
    }

    return {
      config: DEFAULT_CONFIG,
      rootDir: startDir
    };
  }

  if (explicitPath) {
    const resolved = path.resolve(startDir, explicitPath);
    if (fs.existsSync(resolved)) {
      return {
        config: parseGuardDiffConfig(fs.readFileSync(resolved, "utf8")),
        rootDir: path.dirname(resolved)
      };
    }
  }

  const configPath = findUp(startDir, CONFIG_NAME);
  if (!configPath) {
    return {
      config: DEFAULT_CONFIG,
      rootDir: startDir
    };
  }

  return {
    config: parseGuardDiffConfig(fs.readFileSync(configPath, "utf8")),
    rootDir: path.dirname(configPath)
  };
}

function loadIgnorePatterns(rootDir: string, repoDir = rootDir, trustedRef?: string): string[] {
  const ignorePath = path.join(rootDir, IGNORE_NAME);
  if (trustedRef) {
    const content = readRepoFileAtRef(repoDir, trustedRef, path.relative(repoDir, ignorePath));
    return content?.split(/\r?\n/) ?? [];
  }

  if (!fs.existsSync(ignorePath)) {
    return [];
  }

  return fs
    .readFileSync(ignorePath, "utf8")
    .split(/\r?\n/);
}

function readRepoFileAtRef(repoDir: string, ref: string, relativePath: string): string | undefined {
  const safePath = normalizeRepoRelativePath(relativePath);
  if (!safePath) {
    return undefined;
  }

  try {
    return execFileSync("git", ["show", `${ref}:${safePath}`], {
      cwd: repoDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    });
  } catch {
    return undefined;
  }
}

function normalizeRepoRelativePath(relativePath: string): string | undefined {
  const normalized = relativePath.replaceAll("\\", "/");
  if (
    normalized.length === 0 ||
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("/") ||
    normalized.startsWith("../") ||
    normalized.includes("/../")
  ) {
    return undefined;
  }

  return normalized;
}

async function loadRulePacks(config: GuardDiffConfig, rootDir: string): Promise<Rule[]> {
  const packNames = config.rules?.packs ?? [];
  if (packNames.length === 0) {
    return [];
  }

  const requireFromRoot = createRequire(path.join(rootDir, "guarddiff.config.yaml"));
  const rules: Rule[] = [];

  for (const packName of packNames) {
    const resolvedPath = requireFromRoot.resolve(packName);
    const module = await import(pathToFileURL(resolvedPath).href);
    rules.push(...extractRules(module, packName));
  }

  return rules;
}

function extractRules(module: unknown, packName: string): Rule[] {
  const candidate = getExportedRules(module);
  if (!Array.isArray(candidate)) {
    throw new Error(`rule pack ${packName} must export a rules array`);
  }

  for (const rule of candidate) {
    assertRule(rule, packName);
  }

  return candidate;
}

function getExportedRules(module: unknown): unknown {
  if (!isRecord(module)) {
    return undefined;
  }

  if (Array.isArray(module.rules)) {
    return module.rules;
  }

  if (Array.isArray(module.default)) {
    return module.default;
  }

  if (isRecord(module.default) && Array.isArray(module.default.rules)) {
    return module.default.rules;
  }

  return undefined;
}

function assertRule(rule: unknown, packName: string): asserts rule is Rule {
  if (!isRecord(rule)) {
    throw new Error(`rule pack ${packName} exported a non-object rule`);
  }

  if (
    typeof rule.id !== "string" ||
    typeof rule.title !== "string" ||
    !CATEGORIES.includes(rule.category as RuleCategory) ||
    !SEVERITIES.includes(rule.severity as Severity) ||
    typeof rule.defaultConfidence !== "string" ||
    typeof rule.description !== "string" ||
    typeof rule.enabled !== "boolean" ||
    typeof rule.ruleVersion !== "string" ||
    typeof rule.detect !== "function"
  ) {
    throw new Error(`rule pack ${packName} exported invalid rule metadata`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function findUp(startDir: string, fileName: string): string | undefined {
  let current = path.resolve(startDir);

  while (true) {
    const candidate = path.join(current, fileName);
    if (fs.existsSync(candidate)) {
      return candidate;
    }

    if (fs.existsSync(path.join(current, "package.json"))) {
      return undefined;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return undefined;
    }

    current = parent;
  }
}

function isInsideGitWorkTree(cwd: string): boolean {
  try {
    const output = execFileSync("git", ["rev-parse", "--is-inside-work-tree"], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
    return output === "true";
  } catch {
    return false;
  }
}

function getDiffAgainstBase(cwd: string, baseRef: string): string {
  try {
    return execFileSync("git", ["diff", `${baseRef}...HEAD`, "--no-ext-diff", "--binary", "--unified=3"], {
      cwd,
      encoding: "utf8"
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`failed to read diff against ${baseRef}: ${message}`);
  }
}

function enrichDiffsWithContent(fileDiffs: ReturnType<DiffParser["parse"]>, rootDir: string) {
  return attachRawContent(fileDiffs, rootDir, (absolutePath) => {
    if (!fs.existsSync(absolutePath)) {
      return undefined;
    }

    const buffer = fs.readFileSync(absolutePath);
    if (buffer.includes(0)) {
      return undefined;
    }

    return buffer.toString("utf8");
  });
}

function resolveBaseRef(): string {
  const event = readEventPayload();
  const pullRequestBaseSha = event.pull_request?.base?.sha;

  if (typeof pullRequestBaseSha === "string" && pullRequestBaseSha.length > 0) {
    return pullRequestBaseSha;
  }

  if (process.env.GITHUB_BASE_REF) {
    return process.env.GITHUB_BASE_REF;
  }

  return "HEAD~1";
}

function resolvePullRequestBaseSha(): string | undefined {
  const event = readEventPayload();
  const pullRequestBaseSha = event.pull_request?.base?.sha;

  if (typeof pullRequestBaseSha === "string" && /^[0-9a-f]{40}$/i.test(pullRequestBaseSha)) {
    return pullRequestBaseSha;
  }

  return undefined;
}

function readEventPayload(): Record<string, any> {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath || !fs.existsSync(eventPath)) {
    return {};
  }

  return JSON.parse(fs.readFileSync(eventPath, "utf8"));
}

function setOutputs(result: ScanResult, ruleUpdateNotices: RuleUpdateNotice[] = []): void {
  const activeFindings = result.findings.filter((finding) => !finding.suppressed);
  const criticalCount = activeFindings.filter((finding) => finding.severity === "critical").length;

  writeOutput("findings-count", String(activeFindings.length));
  writeOutput("critical-count", String(criticalCount));
  writeOutput("rule-update-count", String(ruleUpdateNotices.length));
  writeOutput("passed", String(result.passed));
}

function annotateFindings(result: ScanResult): void {
  for (const finding of result.findings.filter((entry) => !entry.suppressed)) {
    const level = annotationLevel(finding.severity);
    const title = escapeCommandProperty(`${finding.ruleId}: ${finding.title}`);
    const file = escapeCommandProperty(finding.filePath);
    const line = Math.max(1, finding.lineStart);
    const endLine = Math.max(line, finding.lineEnd);
    const details = [
      finding.message,
      `Severity: ${finding.severity}`,
      `Confidence: ${finding.confidence}`,
      `Remediation: ${finding.remediation}`
    ];
    if (finding.docsUrl) {
      details.push(`Docs: ${finding.docsUrl}`);
    }
    const message = escapeCommandData(details.join("\n"));
    process.stdout.write(`::${level} file=${file},line=${line},endLine=${endLine},title=${title}::${message}\n`);
  }
}

function annotationLevel(severity: Severity): "error" | "warning" | "notice" {
  if (severity === "critical" || severity === "high") {
    return "error";
  }
  if (severity === "medium") {
    return "warning";
  }
  return "notice";
}

function escapeCommandData(value: string): string {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

function escapeCommandProperty(value: string): string {
  return escapeCommandData(value).replace(/:/g, "%3A").replace(/,/g, "%2C");
}

function writeOutput(name: string, value: string): void {
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`, "utf8");
    return;
  }

  process.stdout.write(`::notice::${name}=${value}\n`);
}

async function upsertPullRequestComment(result: ScanResult, ruleUpdateNotices: RuleUpdateNotice[] = []): Promise<void> {
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    process.stdout.write("::warning::Skipping GuardDiff PR comment because GITHUB_TOKEN is not set.\n");
    return;
  }

  const repository = process.env.GITHUB_REPOSITORY;
  const event = readEventPayload();
  const pullRequestNumber = event.pull_request?.number;

  if (!repository || typeof pullRequestNumber !== "number") {
    process.stdout.write("::notice::Skipping GuardDiff PR comment because this run is not attached to a pull request.\n");
    return;
  }

  const [owner, repo] = repository.split("/");
  const apiBase = process.env.GITHUB_API_URL ?? "https://api.github.com";
  const commentsUrl = `${apiBase}/repos/${owner}/${repo}/issues/${pullRequestNumber}/comments?per_page=100`;
  const commentBody = `${COMMENT_MARKER}\n\n${new MarkdownReporter().render(result)}${renderRuleUpdateSection(ruleUpdateNotices)}`;
  const comments = await githubRequest<any[]>(commentsUrl, {
    method: "GET",
    token
  });
  const existingComment = comments.find((comment) => typeof comment.body === "string" && comment.body.includes(COMMENT_MARKER));

  if (existingComment) {
    await githubRequest(`${apiBase}/repos/${owner}/${repo}/issues/comments/${existingComment.id}`, {
      method: "PATCH",
      token,
      body: {
        body: commentBody
      }
    });
    return;
  }

  await githubRequest(commentsUrl, {
    method: "POST",
    token,
    body: {
      body: commentBody
    }
  });
}

async function githubRequest<T>(
  url: string,
  options: {
    method: "GET" | "POST" | "PATCH";
    token: string;
    body?: Record<string, unknown>;
  }
): Promise<T> {
  const response = await fetch(url, {
    method: options.method,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${options.token}`,
      "Content-Type": "application/json",
      Connection: "close",
      "User-Agent": "guarddiff-action"
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  if (!response.ok) {
    throw new Error(`GitHub API request failed (${response.status} ${response.statusText}): ${await response.text()}`);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

async function checkRuleUpdates(currentRules: Rule[], registryUrl: string): Promise<RuleUpdateNotice[]> {
  try {
    const response = await fetchWithTimeout(registryUrl, RULE_UPDATE_TIMEOUT_MS);
    if (!response.ok) {
      process.stdout.write(
        `::warning::Skipping GuardDiff rule update check because registry returned ${response.status} ${response.statusText}.\n`
      );
      return [];
    }

    const payload = (await response.json()) as unknown;
    const registryRules = getRegistryRules(payload);
    const currentById = new Map(currentRules.map((rule) => [rule.id, rule]));
    const notices: RuleUpdateNotice[] = [];

    for (const registryRule of registryRules) {
      const currentRule = currentById.get(registryRule.id);
      if (!currentRule) {
        notices.push({
          ...registryRule,
          type: "new"
        });
        continue;
      }

      if (isVersionGreater(registryRule.latestVersion, currentRule.ruleVersion)) {
        notices.push({
          ...registryRule,
          type: "updated",
          currentVersion: currentRule.ruleVersion
        });
      }
    }

    return notices.sort((left, right) => left.id.localeCompare(right.id));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stdout.write(`::warning::Skipping GuardDiff rule update check: ${escapeCommandData(message)}\n`);
    return [];
  }
}

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  assertHttpsUrl(url);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": "guarddiff-action"
      },
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }
}

function assertHttpsUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("rule registry URL must be a valid HTTPS URL");
  }

  if (parsed.protocol !== "https:") {
    throw new Error("rule registry URL must use HTTPS");
  }
}

function getRegistryRules(payload: unknown): Omit<RuleUpdateNotice, "type" | "currentVersion">[] {
  if (!isRecord(payload) || !Array.isArray(payload.rules)) {
    throw new Error("rule registry response must contain a rules array");
  }

  return payload.rules.flatMap((entry) => {
    if (!isRecord(entry) || typeof entry.id !== "string") {
      return [];
    }

    const latestVersion = readRegistryVersion(entry);
    if (!latestVersion) {
      return [];
    }

    return [
      {
        id: entry.id,
        latestVersion,
        title: typeof entry.title === "string" ? entry.title : undefined,
        docsUrl: typeof entry.docsUrl === "string" ? entry.docsUrl : undefined,
        summary: typeof entry.summary === "string" ? entry.summary : undefined
      }
    ];
  });
}

function readRegistryVersion(entry: Record<string, unknown>): string | undefined {
  if (typeof entry.ruleVersion === "string") {
    return entry.ruleVersion;
  }
  if (typeof entry.latestVersion === "string") {
    return entry.latestVersion;
  }
  return undefined;
}

function isVersionGreater(candidate: string, current: string): boolean {
  const candidateParts = parseSemver(candidate);
  const currentParts = parseSemver(current);
  if (!candidateParts || !currentParts) {
    return candidate !== current;
  }

  for (let index = 0; index < 3; index += 1) {
    if (candidateParts[index] > currentParts[index]) {
      return true;
    }
    if (candidateParts[index] < currentParts[index]) {
      return false;
    }
  }

  return false;
}

function parseSemver(version: string): [number, number, number] | undefined {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(version);
  if (!match) {
    return undefined;
  }
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function emitRuleUpdateNotices(notices: RuleUpdateNotice[]): void {
  if (notices.length === 0) {
    return;
  }

  for (const notice of notices) {
    const current = notice.currentVersion ? `installed ${notice.currentVersion}, ` : "";
    const suffix = notice.docsUrl ? ` ${notice.docsUrl}` : "";
    process.stdout.write(
      `::notice title=${escapeCommandProperty("GuardDiff rule update")}::${escapeCommandData(
        `${notice.id} has ${notice.type === "new" ? "a new rule" : "an update"} available (${current}latest ${notice.latestVersion}).${suffix}`
      )}\n`
    );
  }
}

function renderRuleUpdateSection(notices: RuleUpdateNotice[]): string {
  if (notices.length === 0) {
    return "";
  }

  const rows = notices
    .map((notice) => {
      const rule = notice.docsUrl ? `[${notice.id}](${notice.docsUrl})` : notice.id;
      const installed = notice.currentVersion ?? "not installed";
      const notes = notice.summary ?? notice.title ?? (notice.type === "new" ? "New rule available." : "Rule update available.");
      return `| ${escapeMarkdownCell(rule)} | ${escapeMarkdownCell(installed)} | ${escapeMarkdownCell(
        notice.latestVersion
      )} | ${escapeMarkdownCell(notes)} |`;
    })
    .join("\n");

  return `\n\n## Rule Updates Available\n\n| Rule | Installed | Latest | Notes |\n|---|---:|---:|---|\n${rows}\n`;
}

function escapeMarkdownCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}
