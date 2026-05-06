import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";

import * as vscode from "vscode";

const execFileAsync = promisify(execFile);
const collection = vscode.languages.createDiagnosticCollection("guarddiff");
let statusItem: vscode.StatusBarItem | undefined;

interface GuardDiffPayload {
  result?: {
    findings?: GuardDiffFinding[];
  };
}

interface GuardDiffFinding {
  ruleId: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  filePath: string;
  lineStart: number;
  lineEnd: number;
  message: string;
  suppressed?: boolean;
}

export function activate(context: vscode.ExtensionContext): void {
  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 80);
  statusItem.command = "guarddiff.scanWorkspace";
  statusItem.text = "GuardDiff";
  statusItem.tooltip = "Run GuardDiff security scan";
  statusItem.show();

  context.subscriptions.push(
    collection,
    statusItem,
    vscode.commands.registerCommand("guarddiff.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("guarddiff.clearDiagnostics", () => {
      collection.clear();
      updateStatus("GuardDiff");
    }),
    vscode.workspace.onDidSaveTextDocument(() => {
      if (vscode.workspace.isTrusted && vscode.workspace.getConfiguration("guarddiff").get<boolean>("scanOnSave", false)) {
        void scanWorkspace();
      }
    })
  );
}

export function deactivate(): void {
  collection.dispose();
}

async function scanWorkspace(): Promise<void> {
  if (!vscode.workspace.isTrusted) {
    updateStatus("GuardDiff: workspace not trusted");
    vscode.window.showWarningMessage("GuardDiff scans are disabled until this workspace is trusted.");
    return;
  }

  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    vscode.window.showWarningMessage("Open a workspace before running GuardDiff.");
    return;
  }

  const config = vscode.workspace.getConfiguration("guarddiff");
  const command = validateCommand(config.get<string>("command", "guarddiff"));
  const configPath = validateConfigPath(folder.uri.fsPath, config.get<string>("configPath", ""));
  const failOn = config.get<string>("failOn", "high");
  const args = ["scan", folder.uri.fsPath, "--format", "json", "--fail-on", failOn];
  if (configPath.length > 0) {
    args.push("--config", configPath);
  }

  try {
    updateStatus("GuardDiff: scanning");
    const { stdout } = await execFileAsync(command, args, {
      cwd: folder.uri.fsPath,
      maxBuffer: 10 * 1024 * 1024
    });
    updateDiagnostics(folder.uri.fsPath, stdout);
  } catch (error) {
    const stdout = getStdout(error);
    if (stdout) {
      updateDiagnostics(folder.uri.fsPath, stdout);
      return;
    }
    updateStatus("GuardDiff: error");
    vscode.window.showErrorMessage(`GuardDiff failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function updateDiagnostics(workspaceRoot: string, stdout: string): void {
  const payload = JSON.parse(stdout) as GuardDiffPayload;
  const findings = (payload.result?.findings ?? []).filter((finding) => !finding.suppressed);
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const finding of findings) {
    const absolutePath = path.resolve(workspaceRoot, finding.filePath);
    if (!isInsideDirectory(workspaceRoot, absolutePath)) {
      continue;
    }

    const uri = vscode.Uri.file(absolutePath);
    const diagnostic = new vscode.Diagnostic(
      new vscode.Range(Math.max(0, finding.lineStart - 1), 0, Math.max(0, finding.lineEnd - 1), Number.MAX_SAFE_INTEGER),
      `${finding.ruleId}: ${finding.message}`,
      toDiagnosticSeverity(finding.severity)
    );
    diagnostic.code = finding.ruleId;
    diagnostic.source = "GuardDiff";
    const existing = byFile.get(uri.fsPath) ?? [];
    existing.push(diagnostic);
    byFile.set(uri.fsPath, existing);
  }

  collection.clear();
  for (const [filePath, diagnostics] of byFile) {
    collection.set(vscode.Uri.file(filePath), diagnostics);
  }
  updateStatus(`GuardDiff: ${findings.length}`);
  vscode.window.setStatusBarMessage(`GuardDiff: ${findings.length} finding(s)`, 5000);
}

function updateStatus(text: string): void {
  if (statusItem) {
    statusItem.text = text;
  }
}

function toDiagnosticSeverity(severity: GuardDiffFinding["severity"]): vscode.DiagnosticSeverity {
  if (severity === "critical" || severity === "high") {
    return vscode.DiagnosticSeverity.Error;
  }
  if (severity === "medium") {
    return vscode.DiagnosticSeverity.Warning;
  }
  if (severity === "low") {
    return vscode.DiagnosticSeverity.Information;
  }
  return vscode.DiagnosticSeverity.Hint;
}

function getStdout(error: unknown): string | undefined {
  if (typeof error === "object" && error !== null && "stdout" in error) {
    const stdout = (error as { stdout?: unknown }).stdout;
    return typeof stdout === "string" ? stdout : undefined;
  }
  return undefined;
}

function validateCommand(command: string): string {
  const trimmed = command.trim();
  if (trimmed.length === 0) {
    throw new Error("guarddiff.command must not be empty");
  }

  if (path.isAbsolute(trimmed)) {
    return trimmed;
  }

  if (trimmed.includes("/") || trimmed.includes("\\")) {
    throw new Error("guarddiff.command must be an executable name on PATH or an absolute path");
  }

  return trimmed;
}

function validateConfigPath(workspaceRoot: string, configPath: string): string {
  const trimmed = configPath.trim();
  if (trimmed.length === 0) {
    return "";
  }

  const resolved = path.resolve(workspaceRoot, trimmed);
  if (!isInsideDirectory(workspaceRoot, resolved)) {
    throw new Error("guarddiff.configPath must stay inside the current workspace");
  }

  return resolved;
}

function isInsideDirectory(parent: string, child: string): boolean {
  const relative = path.relative(parent, child);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}
