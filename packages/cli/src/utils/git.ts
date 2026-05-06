import { execFileSync } from "node:child_process";

export function getStagedDiff(cwd: string): string {
  if (!isInsideGitWorkTree(cwd)) {
    throw new Error("current directory is not inside a git work tree");
  }

  try {
    return execFileSync("git", ["diff", "--cached", "--no-ext-diff", "--binary", "--unified=3"], {
      cwd,
      encoding: "utf8"
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`failed to read staged diff: ${message}`);
  }
}

export function getDiffAgainstBase(cwd: string, baseRef: string, targetPath?: string): string {
  if (!isInsideGitWorkTree(cwd)) {
    throw new Error("current directory is not inside a git work tree");
  }

  try {
    const args = ["diff", `${baseRef}...HEAD`, "--no-ext-diff", "--binary", "--unified=3"];
    if (targetPath) {
      args.push("--", targetPath);
    }
    return execFileSync("git", args, {
      cwd,
      encoding: "utf8"
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`failed to read diff against ${baseRef}: ${message}`);
  }
}

export function isInsideGitWorkTree(cwd: string): boolean {
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
