import { describe, expect, it } from "vitest";

import { buildRuleContext } from "../../test-helpers.js";
import { mcpAutoExecWithoutApprovalRule } from "./auto-exec-without-approval.js";
import { mcpFullHomeAccessRule } from "./full-home-access.js";
import { mcpRootAccessRule } from "./root-access.js";
import { mcpUnrestrictedNetworkRule } from "./unrestricted-network.js";

describe("mcp/full-home-access", () => {
  it("detects a full home directory permission", () => {
    const findings = mcpFullHomeAccessRule.detect(
      buildRuleContext({
        filePath: ".mcp/config.json",
        addedLines: ['"allowedDirectories": ["/Users/alice"]']
      })
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
  });

  it("ignores project-scoped directories", () => {
    expect(
      mcpFullHomeAccessRule.detect(
        buildRuleContext({
          filePath: ".mcp/config.json",
          addedLines: ['"allowedDirectories": ["/Users/alice/projects/guarddiff"]']
        })
      )
    ).toHaveLength(0);
  });

  it("ignores removed lines", () => {
    expect(
      mcpFullHomeAccessRule.detect(
        buildRuleContext({
          filePath: ".mcp/config.json",
          removedLines: ['"allowedDirectories": ["/Users/alice"]']
        })
      )
    ).toHaveLength(0);
  });

  it("ignores home paths mentioned in markdown documentation", () => {
    expect(
      mcpFullHomeAccessRule.detect(
        buildRuleContext({
          filePath: "README.md",
          addedLines: ["Use /Users/alice/projects/guarddiff as an example path in docs."]
        })
      )
    ).toHaveLength(0);
  });
});

describe("mcp/root-access", () => {
  it("detects root filesystem access", () => {
    const findings = mcpRootAccessRule.detect(
      buildRuleContext({
        filePath: ".mcp/config.json",
        addedLines: ['"roots": ["/"]']
      })
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
  });

  it("ignores URLs that contain slashes", () => {
    expect(
      mcpRootAccessRule.detect(
        buildRuleContext({
          filePath: ".mcp/config.json",
          addedLines: ['"endpoint": "https://api.example.com/"']
        })
      )
    ).toHaveLength(0);
  });

  it("ignores slash separators in documentation prose", () => {
    expect(
      mcpRootAccessRule.detect(
        buildRuleContext({
          filePath: "docs/getting-started.md",
          addedLines: ["This workflow connects git diff / patch file / stdin inputs."]
        })
      )
    ).toHaveLength(0);
  });
});

describe("mcp/auto-exec-without-approval", () => {
  it("detects approval disabled settings", () => {
    const findings = mcpAutoExecWithoutApprovalRule.detect(
      buildRuleContext({
        filePath: ".mcp/config.yaml",
        addedLines: ["approval_policy: never"]
      })
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
  });

  it("ignores approval-enabled settings", () => {
    expect(
      mcpAutoExecWithoutApprovalRule.detect(
        buildRuleContext({
          filePath: ".mcp/config.yaml",
          addedLines: ["approval_policy: manual"]
        })
      )
    ).toHaveLength(0);
  });
});

describe("mcp/unrestricted-network", () => {
  it("detects unrestricted network access", () => {
    const findings = mcpUnrestrictedNetworkRule.detect(
      buildRuleContext({
        filePath: ".mcp/config.yaml",
        addedLines: ["network_access: true"]
      })
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
  });

  it("ignores disabled network access", () => {
    expect(
      mcpUnrestrictedNetworkRule.detect(
        buildRuleContext({
          filePath: ".mcp/config.yaml",
          addedLines: ["network_access: false"]
        })
      )
    ).toHaveLength(0);
  });
});
