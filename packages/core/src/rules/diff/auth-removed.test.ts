import { describe, expect, it } from "vitest";

import { buildRuleContext } from "../../test-helpers.js";
import { authRemovedRule } from "./auth-removed.js";

describe("diff/auth-removed", () => {
  it("detects auth removal as critical", () => {
    const findings = authRemovedRule.detect(
      buildRuleContext({
        filePath: "src/middleware/auth.ts",
        removedLines: ["requireAuth(req, res, next);"],
        contextBefore: ["router.get('/admin', handler);"]
      })
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].confidence).toBe("likely");
  });

  it("downgrades refactoring to info", () => {
    const findings = authRemovedRule.detect(
      buildRuleContext({
        filePath: "src/middleware/auth.ts",
        addedLines: ["requireAuth(req, res, next); // moved"],
        removedLines: ["requireAuth(req, res, next);"],
        contextBefore: ["router.get('/admin', handler);"]
      })
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("info");
  });

  it("reports high when auth-like removal lacks authentication context", () => {
    const findings = authRemovedRule.detect(
      buildRuleContext({
        filePath: "src/lib/request.ts",
        removedLines: ["authenticate(payload);"],
        contextBefore: ["const payload = buildPayload(input);"],
        contextAfter: ["return payload;"]
      })
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].confidence).toBe("possible");
  });
});
