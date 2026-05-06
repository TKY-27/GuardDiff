import { describe, expect, it } from "vitest";

import type { FileDiff, GuardDiffConfig } from "../../types/index.js";
import { firebaseOpenRulesRule } from "./firebase-open-rules.js";

const config: GuardDiffConfig = { version: "1", policy: { failOn: "high" } };

describe("config/firebase-open-rules", () => {
  it("detects globally open firestore rules", () => {
    const fileDiff: FileDiff = {
      filePath: "firestore.rules",
      originalPath: "firestore.rules",
      isNew: true,
      isDeleted: false,
      isRenamed: false,
      isBinary: false,
      rawContent: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}`,
      hunks: []
    };

    const findings = firebaseOpenRulesRule.detect({ fileDiff, config });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
  });
});
