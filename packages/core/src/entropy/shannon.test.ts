import { describe, expect, it } from "vitest";

import { calculateShannonEntropy } from "./shannon.js";

describe("calculateShannonEntropy", () => {
  it("returns 0 for empty string", () => {
    expect(calculateShannonEntropy("")).toBe(0);
  });

  it("returns low entropy for repeated characters", () => {
    expect(calculateShannonEntropy("aaaaaa")).toBeLessThan(1);
  });

  it("returns high entropy for random-looking strings", () => {
    expect(calculateShannonEntropy("xK9mP2qR7nL4wT6vZ1")).toBeGreaterThan(4);
  });

  it("keeps UUID entropy below the detection threshold", () => {
    const uuid = "550e8400e29b41d4a716446655440000";
    expect(calculateShannonEntropy(uuid)).toBeLessThan(4.5);
  });
});
