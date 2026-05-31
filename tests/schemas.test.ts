import { describe, expect, it } from "vitest";
import {
  agentIdSchema,
  groupIdSchema,
  managerSectionSchema,
  offsetSchema,
  searchTextSchema,
  sortSchema,
} from "../src/tools/schemas.js";

describe("tool input schemas", () => {
  it("should accept normal Wazuh identifiers", () => {
    expect(agentIdSchema.parse("001")).toBe("001");
    expect(groupIdSchema.parse("linux-servers_01")).toBe("linux-servers_01");
  });

  it("should reject path-like agent identifiers", () => {
    expect(agentIdSchema.safeParse("../manager").success).toBe(false);
    expect(agentIdSchema.safeParse("001/../../manager").success).toBe(false);
  });

  it("should reject unsupported sort fields", () => {
    const schema = sortSchema(["name", "-name", "+name"], "Sort by name");

    expect(schema.safeParse("-name").success).toBe(true);
    expect(schema.safeParse("-../../name").success).toBe(false);
  });

  it("should bound pagination offsets", () => {
    expect(offsetSchema.safeParse(100000).success).toBe(true);
    expect(offsetSchema.safeParse(100001).success).toBe(false);
  });

  it("should reject unsafe or oversized search text", () => {
    expect(searchTextSchema.safeParse("ssh failed").success).toBe(true);
    expect(searchTextSchema.safeParse('{"query":{"match_all":{}}}').success).toBe(false);
    expect(searchTextSchema.safeParse("a".repeat(257)).success).toBe(false);
  });

  it("should restrict manager configuration sections", () => {
    expect(managerSectionSchema.safeParse("syscheck").success).toBe(true);
    expect(managerSectionSchema.safeParse("../etc/passwd").success).toBe(false);
  });
});
