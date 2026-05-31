import { z } from "zod";

const safeText = /^[\p{L}\p{N}\s._:@/+,\-#()[\]]+$/u;
const safeIdentifier = /^[A-Za-z0-9._:-]+$/;

export const agentIdSchema = z
  .string()
  .trim()
  .min(1)
  .max(32)
  .regex(/^\d+$/, "Agent ID must contain only digits")
  .describe("Agent identifier (e.g., '001')");

export const alertIdSchema = z
  .string()
  .trim()
  .min(1)
  .max(256)
  .regex(safeIdentifier, "Alert ID contains unsupported characters")
  .describe("Alert identifier");

export const groupIdSchema = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(safeIdentifier, "Group identifier contains unsupported characters")
  .describe("Group name/identifier (e.g., 'default', 'linux-servers')");

export const policyIdSchema = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(safeIdentifier, "Policy identifier contains unsupported characters")
  .describe("SCA policy identifier (e.g., 'cis_debian10')");

export const ruleIdSchema = z
  .number()
  .int()
  .min(0)
  .max(999999)
  .describe("Rule identifier (e.g., 5710)");

export const ruleIdFilterSchema = z
  .string()
  .trim()
  .min(1)
  .max(16)
  .regex(/^\d+$/, "Rule ID must contain only digits")
  .describe("Filter by specific rule ID");

export const cveIdSchema = z
  .string()
  .trim()
  .min(13)
  .max(32)
  .regex(/^CVE-\d{4}-\d{4,}$/, "CVE ID must use the CVE-YYYY-NNNN format")
  .describe("CVE identifier (e.g., CVE-2020-14393)");

export const severitySchema = z
  .enum(["Critical", "High", "Medium", "Low", "None", "Unknown"])
  .describe("Vulnerability severity");

export const searchTextSchema = z
  .string()
  .trim()
  .min(1)
  .max(256)
  .regex(safeText, "Search text contains unsupported characters");

export const optionalSearchTextSchema = searchTextSchema.optional();

export const dateTimeSchema = z
  .string()
  .trim()
  .datetime({ offset: true })
  .describe("ISO 8601 timestamp with timezone offset");

export const managerSectionSchema = z
  .enum([
    "alerts",
    "analysis",
    "auth",
    "cluster",
    "global",
    "logging",
    "remote",
    "rootcheck",
    "ruleset",
    "syscheck",
    "vulnerability-detection",
  ])
  .describe("Configuration section to retrieve");

export function limitSchema(defaultValue: number, maxValue = 100): z.ZodDefault<z.ZodNumber> {
  return z
    .number()
    .int()
    .min(1)
    .max(maxValue)
    .default(defaultValue)
    .describe(`Maximum number of items to return (1-${maxValue})`);
}

export const offsetSchema = z
  .number()
  .int()
  .min(0)
  .max(100000)
  .default(0)
  .describe("Pagination offset");

export function sortSchema(
  values: [string, ...string[]],
  description: string
): z.ZodType<string | undefined> {
  return z.enum(values).optional().describe(description);
}
