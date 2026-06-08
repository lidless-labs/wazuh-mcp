import { Buffer } from "node:buffer";
import { z } from "zod";

const DEFAULT_MAX_TOOL_RESPONSE_BYTES = 250_000;

export const includeIpSchema = z
  .boolean()
  .default(false)
  .describe("Include agent IP addresses in the response");

export const includeFullLogSchema = z
  .boolean()
  .default(false)
  .describe("Include full raw alert log text in the response");

export const includeRawDataSchema = z
  .boolean()
  .default(false)
  .describe("Include raw event data in the response");

export const includeCommandSchema = z
  .boolean()
  .default(false)
  .describe("Include process command lines and arguments in the response");

export const includeHashesSchema = z
  .boolean()
  .default(false)
  .describe("Include file hash values in the response");

export const includeDescriptionSchema = z
  .boolean()
  .default(false)
  .describe("Include full log descriptions in the response");

export const includeSensitiveConfigSchema = z
  .boolean()
  .default(false)
  .describe(
    "Request sensitive (unredacted) manager configuration values. Only honored when the server-side WAZUH_ALLOW_SENSITIVE_CONFIG flag is enabled; otherwise values are always redacted."
  );

export function withOptionalField<K extends string, V>(
  target: Record<string, unknown>,
  key: K,
  value: V | undefined,
  include: boolean
): Record<string, unknown> {
  if (include && value !== undefined) {
    return { ...target, [key]: value };
  }
  return target;
}

export function paginationMetadata(total: number, limit: number, offset: number): Record<string, number | boolean> {
  return {
    total,
    limit,
    offset,
    has_more: offset + limit < total,
  };
}

function maxToolResponseBytes(): number {
  const value = Number(process.env.WAZUH_MCP_MAX_RESPONSE_BYTES ?? DEFAULT_MAX_TOOL_RESPONSE_BYTES);
  if (!Number.isInteger(value) || value <= 0) return DEFAULT_MAX_TOOL_RESPONSE_BYTES;
  return value;
}

function truncateUtf8(text: string, maxBytes: number): string {
  const buffer = Buffer.from(text, "utf8");
  if (buffer.byteLength <= maxBytes) return text;
  return buffer.subarray(0, maxBytes).toString("utf8");
}

export function formatToolResponse(value: unknown): string {
  const text = JSON.stringify(value, null, 2);
  const maxBytes = maxToolResponseBytes();
  const byteLength = Buffer.byteLength(text, "utf8");
  if (byteLength <= maxBytes) return text;

  const preview = truncateUtf8(text, Math.max(0, Math.floor(maxBytes * 0.6)));
  return JSON.stringify(
    {
      output: {
        response_truncated: true,
        max_response_bytes: maxBytes,
        original_response_bytes: byteLength,
      },
      preview,
    },
    null,
    2
  );
}
