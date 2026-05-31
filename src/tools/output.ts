import { z } from "zod";

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
  .describe("Include sensitive manager configuration values in the response");

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
