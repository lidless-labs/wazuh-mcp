const SECRET_PATTERNS = [
  /(authorization:\s*)(basic|bearer)\s+[a-z0-9._~+/=-]+/gi,
  /\b(basic|bearer)\s+[a-z0-9._~+/=-]+/gi,
  /(https?:\/\/)([^:\s/@]+):([^@\s/]+)@/gi,
  /([?&](?:password|token|secret|api[_-]?key|key)=)[^&\s]+/gi,
  /\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/g,
];

export function sanitizeErrorMessage(message: string, secrets: string[] = []): string {
  let sanitized = message;
  for (const secret of secrets) {
    if (secret) sanitized = sanitized.split(secret).join("[REDACTED]");
  }
  sanitized = sanitized
    .replace(SECRET_PATTERNS[0], "$1$2 [REDACTED]")
    .replace(SECRET_PATTERNS[1], "$1 [REDACTED]")
    .replace(SECRET_PATTERNS[2], "$1[REDACTED]:[REDACTED]@")
    .replace(SECRET_PATTERNS[3], "$1[REDACTED]")
    .replace(SECRET_PATTERNS[4], "[REDACTED]");
  return sanitized.length > 500 ? `${sanitized.slice(0, 500)}...` : sanitized;
}

function stringField(value: unknown, field: string): string | undefined {
  if (!value || typeof value !== "object") return undefined;
  const record = value as Record<string, unknown>;
  return typeof record[field] === "string" ? record[field] : undefined;
}

export function extractSafeErrorDetail(body: unknown, secrets: string[] = []): string | undefined {
  if (!body || typeof body !== "object") return undefined;
  const record = body as Record<string, unknown>;
  const message = stringField(record, "message");
  if (message) return sanitizeErrorMessage(message, secrets);

  const error = record.error;
  if (!error) return undefined;
  if (typeof error === "string") return sanitizeErrorMessage(error, secrets);
  if (typeof error !== "object") return undefined;

  const type = stringField(error, "type");
  const reason = stringField(error, "reason");
  const detail = [type, reason].filter(Boolean).join(": ");
  return detail ? sanitizeErrorMessage(detail, secrets) : undefined;
}

export function safeCaughtErrorMessage(error: unknown, fallback: string, secrets: string[] = []): string {
  if (error instanceof Error) return sanitizeErrorMessage(error.message, secrets);
  if (typeof error === "string") return sanitizeErrorMessage(error, secrets);
  return fallback;
}
