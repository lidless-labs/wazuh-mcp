const SENSITIVE_KEY_PATTERN =
  /(pass(word)?|token|secret|key|credential|authorization|auth|private|certificate|cert|api[-_]?key)/i;

const REDACTED = "[REDACTED]";

export function redactSensitiveConfig(value: unknown): unknown {
  return redactValue(value, "");
}

function redactValue(value: unknown, key: string): unknown {
  if (SENSITIVE_KEY_PATTERN.test(key)) {
    return REDACTED;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, key));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([childKey, childValue]) => [
        childKey,
        redactValue(childValue, childKey),
      ])
    );
  }

  return value;
}
