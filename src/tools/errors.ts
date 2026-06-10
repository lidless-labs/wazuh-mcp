import { safeCaughtErrorMessage } from "../safe-error.js";

export interface ToolErrorResponse {
  [key: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  isError: true;
}

/**
 * Build a tool error response with the message routed through the
 * safe-error sanitizer. Every tool catch block must use this helper so
 * that errors which bypass the WazuhClientError/WazuhIndexerError
 * wrappers (JSON parse errors with body snippets, URL errors, re-thrown
 * unknowns) never reach the MCP client unsanitized.
 */
export function toolErrorResponse(error: unknown): ToolErrorResponse {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify({
          error: safeCaughtErrorMessage(error, "Unexpected error"),
        }),
      },
    ],
    isError: true,
  };
}
