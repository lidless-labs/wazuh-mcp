import http from "node:http";
import https from "node:https";
import { Buffer } from "node:buffer";

export interface HttpRequestOptions {
  method: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs: number;
  verifySsl: boolean;
  maxResponseBytes?: number;
}

export interface HttpResponse {
  ok: boolean;
  status: number;
  statusText: string;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

export class HttpTimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`Request timeout after ${timeoutMs}ms`);
    this.name = "HttpTimeoutError";
  }
}

export const DEFAULT_MAX_HTTP_RESPONSE_BYTES = 16 * 1024 * 1024;

export class HttpResponseTooLargeError extends Error {
  constructor(maxBytes: number) {
    super(`Upstream response exceeds ${maxBytes} bytes`);
    this.name = "HttpResponseTooLargeError";
  }
}

export class HttpInvalidJsonError extends Error {
  constructor() {
    // Constant message: never include a body excerpt (may carry secrets).
    super("upstream returned invalid JSON");
    this.name = "HttpInvalidJsonError";
  }
}

export function isTransientNetworkError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const code = (error as NodeJS.ErrnoException).code;
  return code === "ECONNRESET" || code === "ETIMEDOUT" || code === "EAI_AGAIN";
}

export async function httpRequest(url: string, options: HttpRequestOptions): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const maxBytes = options.maxResponseBytes ?? DEFAULT_MAX_HTTP_RESPONSE_BYTES;
    let settled = false;
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const settleResolve = (response: HttpResponse): void => {
      if (settled) return;
      settled = true;
      if (deadline !== undefined) clearTimeout(deadline);
      resolve(response);
    };
    const settleReject = (error: unknown): void => {
      if (settled) return;
      settled = true;
      if (deadline !== undefined) clearTimeout(deadline);
      reject(error);
    };
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === "https:";
    const request = (isHttps ? https : http).request(
      parsedUrl,
      {
        method: options.method,
        headers: options.headers,
        rejectUnauthorized: isHttps ? options.verifySsl : undefined,
      },
      (response) => {
        const rawLength = response.headers?.["content-length"];
        const contentLength = Number(Array.isArray(rawLength) ? rawLength[0] : rawLength);
        // HEAD, 204 and 304 carry no body, so their Content-Length is not a size.
        const hasBody = options.method !== "HEAD" && response.statusCode !== 204 && response.statusCode !== 304;
        if (hasBody && Number.isInteger(contentLength) && contentLength > maxBytes) {
          request.destroy(new HttpResponseTooLargeError(maxBytes));
          settleReject(new HttpResponseTooLargeError(maxBytes));
          return;
        }
        const chunks: Buffer[] = [];
        let receivedBytes = 0;
        let tooLarge = false;
        response.on("data", (chunk: Buffer | string) => {
          if (tooLarge || settled) return;
          const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          receivedBytes += buffer.byteLength;
          if (receivedBytes > maxBytes) {
            tooLarge = true;
            request.destroy(new HttpResponseTooLargeError(maxBytes));
            settleReject(new HttpResponseTooLargeError(maxBytes));
            return;
          }
          chunks.push(buffer);
        });
        response.on("end", () => {
          if (tooLarge || settled) return;
          const rawBody = Buffer.concat(chunks).toString("utf8");
          settleResolve({
            ok: response.statusCode !== undefined && response.statusCode >= 200 && response.statusCode < 300,
            status: response.statusCode ?? 0,
            statusText: response.statusMessage ?? "",
            json: async () => {
              if (!rawBody) return null;
              try {
                return JSON.parse(rawBody);
              } catch {
                throw new HttpInvalidJsonError();
              }
            },
            text: async () => rawBody,
          });
        });
        response.on("error", (error: Error) => {
          settleReject(error);
        });
        // 'aborted' fires before the ECONNRESET 'error', so tag it the same way
        // to keep mid-body resets retryable.
        response.on("aborted", () => {
          const error = new Error("upstream response aborted") as NodeJS.ErrnoException;
          error.code = "ECONNRESET";
          settleReject(error);
        });
      }
    );

    // Absolute wall-clock deadline for headers + body.
    deadline = setTimeout(() => {
      request.destroy(new HttpTimeoutError(options.timeoutMs));
      settleReject(new HttpTimeoutError(options.timeoutMs));
    }, options.timeoutMs);
    request.setTimeout(options.timeoutMs, () => {
      request.destroy(new HttpTimeoutError(options.timeoutMs));
      settleReject(new HttpTimeoutError(options.timeoutMs));
    });
    request.on("error", settleReject);
    if (options.body !== undefined) request.write(options.body);
    request.end();
  });
}
