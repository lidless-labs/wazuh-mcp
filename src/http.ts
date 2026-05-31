import http from "node:http";
import https from "node:https";
import { Buffer } from "node:buffer";

export interface HttpRequestOptions {
  method: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs: number;
  verifySsl: boolean;
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

export function isTransientNetworkError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const code = (error as NodeJS.ErrnoException).code;
  return code === "ECONNRESET" || code === "ETIMEDOUT" || code === "EAI_AGAIN";
}

export async function httpRequest(url: string, options: HttpRequestOptions): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
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
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer | string) => {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        });
        response.on("end", () => {
          const rawBody = Buffer.concat(chunks).toString("utf8");
          resolve({
            ok: response.statusCode !== undefined && response.statusCode >= 200 && response.statusCode < 300,
            status: response.statusCode ?? 0,
            statusText: response.statusMessage ?? "",
            json: async () => (rawBody ? JSON.parse(rawBody) : null),
            text: async () => rawBody,
          });
        });
      }
    );

    request.setTimeout(options.timeoutMs, () => {
      request.destroy(new HttpTimeoutError(options.timeoutMs));
    });
    request.on("error", reject);
    if (options.body !== undefined) request.write(options.body);
    request.end();
  });
}
