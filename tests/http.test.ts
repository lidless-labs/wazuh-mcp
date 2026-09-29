import { afterEach, describe, expect, it } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import {
  HttpInvalidJsonError,
  HttpResponseTooLargeError,
  HttpTimeoutError,
  httpRequest,
} from "../src/http.js";

const servers: http.Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map((s) => new Promise<void>((resolve) => s.close(() => resolve())))
  );
});

function listen(handler: http.RequestListener): Promise<string> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    servers.push(server);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${port}`);
    });
  });
}

describe("httpRequest response limits", () => {
  it("should reject early when content-length exceeds maxResponseBytes", async () => {
    const url = await listen((_req, res) => {
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Length": "1024",
      });
      res.end("{}");
    });

    await expect(
      httpRequest(url, { method: "GET", timeoutMs: 5000, verifySsl: false, maxResponseBytes: 10 })
    ).rejects.toBeInstanceOf(HttpResponseTooLargeError);
  });

  it("should reject while streaming when chunks exceed maxResponseBytes", async () => {
    const url = await listen((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      // No content-length: forces byte counting on the data path.
      res.write("x".repeat(500));
      res.write("y".repeat(500));
      res.end();
    });

    await expect(
      httpRequest(url, { method: "GET", timeoutMs: 5000, verifySsl: false, maxResponseBytes: 100 })
    ).rejects.toBeInstanceOf(HttpResponseTooLargeError);
  });

  it("should reject with HttpTimeoutError when the whole request exceeds the wall-clock deadline", async () => {
    const url = await listen((_req, _res) => {
      // Never respond: the absolute deadline must fire.
    });

    await expect(
      httpRequest(url, { method: "GET", timeoutMs: 100, verifySsl: false })
    ).rejects.toBeInstanceOf(HttpTimeoutError);
  });

  it("should reject (not hang) when the connection drops mid-body", async () => {
    const url = await listen((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.write('{"partial":');
      res.socket?.destroy();
    });

    await expect(
      httpRequest(url, { method: "GET", timeoutMs: 2000, verifySsl: false })
    ).rejects.toMatchObject({ code: "ECONNRESET" });
  });

  it("should enforce the deadline against a slow-drip body the idle timeout never catches", async () => {
    const url = await listen((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      const timer = setInterval(() => res.write(" "), 20);
      res.on("close", () => clearInterval(timer));
    });

    await expect(
      httpRequest(url, { method: "GET", timeoutMs: 200, verifySsl: false })
    ).rejects.toBeInstanceOf(HttpTimeoutError);
  });

  it("should not apply the size precheck to HEAD responses", async () => {
    const url = await listen((_req, res) => {
      res.writeHead(200, { "Content-Length": "999999999" });
      res.end();
    });

    const response = await httpRequest(url, { method: "HEAD", timeoutMs: 2000, verifySsl: false, maxResponseBytes: 10 });
    expect(response.status).toBe(200);
  });
});

describe("httpRequest json()", () => {
  it("should throw HttpInvalidJsonError with a constant message and no body excerpt", async () => {
    const leaked = "not-json{secret-marker-xyz";
    const url = await listen((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(leaked);
    });

    const response = await httpRequest(url, {
      method: "GET",
      timeoutMs: 5000,
      verifySsl: false,
    });
    const failure = await response.json().catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(HttpInvalidJsonError);
    expect((failure as Error).message).toBe("upstream returned invalid JSON");
    expect((failure as Error).message).not.toContain("secret-marker-xyz");
  });
});
