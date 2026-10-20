import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls, { type PeerCertificate } from "node:tls";
import { getConfig, type WazuhConfig } from "../src/config.js";
import { httpRequest } from "../src/http.js";
import { buildTlsIdentityOptions, parseTlsServername } from "../src/tls-identity.js";
import { runWazuhDiagnostics } from "../src/tools/diagnostics.js";
import type { WazuhClient } from "../src/client.js";

function setRequiredEnv(): void {
  vi.stubEnv("WAZUH_URL", "https://wazuh.example.com:55000");
  vi.stubEnv("WAZUH_USERNAME", "admin");
  vi.stubEnv("WAZUH_PASSWORD", "secret");
}

function setIndexerEnv(): void {
  vi.stubEnv("WAZUH_INDEXER_URL", "https://indexer.example.com:9200");
  vi.stubEnv("WAZUH_INDEXER_USERNAME", "reader");
  vi.stubEnv("WAZUH_INDEXER_PASSWORD", "indexer-secret");
}

describe("parseTlsServername", () => {
  it("returns undefined when the variable is unset", () => {
    expect(parseTlsServername(undefined, "X")).toBeUndefined();
  });

  it("accepts IPv4, IPv6, and DNS names and normalizes case and whitespace", () => {
    expect(parseTlsServername("127.0.0.1", "X")).toBe("127.0.0.1");
    expect(parseTlsServername("::1", "X")).toBe("::1");
    expect(parseTlsServername("2001:db8::1", "X")).toBe("2001:db8::1");
    expect(parseTlsServername(" Wazuh.Example.COM ", "X")).toBe("wazuh.example.com");
    expect(parseTlsServername("wazuh-indexer", "X")).toBe("wazuh-indexer");
    expect(parseTlsServername("a".repeat(63) + ".example.com", "X")).toBeDefined();
  });

  it.each([
    ["", "must not be empty"],
    ["   ", "must not be empty"],
    ["https://wazuh.example.com", "without a scheme"],
    ["wazuh.example.com/path", "without a path"],
    ["wazuh.example.com?x=1", "without a path"],
    ["user@wazuh.example.com", "without a path"],
    ["two words", "without a path"],
    ["wazuh.example.com:9200", "must not include a port"],
    ["[::1]", "must not include a port or brackets"],
    ["-bad.example.com", "valid IPv4 address, IPv6 address, or DNS name"],
    ["bad_name.example.com", "valid IPv4 address, IPv6 address, or DNS name"],
    ["a..example.com", "valid IPv4 address, IPv6 address, or DNS name"],
    ["wazuh.example.com.", "valid IPv4 address, IPv6 address, or DNS name"],
    ["256.1.1.1", "valid IPv4 address, IPv6 address, or DNS name"],
    ["a".repeat(64) + ".example.com", "valid IPv4 address, IPv6 address, or DNS name"],
    ["a".repeat(250) + ".example.com", "at most 253 characters"],
  ])("rejects %j", (value, message) => {
    expect(() => parseTlsServername(value, "WAZUH_TLS_SERVERNAME")).toThrow(message);
  });

  it("does not echo the rejected value", () => {
    expect(() => parseTlsServername("https://secret-host.example", "X")).not.toThrow(/secret-host/);
  });
});

describe("TLS servername config", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("leaves both names unset by default", () => {
    setRequiredEnv();
    setIndexerEnv();
    const config = getConfig();
    expect(config.tlsServername).toBeUndefined();
    expect(config.indexer?.tlsServername).toBeUndefined();
  });

  it("parses WAZUH_TLS_SERVERNAME and WAZUH_INDEXER_TLS_SERVERNAME independently", () => {
    setRequiredEnv();
    setIndexerEnv();
    vi.stubEnv("WAZUH_TLS_SERVERNAME", "localhost");
    vi.stubEnv("WAZUH_INDEXER_TLS_SERVERNAME", "127.0.0.1");
    const config = getConfig();
    expect(config.tlsServername).toBe("localhost");
    expect(config.indexer?.tlsServername).toBe("127.0.0.1");
  });

  it("rejects an invalid manager or indexer name at startup", () => {
    setRequiredEnv();
    setIndexerEnv();
    vi.stubEnv("WAZUH_TLS_SERVERNAME", "https://localhost");
    expect(() => getConfig()).toThrow("WAZUH_TLS_SERVERNAME must be a bare host name");
    vi.stubEnv("WAZUH_TLS_SERVERNAME", "localhost");
    vi.stubEnv("WAZUH_INDEXER_TLS_SERVERNAME", "");
    expect(() => getConfig()).toThrow("WAZUH_INDEXER_TLS_SERVERNAME must not be empty");
  });

  it("ignores WAZUH_INDEXER_TLS_SERVERNAME when no indexer is configured", () => {
    setRequiredEnv();
    vi.stubEnv("WAZUH_INDEXER_TLS_SERVERNAME", "127.0.0.1");
    expect(getConfig().indexer).toBeUndefined();
  });
});

describe("buildTlsIdentityOptions", () => {
  // Shape of the certificate Node hands to checkServerIdentity for a leaf whose
  // only SAN is IP:127.0.0.1, which is what the Wazuh indexer node cert carries.
  const loopbackCert = {
    subject: { CN: "indexer" },
    subjectaltname: "IP Address:127.0.0.1",
  } as unknown as PeerCertificate;
  const localhostCert = {
    subject: { CN: "localhost" },
    subjectaltname: "DNS:localhost",
  } as unknown as PeerCertificate;

  it("checks the configured IP instead of the URL host", () => {
    const options = buildTlsIdentityOptions("127.0.0.1");
    expect(options.checkServerIdentity("192.0.2.10", loopbackCert)).toBeUndefined();
    expect(tls.checkServerIdentity("192.0.2.10", loopbackCert)).toBeInstanceOf(Error);
  });

  it("fails when the configured name is not in the certificate", () => {
    const options = buildTlsIdentityOptions("192.0.2.99");
    expect(options.checkServerIdentity("127.0.0.1", loopbackCert)).toBeInstanceOf(Error);
    expect(buildTlsIdentityOptions("localhost").checkServerIdentity("192.0.2.10", loopbackCert)).toBeInstanceOf(Error);
  });

  it("checks a DNS name against a localhost-only certificate", () => {
    expect(buildTlsIdentityOptions("localhost").checkServerIdentity("192.0.2.10", localhostCert)).toBeUndefined();
    expect(buildTlsIdentityOptions("wazuh.example.com").checkServerIdentity("192.0.2.10", localhostCert)).toBeInstanceOf(
      Error
    );
  });

  it("sets SNI for DNS names and never for IP addresses", () => {
    expect(buildTlsIdentityOptions("localhost").servername).toBe("localhost");
    expect(buildTlsIdentityOptions("wazuh.example.com").servername).toBe("wazuh.example.com");
    expect("servername" in buildTlsIdentityOptions("127.0.0.1")).toBe(false);
    expect("servername" in buildTlsIdentityOptions("::1")).toBe(false);
  });
});

describe("httpRequest TLS identity override", () => {
  it("passes the identity options to https.request only when verification is on", async () => {
    const captured: Array<Record<string, unknown>> = [];
    const spy = vi.spyOn(https, "request").mockImplementation(((_url: unknown, options: Record<string, unknown>) => {
      captured.push(options);
      throw new Error("stop");
    }) as unknown as typeof https.request);
    try {
      const base = { method: "GET", timeoutMs: 1000, tlsServername: "127.0.0.1" };
      await expect(httpRequest("https://192.0.2.10:9200/", { ...base, verifySsl: true })).rejects.toThrow("stop");
      await expect(httpRequest("https://192.0.2.10:9200/", { ...base, verifySsl: false })).rejects.toThrow("stop");
      await expect(
        httpRequest("https://192.0.2.10:9200/", { method: "GET", timeoutMs: 1000, verifySsl: true })
      ).rejects.toThrow("stop");
    } finally {
      spy.mockRestore();
    }
    expect(typeof captured[0].checkServerIdentity).toBe("function");
    expect("servername" in captured[0]).toBe(false);
    expect(captured[1].checkServerIdentity).toBeUndefined();
    expect(captured[2].checkServerIdentity).toBeUndefined();
  });
});

function hasOpenssl(): boolean {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

describe.skipIf(!hasOpenssl())("httpRequest against a TLS server with a throwaway CA", () => {
  let dir: string;
  let caPem: string;
  let ipLeaf: { key: string; cert: string };
  let dnsLeaf: { key: string; cert: string };
  const servers: https.Server[] = [];

  function openssl(...args: string[]): void {
    execFileSync("openssl", args, { cwd: dir, stdio: "ignore" });
  }

  function makeLeaf(name: string, san: string): { key: string; cert: string } {
    writeFileSync(join(dir, `${name}.ext`), `subjectAltName=${san}\nbasicConstraints=CA:FALSE\n`);
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
      "-keyout", `${name}.key`, "-subj", `/CN=${name}`, "-out", `${name}.csr`);
    openssl("x509", "-req", "-in", `${name}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
      "-out", `${name}.pem`, "-days", "2", "-extfile", `${name}.ext`);
    return { key: readFileSync(join(dir, `${name}.key`), "utf8"), cert: readFileSync(join(dir, `${name}.pem`), "utf8") };
  }

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "wazuh-tls-"));
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
      "-keyout", "ca.key", "-subj", "/CN=test-root-ca", "-days", "2",
      "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign", "-out", "ca.pem");
    caPem = readFileSync(join(dir, "ca.pem"), "utf8");
    ipLeaf = makeLeaf("ipleaf", "IP:127.0.0.1");
    dnsLeaf = makeLeaf("dnsleaf", "DNS:wazuh-indexer.test");
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  afterEach(async () => {
    await Promise.all(servers.splice(0).map((s) => new Promise<void>((resolve) => s.close(() => resolve()))));
  });

  async function serve(leaf: { key: string; cert: string }, sni?: string[]): Promise<number> {
    const server = https.createServer({ key: leaf.key, cert: leaf.cert }, (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{}");
    });
    server.on("secureConnection", (socket) => {
      sni?.push((socket as tls.TLSSocket).servername || "");
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    return (server.address() as AddressInfo).port;
  }

  // The URL host is "localhost", which is not in the IP-only leaf, standing in
  // for a LAN address that is not in the certificate.
  const base = { method: "GET", timeoutMs: 5000, verifySsl: true } as const;

  it("fails without a servername because the URL host is not in the certificate", async () => {
    const port = await serve(ipLeaf);
    await expect(httpRequest(`https://localhost:${port}/`, { ...base, ca: caPem })).rejects.toMatchObject({
      code: "ERR_TLS_CERT_ALTNAME_INVALID",
    });
  });

  it("passes when the servername is the IP in the certificate and does not use the IP as SNI", async () => {
    const sni: string[] = [];
    const port = await serve(ipLeaf, sni);
    const response = await httpRequest(`https://localhost:${port}/`, { ...base, ca: caPem, tlsServername: "127.0.0.1" });
    expect(response.ok).toBe(true);
    // Node falls back to the URL host for SNI; the IP override must not be sent.
    expect(sni).toEqual(["localhost"]);
  });

  it("fails when the servername differs from the certificate", async () => {
    const port = await serve(ipLeaf);
    await expect(
      httpRequest(`https://localhost:${port}/`, { ...base, ca: caPem, tlsServername: "127.0.0.2" })
    ).rejects.toMatchObject({ code: "ERR_TLS_CERT_ALTNAME_INVALID" });
  });

  it("sends the DNS servername as SNI and validates against it", async () => {
    const sni: string[] = [];
    const port = await serve(dnsLeaf, sni);
    const response = await httpRequest(`https://127.0.0.1:${port}/`, {
      ...base,
      ca: caPem,
      tlsServername: "wazuh-indexer.test",
    });
    expect(response.ok).toBe(true);
    expect(sni).toEqual(["wazuh-indexer.test"]);
  });

  it("still rejects a certificate the CA did not sign even when the name matches", async () => {
    const port = await serve(ipLeaf);
    const otherDir = mkdtempSync(join(tmpdir(), "wazuh-tls-other-"));
    try {
      execFileSync(
        "openssl",
        ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "o.key",
          "-subj", "/CN=other-ca", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE", "-out", "o.pem"],
        { cwd: otherDir, stdio: "ignore" }
      );
      const otherCa = readFileSync(join(otherDir, "o.pem"), "utf8");
      await expect(
        httpRequest(`https://localhost:${port}/`, { ...base, ca: otherCa, tlsServername: "127.0.0.1" })
      ).rejects.toMatchObject({ code: expect.stringMatching(/UNABLE_TO_VERIFY|SELF_SIGNED|CERT/) });
    } finally {
      rmSync(otherDir, { recursive: true, force: true });
    }
  });
});

describe("diagnostics for TLS servername", () => {
  const config: WazuhConfig = {
    url: "https://wazuh.example.com:55000",
    username: "admin",
    password: "secret",
    verifySsl: true,
    timeout: 30000,
    indexer: {
      url: "https://indexer.example.com:9200",
      username: "reader",
      password: "indexer-secret",
      verifySsl: true,
      timeout: 30000,
    },
  };

  async function messages(cfg: WazuhConfig): Promise<Array<{ status: string; message: string }>> {
    const result = await runWazuhDiagnostics({} as WazuhClient, cfg, undefined, false);
    return result.checks;
  }

  it("reports nothing when neither name is set", async () => {
    const checks = await messages(config);
    expect(checks.some((c) => c.message.includes("TLS_SERVERNAME"))).toBe(false);
  });

  it("reports an active name when verification is on", async () => {
    const checks = await messages({
      ...config,
      tlsServername: "localhost",
      indexer: { ...config.indexer!, tlsServername: "127.0.0.1" },
    });
    const servername = checks.filter((c) => c.message.includes("TLS_SERVERNAME"));
    expect(servername).toHaveLength(2);
    expect(servername.every((c) => c.status === "ok")).toBe(true);
  });

  it("warns that the name is ignored when verification is off", async () => {
    const checks = await messages({
      ...config,
      verifySsl: false,
      tlsServername: "localhost",
      indexer: { ...config.indexer!, verifySsl: false, tlsServername: "127.0.0.1" },
    });
    const ignored = checks.filter((c) => c.message.includes("ignored because TLS certificate verification is disabled"));
    expect(ignored.map((c) => c.status)).toEqual(["warning", "warning"]);
    expect(ignored[0].message).toContain("WAZUH_TLS_SERVERNAME");
    expect(ignored[1].message).toContain("WAZUH_INDEXER_TLS_SERVERNAME");
  });
});
