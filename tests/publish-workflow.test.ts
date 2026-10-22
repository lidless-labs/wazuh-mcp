import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const workflow = readFileSync(
  new URL("../.github/workflows/publish.yml", import.meta.url),
  "utf8"
);

// Split the jobs block into per-job text without a YAML dependency. Jobs are
// the two-space-indented keys under `jobs:`.
function jobBlocks(text: string): Record<string, string> {
  const jobs = text.slice(text.indexOf("\njobs:\n") + "\njobs:\n".length);
  const parts = jobs.split(/^  (?=[a-z][a-z0-9_-]*:\s*$)/m).filter((part) => part.trim() !== "");
  return Object.fromEntries(
    parts
      .filter((part) => /^[a-z][a-z0-9_-]*:/.test(part))
      .map((part) => [part.slice(0, part.indexOf(":")), part])
  );
}

describe("publish workflow", () => {
  const jobs = jobBlocks(workflow);

  it("defines a build job and a publish job", () => {
    expect(Object.keys(jobs)).toEqual(["build", "publish"]);
  });

  it("keeps the OIDC permission out of the job that installs dependencies", () => {
    expect(jobs.build).toMatch(/npm ci/);
    expect(jobs.build).not.toMatch(/id-token/);
    expect(jobs.build).not.toMatch(/NPM_TOKEN|NODE_AUTH_TOKEN/);
    expect(jobs.build).not.toMatch(/environment:/);
  });

  it("publishes a prebuilt tarball from a job that installs nothing", () => {
    expect(jobs.publish).toMatch(/id-token: write/);
    expect(jobs.publish).toMatch(/needs: build/);
    expect(jobs.publish).not.toMatch(/npm (ci|install|i)\b/);
    expect(jobs.publish).not.toMatch(/actions\/checkout/);
    expect(jobs.publish).toMatch(/npm publish "\$RUNNER_TEMP\/package\/\$TARBALL"/);
  });

  it("does not grant id-token at the workflow level", () => {
    const header = workflow.slice(0, workflow.indexOf("\njobs:\n"));
    expect(header).not.toMatch(/id-token/);
  });

  it("pins every action to a full commit SHA", () => {
    const uses = [...workflow.matchAll(/uses:\s*(\S+)/g)].map((match) => match[1]);
    expect(uses.length).toBeGreaterThan(0);
    for (const ref of uses) expect(ref).toMatch(/@[0-9a-f]{40}$/);
  });
});
