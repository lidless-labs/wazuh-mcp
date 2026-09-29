import { describe, it, expect } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerPrompts } from "../src/prompts.js";

type PromptResult = {
  messages: Array<{ role: string; content: { type: string; text: string } }>;
};
type PromptHandler = (args: Record<string, string>) => PromptResult;

// Capture prompt handlers registered via server.prompt()
function capturePrompts(): Map<string, PromptHandler> {
  const prompts = new Map<string, PromptHandler>();

  const mockServer = {
    prompt: (
      name: string,
      _description: string,
      _schema: unknown,
      handler: PromptHandler
    ) => {
      prompts.set(name, handler);
    },
  } as unknown as McpServer;

  registerPrompts(mockServer);
  return prompts;
}

function singleUserText(result: PromptResult): string {
  expect(result.messages).toHaveLength(1);
  expect(result.messages[0].role).toBe("user");
  expect(result.messages[0].content.type).toBe("text");
  return result.messages[0].content.text;
}

describe("Prompts", () => {
  const prompts = capturePrompts();

  it("registers the three documented prompts", () => {
    expect([...prompts.keys()].sort()).toEqual([
      "agent-health-check",
      "investigate-alert",
      "security-overview",
    ]);
  });

  it("investigate-alert interpolates the alert ID", () => {
    const text = singleUserText(prompts.get("investigate-alert")!({ alert_id: "1712345678.42" }));

    expect(text.split("\n")[0]).toBe("Investigate Wazuh alert 1712345678.42. Please:");
    expect(text).toContain("get_alert");
    expect(text).toContain("get_rule");
    expect(text).toContain("get_agent");
  });

  it("agent-health-check interpolates the agent ID", () => {
    const text = singleUserText(prompts.get("agent-health-check")!({ agent_id: "007" }));

    expect(text.split("\n")[0]).toBe("Perform a health check on Wazuh agent 007. Please:");
    expect(text).toContain("get_agent_stats");
  });

  it("security-overview takes no arguments and references the overview tools", () => {
    const text = singleUserText(prompts.get("security-overview")!({}));

    expect(text.split("\n")[0]).toBe(
      "Generate a security overview of the Wazuh environment. Please:"
    );
    expect(text).toContain("get_wazuh_version");
    expect(text).toContain("list_agents");
  });
});
