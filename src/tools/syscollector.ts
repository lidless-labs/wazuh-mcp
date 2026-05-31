import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { WazuhClient } from "../client.js";
import { includeCommandSchema, paginationMetadata } from "./output.js";
import { agentIdSchema, limitSchema, offsetSchema, optionalSearchTextSchema } from "./schemas.js";

export function registerSyscollectorTools(
  server: McpServer,
  client: WazuhClient
): void {
  server.tool(
    "get_agent_os",
    "Get operating system information collected from a Wazuh agent",
    {
      agent_id: agentIdSchema,
    },
    async ({ agent_id }) => {
      try {
        const response = await client.getAgentOs(agent_id);
        const items = response.data.affected_items;

        const result = {
          agent_id,
          os: items[0] ?? null,
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error),
              }),
            },
          ],
          isError: true,
        };
      }
    }
  );

  server.tool(
    "get_agent_packages",
    "List software packages installed on a Wazuh agent",
    {
      agent_id: agentIdSchema,
      limit: limitSchema(25, 500),
      offset: offsetSchema,
      search: optionalSearchTextSchema.describe("Filter packages by name"),
    },
    async ({ agent_id, limit, offset, search }) => {
      try {
        const params: Record<string, string | number> = { limit, offset };
        if (search) params.search = search;

        const response = await client.getAgentPackages(agent_id, params);
        const data = response.data;

        const result = {
          agent_id,
          packages: data.affected_items.map((pkg) => ({
            name: pkg.name,
            version: pkg.version,
            architecture: pkg.architecture,
            description: pkg.description,
            format: pkg.format,
            vendor: pkg.vendor,
            install_time: pkg.install_time,
            size: pkg.size,
          })),
          total: data.total_affected_items,
          limit,
          offset,
          pagination: paginationMetadata(data.total_affected_items, limit, offset),
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error),
              }),
            },
          ],
          isError: true,
        };
      }
    }
  );

  server.tool(
    "get_agent_processes",
    "List running processes on a Wazuh agent",
    {
      agent_id: agentIdSchema,
      limit: limitSchema(25, 500),
      offset: offsetSchema,
      search: optionalSearchTextSchema.describe("Filter processes by name or command"),
      include_command: includeCommandSchema,
    },
    async ({ agent_id, limit, offset, search, include_command = false }) => {
      try {
        const params: Record<string, string | number> = { limit, offset };
        if (search) params.search = search;

        const response = await client.getAgentProcesses(agent_id, params);
        const data = response.data;

        const result = {
          agent_id,
          processes: data.affected_items.map((proc) => ({
            pid: proc.pid,
            name: proc.name,
            state: proc.state,
            ppid: proc.ppid,
            euser: proc.euser,
            vm_size: proc.vm_size,
            ...(include_command ? { cmd: proc.cmd, argvs: proc.argvs } : {}),
          })),
          total: data.total_affected_items,
          limit,
          offset,
          pagination: paginationMetadata(data.total_affected_items, limit, offset),
          output: {
            command_included: include_command,
          },
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error),
              }),
            },
          ],
          isError: true,
        };
      }
    }
  );

  server.tool(
    "get_agent_ports",
    "List open network ports on a Wazuh agent",
    {
      agent_id: agentIdSchema,
      limit: limitSchema(25, 500),
      offset: offsetSchema,
    },
    async ({ agent_id, limit, offset }) => {
      try {
        const response = await client.getAgentPorts(agent_id, { limit, offset });
        const data = response.data;

        const result = {
          agent_id,
          ports: data.affected_items.map((port) => ({
            protocol: port.protocol,
            local_ip: port.local_ip,
            local_port: port.local_port,
            remote_ip: port.remote_ip,
            remote_port: port.remote_port,
            state: port.state,
            pid: port.pid,
            process: port.process,
          })),
          total: data.total_affected_items,
          limit,
          offset,
          pagination: paginationMetadata(data.total_affected_items, limit, offset),
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error),
              }),
            },
          ],
          isError: true,
        };
      }
    }
  );

  server.tool(
    "get_agent_network",
    "List network interfaces and their IP addresses on a Wazuh agent",
    {
      agent_id: agentIdSchema,
    },
    async ({ agent_id }) => {
      try {
        const response = await client.getAgentNetwork(agent_id);
        const data = response.data;

        const result = {
          agent_id,
          interfaces: data.affected_items.map((iface) => ({
            name: iface.name,
            type: iface.type,
            state: iface.state,
            mac: iface.mac,
            mtu: iface.mtu,
            ipv4: iface.ipv4,
            ipv6: iface.ipv6,
            tx_packets: iface.tx_packets,
            rx_packets: iface.rx_packets,
          })),
          total: data.total_affected_items,
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error),
              }),
            },
          ],
          isError: true,
        };
      }
    }
  );

  server.tool(
    "get_agent_hotfixes",
    "List Windows hotfixes/patches installed on a Wazuh agent",
    {
      agent_id: agentIdSchema,
      limit: limitSchema(25, 500),
      offset: offsetSchema,
    },
    async ({ agent_id, limit, offset }) => {
      try {
        const response = await client.getAgentHotfixes(agent_id, { limit, offset });
        const data = response.data;

        const result = {
          agent_id,
          hotfixes: data.affected_items.map((h) => h.hotfix),
          total: data.total_affected_items,
          limit,
          offset,
          pagination: paginationMetadata(data.total_affected_items, limit, offset),
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error),
              }),
            },
          ],
          isError: true,
        };
      }
    }
  );
}
