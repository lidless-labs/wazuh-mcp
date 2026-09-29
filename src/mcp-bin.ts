import { serveMcp } from "./mcp-server.js";

serveMcp().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
