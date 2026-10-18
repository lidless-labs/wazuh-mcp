import { serveMcp } from "./mcp-server.js";

const start = process.argv.includes("--http")
  ? import("./mcp-http.js").then(({ startHttpServer }) => startHttpServer())
  : serveMcp();

start.catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
