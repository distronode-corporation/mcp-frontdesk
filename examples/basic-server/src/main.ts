// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Run the example: `npm start` (port 3000), or `PORT=4000 npm start`.
 */
import { startExampleServer } from "./server.ts";

const port = Number(process.env.PORT ?? 3000);
if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("PORT must be a port number");

const example = await startExampleServer({ port });
console.log(`MCP server:     ${example.resource}`);
console.log(`Authorization:  ${example.origin}/.well-known/oauth-authorization-server`);
console.log("Accepting the clients in mcp-frontdesk's claudeClients preset. Ctrl+C stops it.");

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    void example.close().then(() => process.exit(0));
  });
}
