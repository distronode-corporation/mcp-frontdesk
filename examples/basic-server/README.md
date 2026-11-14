# mcp-frontdesk example: basic server

A runnable MCP server on plain `node:http`: mcp-frontdesk for OAuth and the bearer gate, the
official MCP TypeScript SDK for the protocol, a demo sign-in and consent page, in-memory stores, and
three tools over made-up notes. Loopback http only. Never deploy it: the sign-in has no password.

```sh
# from the repository root
npm ci && npm run build
cd examples/basic-server
npm ci
npm start      # http://127.0.0.1:3000/mcp
npm test       # the end-to-end test
```

| File | What |
|---|---|
| `src/server.ts` | `startExampleServer`: routing, the consent flow, the gate in front of the SDK |
| `src/pages.ts` | The sign-in and consent pages |
| `src/notes.ts` | The made-up data and the three tools |
| `src/node-http.ts` | `node:http` to Web `Request` and `Response`, and a capped form reader |
| `src/main.ts` | `npm start` |
| `test/e2e.test.ts` | The end-to-end test |

What the test covers, and why it reaches its metadata document the way it does, is in the
[main README](../../README.md#example-server).
