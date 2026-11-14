/**
 * The demo's data and tools: a notebook per demo account, in memory, made up.
 *
 * The tools read the person from the verified access token (`authInfo.extra`),
 * so each account sees only its own notes, and `add_note` asks for the
 * `notes:write` scope through the SDK's step-up challenge.
 */
import { McpServer, requireScopes, type AuthInfo } from "@modelcontextprotocol/server";
import * as z from "zod";

export const SCOPES = ["notes:read", "notes:write"] as const;

/** The demo sign-in offers these accounts. There are no passwords: this is a demo. */
export const DEMO_ACCOUNTS = [
  { id: "user-1", label: "Demo account one (user-1@example.com)" },
  { id: "user-2", label: "Demo account two (user-2@example.com)" },
] as const;

export interface Note {
  id: string;
  title: string;
  body: string;
}

/** Notes per account id. */
export class Notebooks {
  readonly #notes = new Map<string, Note[]>();
  #next = 1;

  constructor() {
    this.add("user-1", "Garden plan", "Tomatoes along the south fence, basil beside them.");
    this.add("user-1", "Book list", "Three novels and a field guide to clouds.");
    this.add("user-2", "Trip checklist", "Tickets, charger, the blue umbrella.");
  }

  list(owner: string): Note[] {
    return [...(this.#notes.get(owner) ?? [])];
  }

  get(owner: string, id: string): Note | undefined {
    return this.#notes.get(owner)?.find((note) => note.id === id);
  }

  add(owner: string, title: string, body: string): Note {
    const note = { id: `note-${this.#next++}`, title, body };
    this.#notes.set(owner, [...this.list(owner), note]);
    return note;
  }
}

function ownerOf(authInfo: AuthInfo | undefined): string {
  const subject = authInfo?.extra?.subject;
  // The HTTP layer only reaches the MCP handler with a verified token, so this cannot be missing.
  if (typeof subject !== "string") throw new Error("no authenticated subject");
  return subject;
}

const text = (value: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(value) }] });

/** One MCP server instance for one request (the SDK's handler calls this per request). */
export function notesServer(notebooks: Notebooks): McpServer {
  const server = new McpServer({ name: "mcp-frontdesk-example", version: "0.0.0" });

  server.registerTool(
    "list_notes",
    { description: "List the signed-in person's notes: id and title.", annotations: { readOnlyHint: true } },
    async (ctx) => text(notebooks.list(ownerOf(ctx.http?.authInfo)).map(({ id, title }) => ({ id, title }))),
  );

  server.registerTool(
    "read_note",
    {
      description: "Read one note by id.",
      inputSchema: z.object({ id: z.string() }),
      annotations: { readOnlyHint: true },
    },
    async ({ id }, ctx) => {
      const note = notebooks.get(ownerOf(ctx.http?.authInfo), id);
      return note ? text(note) : { content: [{ type: "text", text: `No note ${id}.` }], isError: true };
    },
  );

  server.registerTool(
    "add_note",
    {
      description: "Add a note. Needs the notes:write scope.",
      inputSchema: z.object({ title: z.string().min(1).max(100), body: z.string().max(2000) }),
      scopeChallenge: requireScopes("notes:write"),
    },
    async ({ title, body }, ctx) => text(notebooks.add(ownerOf(ctx.http?.authInfo), title, body)),
  );

  return server;
}
