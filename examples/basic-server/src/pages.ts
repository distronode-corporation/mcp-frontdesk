/**
 * The demo's HTML: a sign-in page and a consent page, plain forms, no script.
 * Every value from a request or a client's metadata document is escaped.
 */
import type { AuthorizeRequest } from "mcp-frontdesk";

import { DEMO_ACCOUNTS } from "./notes.ts";

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
}

/**
 * No framing (clickjacking), no script, no referrer. There is no `form-action`
 * directive: browsers apply it to the redirect after a submit, and the consent
 * form's answer redirects to the client.
 */
const PAGE_HEADERS = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
};

function page(title: string, body: string, status = 200, headers: Record<string, string> = {}): Response {
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem}button{font:inherit;padding:.4rem 1rem;margin-right:.5rem}.warn{background:#fff3cd;padding:.5rem}</style>
</head>
<body>
${body}
</body>
</html>
`;
  return new Response(html, { status, headers: { ...PAGE_HEADERS, ...headers } });
}

/** Hidden inputs carrying every parameter of the authorization request through the form. */
function hiddenParams(params: URLSearchParams): string {
  return [...params]
    .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
    .join("\n");
}

export function signInPage(next: string): Response {
  const options = DEMO_ACCOUNTS.map((account) => `<option value="${account.id}">${escapeHtml(account.label)}</option>`).join("");
  return page(
    "Sign in",
    `<h1>Sign in</h1>
<p class="warn">Demo sign-in: pick an account, no password. Never deploy this.</p>
<form method="post" action="/signin">
<input type="hidden" name="next" value="${escapeHtml(next)}">
<label>Account <select name="account">${options}</select></label>
<p><button type="submit">Sign in</button></p>
</form>`,
  );
}

export function consentPage(request: AuthorizeRequest, params: URLSearchParams, csrf: string, account: string): Response {
  const scopes = request.scopes.map((scope) => `<li><code>${escapeHtml(scope)}</code></li>`).join("");
  const loopback = request.loopback
    ? `<p class="warn">The answer goes to a program on this computer (${escapeHtml(request.redirectHost)}). Any program here can listen on that address: approve only if you started the connection.</p>`
    : "";
  return page(
    "Connect an app",
    `<h1>Connect an app</h1>
<p><strong>${escapeHtml(request.clientName)}</strong> (from <code>${escapeHtml(request.clientHost)}</code>) wants to use your notes as <code>${escapeHtml(account)}</code>.</p>
<p>It asks for:</p>
<ul>${scopes}</ul>
<p>The answer goes to <code>${escapeHtml(request.redirectHost)}</code>.</p>
${loopback}
<form method="post" action="/authorize">
${hiddenParams(params)}
<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
<button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form>`,
  );
}

export function errorPage(status: number, message: string): Response {
  return page("Something went wrong", `<h1>Something went wrong</h1>\n<p>${escapeHtml(message)}</p>`, status);
}
