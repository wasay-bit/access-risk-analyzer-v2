// HTTP server: serves the page in public/ and the JSON API under /api.
// Run with: npm start

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadUsers, userFromAuthHeader } from "./auth.js";
import { AccessRiskService } from "./service.js";
import { FileStore } from "./file-store.js";

const here = fileURLToPath(new URL(".", import.meta.url));
const DEFAULT_PUBLIC = resolve(here, "..", "public");
const MAX_BODY = 64 * 1024;

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "content-security-policy":
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function send(res, status, body) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...SECURITY_HEADERS,
  });
  res.end(JSON.stringify(body));
}

async function readJson(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new HttpError(413, "Request is too large.");
    chunks.push(chunk);
  }
  if (size === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "Request body must be JSON.");
  }
}

async function serveStatic(res, publicDir, pathname) {
  const rel = pathname === "/" ? "index.html" : pathname.slice(1);
  const full = resolve(publicDir, rel);
  if (!full.startsWith(publicDir + sep)) throw new HttpError(404, "Not found.");
  let data;
  try {
    data = await readFile(full);
  } catch {
    throw new HttpError(404, "Not found.");
  }
  res.writeHead(200, {
    "content-type": TYPES[extname(full)] ?? "application/octet-stream",
    ...SECURITY_HEADERS,
  });
  res.end(data);
}

async function route(req, res, url, user, service) {
  const p = url.pathname;
  const m = req.method;

  if (p === "/api/me" && m === "GET") return send(res, 200, { name: user });
  if (p === "/api/policy" && m === "GET") return send(res, 200, service.policy());
  if (p === "/api/requests" && m === "GET") return send(res, 200, await service.list());
  if (p === "/api/requests" && m === "POST") {
    return send(res, 201, await service.submit(user, await readJson(req)));
  }
  if (p === "/api/audit" && m === "GET") {
    return send(res, 200, await service.audit(Number(url.searchParams.get("limit")) || 100));
  }
  if (p === "/api/seed" && m === "POST") return send(res, 200, await service.seedDemo());

  const decision = p.match(/^\/api\/requests\/(AR-\d{4,})\/decision$/);
  if (decision && m === "POST") {
    return send(res, 200, await service.decide(user, decision[1], await readJson(req)));
  }
  throw new HttpError(404, "Not found.");
}

// Builds the server without starting it, so tests can run it on any port.
export function createApp({ service, users, publicDir = DEFAULT_PUBLIC }) {
  const root = resolve(publicDir);
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://localhost");
      if (!url.pathname.startsWith("/api/")) {
        if (req.method !== "GET") throw new HttpError(405, "Method not allowed.");
        return await serveStatic(res, root, url.pathname);
      }
      const user = userFromAuthHeader(req.headers.authorization, users);
      if (!user) throw new HttpError(401, "Sign in with your access token.");
      await route(req, res, url, user, service);
    } catch (err) {
      const status = err.status ?? 500;
      if (status === 500) console.error(err);
      send(res, status, { error: status === 500 ? "Something went wrong." : err.message });
    }
  });
}

async function main() {
  const port = Number(process.env.PORT ?? 3000);
  const host = process.env.HOST ?? "127.0.0.1";
  const usersPath = process.env.ARA_USERS ?? join(here, "..", "data", "users.json");
  const statePath = process.env.ARA_DATA ?? join(here, "..", "data", "state.json");

  let usersDoc;
  try {
    usersDoc = JSON.parse(await readFile(usersPath, "utf8"));
  } catch {
    console.error(`No users file at ${usersPath}. Run "npm run setup" first.`);
    process.exit(1);
  }

  const service = new AccessRiskService({ store: new FileStore(statePath) });
  const server = createApp({ service, users: loadUsers(usersDoc) });
  server.listen(port, host, () => {
    console.log(`Access Risk Analyzer running at http://${host}:${port}`);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main();
}
