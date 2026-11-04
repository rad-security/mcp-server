// Black-box tests for tenant-scoped sessions: they run the built server against a fake RAD API and
// talk to it with a real MCP client. Run `npm run build` first.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { once } from "node:events";
import { after, before, test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const SERVER = new URL("../dist/index.js", import.meta.url).pathname;
const TENANT = "t-1";
const CHILD = "a-child";
const FOREIGN = "a-foreign"; // the identity can access this account, but it is in another tenant
const TOKEN = "ory_st_test";
const WORKFLOW = "Zi9yYWQ+dGVzdA=="; // workflow IDs are standard base64

let api;
let apiUrl;
let requests = [];

before(async () => {
  api = createServer((req, res) => {
    const url = new URL(req.url, "http://fake");
    requests.push({ method: req.method, path: url.pathname, query: url.searchParams });
    const json = (body) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(body));
    };

    if (url.pathname === "/accounts") {
      return json({
        accounts: [{ id: CHILD, name: "Child", parent_id: TENANT, created_at: "2026-01-01" }],
      });
    }
    if (url.pathname === `/accounts/${CHILD}`) return json({ id: CHILD, parent_id: TENANT });
    if (url.pathname === `/accounts/${FOREIGN}`) return json({ id: FOREIGN, parent_id: "t-other" });
    if (url.pathname === `/accounts/${TENANT}`) return json({ id: TENANT });
    if (url.pathname === `/accounts/${CHILD}/clusters`) return json({ clusters: ["c-1"] });
    if (url.pathname === `/accounts/a-direct/clusters`) return json({ clusters: ["c-direct"] });
    if (url.pathname === `/tenants/${TENANT}/integrations/external`) return json({ integrations: [] });
    if (url.pathname === `/accounts/${CHILD}/workflows/${WORKFLOW}/runs`) return json({ runs: [] });
    res.statusCode = 404;
    return json({ error: `unexpected ${url.pathname}` });
  });
  api.listen(0, "127.0.0.1");
  await once(api, "listening");
  apiUrl = `http://127.0.0.1:${api.address().port}`;
});

after(() => api.close());

async function connectStdio(env) {
  const client = new Client({ name: "test", version: "1.0.0" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [SERVER],
      stderr: "ignore",
      env: {
        PATH: process.env.PATH,
        LOG_LEVEL: "silent",
        RAD_SECURITY_API_URL: apiUrl,
        RAD_SECURITY_SESSION_TOKEN: TOKEN,
        ...env,
      },
    })
  );
  return client;
}

const tenantEnv = { RAD_SECURITY_TENANT_ID: TENANT };

async function withClient(env, fn) {
  const client = await connectStdio(env);
  try {
    requests = [];
    await fn(client);
  } finally {
    await client.close();
  }
}

const toolNames = async (client) => (await client.listTools()).tools.map((t) => t.name);
const callJson = async (client, name, args = {}) =>
  JSON.parse((await client.callTool({ name, arguments: args })).content[0].text);

test("account mode: tools and arguments are unchanged", async () => {
  await withClient({ RAD_SECURITY_ACCOUNT_ID: "a-direct", RAD_SECURITY_TENANT_ID: TENANT }, async (client) => {
    const { tools } = await client.listTools();
    assert.ok(!tools.some((t) => t.name === "list_accounts"));
    assert.ok(!tools.some((t) => t.inputSchema.properties?.account_id));
    assert.ok(tools.some((t) => t.annotations?.readOnlyHint === false), "writes stay available");

    assert.deepEqual(await callJson(client, "list_clusters"), { clusters: ["c-direct"] });
    assert.deepEqual(requests.map((r) => r.path), ["/accounts/a-direct/clusters"]);
  });
});

test("tenant mode: tools require account_id, except tenant-level ones", async () => {
  await withClient(tenantEnv, async (client) => {
    const { tools } = await client.listTools();
    for (const tool of tools) {
      const tenantLevel = ["list_accounts", "list_external_integrations"].includes(tool.name);
      assert.equal(tool.inputSchema.required?.includes("account_id") ?? false, !tenantLevel, tool.name);
    }
  });
});

test("tenant mode: list_accounts returns the tenant's children, trimmed to id and name", async () => {
  await withClient(tenantEnv, async (client) => {
    assert.deepEqual(await callJson(client, "list_accounts"), {
      accounts: [{ id: CHILD, name: "Child" }],
    });
    assert.equal(requests[0].query.get("parent_id"), TENANT);
    assert.equal(requests[0].query.get("exclude_parent"), "true");
  });
});

test("tenant mode: a child account is routed to that account", async () => {
  await withClient(tenantEnv, async (client) => {
    const result = await callJson(client, "list_clusters", { account_id: CHILD });
    assert.deepEqual(result, { clusters: ["c-1"] });
    assert.deepEqual(requests.map((r) => r.path), [`/accounts/${CHILD}`, `/accounts/${CHILD}/clusters`]);
    assert.equal(requests[1].query.has("account_id"), false);
  });
});

test("tenant mode: base64 workflow IDs reach the API unencoded", async () => {
  await withClient(tenantEnv, async (client) => {
    const result = await callJson(client, "list_workflow_runs", { account_id: CHILD, workflow_id: WORKFLOW });
    assert.equal(result.error, undefined);
    assert.equal(requests.at(-1).path, `/accounts/${CHILD}/workflows/${WORKFLOW}/runs`);
  });
});

test("tenant mode: missing, foreign and tenant account IDs are rejected without running the tool", async () => {
  await withClient(tenantEnv, async (client) => {
    assert.match((await callJson(client, "list_clusters")).error, /"account_id" is required/);
    for (const accountId of [FOREIGN, TENANT]) {
      const { error } = await callJson(client, "list_clusters", { account_id: accountId });
      assert.match(error, /not a child account/);
    }
    assert.ok(!requests.some((r) => r.path.endsWith("/clusters")));
  });
});

test("tenant mode: tenant-level tools don't need an account", async () => {
  await withClient(tenantEnv, async (client) => {
    assert.deepEqual(await callJson(client, "list_external_integrations"), { integrations: [] });
  });
});

test("tenant mode: read-only by default, enforced on call as well as in the list", async () => {
  await withClient(tenantEnv, async (client) => {
    const { tools } = await client.listTools();
    assert.ok(tools.every((t) => t.annotations?.readOnlyHint === true));
    const { error } = await callJson(client, "ignore_cve", { account_id: CHILD });
    assert.match(error, /not enabled/);
  });
});

test("tenant mode: RAD_SECURITY_READONLY=false enables writes", async () => {
  await withClient({ ...tenantEnv, RAD_SECURITY_READONLY: "false" }, async (client) => {
    assert.ok((await toolNames(client)).includes("ignore_cve"));
  });
});

test("hosted: credential forms, read-only header, and rejected credentials", async () => {
  const port = 39000 + Math.floor(Math.random() * 1000);
  const server = spawn(process.execPath, [SERVER], {
    stdio: "ignore",
    env: {
      PATH: process.env.PATH,
      LOG_LEVEL: "silent",
      TRANSPORT_TYPE: "streamable",
      MCP_AUTH_MODE: "header",
      PORT: String(port),
      RAD_SECURITY_API_URL: apiUrl,
    },
  });
  const url = `http://127.0.0.1:${port}/mcp`;

  try {
    await waitForHealthy(`http://127.0.0.1:${port}/healthz`);

    const connect = async (headers) => {
      const client = new Client({ name: "test", version: "1.0.0" });
      await client.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers } }));
      return client;
    };

    const tenant = await connect({ Authorization: `Bearer ${TOKEN}:tenant=${TENANT}` });
    let names = await toolNames(tenant);
    assert.ok(names.includes("list_accounts"));
    assert.ok(!names.includes("ignore_cve"));
    assert.deepEqual(await callJson(tenant, "list_clusters", { account_id: CHILD }), { clusters: ["c-1"] });
    await tenant.close();

    const tenantWrites = await connect({
      Authorization: `Bearer ${TOKEN}:tenant=${TENANT}`,
      "X-Rad-Readonly": "false",
    });
    assert.ok((await toolNames(tenantWrites)).includes("ignore_cve"));
    await tenantWrites.close();

    const account = await connect({ Authorization: `Bearer ${TOKEN}:a-direct` });
    names = await toolNames(account);
    assert.ok(!names.includes("list_accounts"));
    assert.ok(names.includes("ignore_cve"));
    await account.close();

    for (const credential of [`${TOKEN}:tenant=`, `key:secret:tenant=`]) {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${credential}`,
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      });
      assert.equal(response.status, 401, credential);
    }
  } finally {
    server.kill();
  }
});

async function waitForHealthy(url) {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(url)).ok) return;
    } catch {
      // not listening yet
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("server did not become healthy");
}
