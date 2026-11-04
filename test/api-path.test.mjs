// Run `npm run build` first.
import assert from "node:assert/strict";
import { test } from "node:test";
import { apiPath } from "../dist/apiPath.js";

test("base64 workflow IDs reach the API unencoded", () => {
  assert.equal(apiPath`/workflows/${"Zi9yYWQ+dGVzdA=="}/runs`, "/workflows/Zi9yYWQ+dGVzdA==/runs");
});

test("values that could leave their path segment stay encoded", () => {
  assert.equal(apiPath`/a/${"../b"}`, "/a/..%2Fb");
  assert.equal(apiPath`/a/${"b?c=d"}`, "/a/b%3Fc=d");
  assert.equal(apiPath`/a/${"b#c"}`, "/a/b%23c");
  assert.equal(apiPath`/a/${"b%3Dc"}`, "/a/b%253Dc");
});
