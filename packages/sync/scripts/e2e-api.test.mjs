import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { runInNewContext } from "node:vm";

const source = readFileSync(new URL("./e2e.mjs", import.meta.url), "utf8");
const native = readFileSync(new URL("../src/native.ts", import.meta.url), "utf8");
const start = source.indexOf("async function state(name) {");
const end = source.indexOf("function bip39(entropy) {", start);
assert.ok(start > 0 && end > start);
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const key = "pw:https://fixture.example\nfixture";
const fingerprint = Buffer.alloc(32, 7).toString("base64");
const record = (sealed) => ({ key, value: { version: 2, sealed, fingerprint }, created: 123 });

function harness({ allowed = true, records = () => [record("random-sealed-value")], passwords = true, enabled = true } = {}) {
  const calls = [];
  const doc = { enabled, folder: "/scratch/synthetic-chain", profiles: { default: { enabled: true, syncId: "a".repeat(26) } } };
  const ui = { enabled, types: { passwords: false }, devices: [], remoteTabs: {} };
  const acSync = {
    doc: () => doc,
    useSync: { getState: () => ui },
    menu: { syncedDevicesMenuItem: () => null },
    setTypeSynced: (type, on) => { calls.push(["setTypeSynced", type, on]); ui.types[type] = on; },
    syncNow: async () => { calls.push(["syncNow"]); },
    authorizePasswords: async () => { calls.push(["authorizePasswords"]); return allowed; },
    native: {
      passwordSyncAuthorized: async (...args) => { calls.push(["passwordSyncAuthorized", ...args]); return allowed; },
      readPasswordRecords: async (...args) => { calls.push(["readPasswordRecords", ...args]); return records(); },
    },
  };
  const ac = { store: { getState: () => ({
    bookmarks: { roots: { default: { bar: "bar", other: "other" } }, nodes: { bar: { title: "bar", children: [] }, other: { title: "other", children: [] } } },
    history: {}, settings: {}, tabs: {}, groups: {},
  }) } };
  const globalThis = { expo: { modules: { ArdiaCEF: { listPasswords: async () => ({ passwords: [{ origin: "https://fixture.example", username: "fixture" }] }) } } } };
  const api = runInNewContext(`${source.slice(start, end)}\n({ state, passwordRecords, capturePassword, authorizePasswords, same, hasPassword });`, {
    PASSWORDS: passwords,
    ev: async (_name, body) => new AsyncFunction("acSync", "ac", "globalThis", body)(acSync, ac, globalThis),
  });
  return { ...api, calls };
}

test("state uses the current bound native API and compares fingerprints, not ciphertext", async () => {
  let reads = 0;
  const h = harness({ records: () => [record(`random-ciphertext-${++reads}`)] });
  const a = await h.state("A");
  const b = await h.state("B");
  assert.equal(h.same(a, b), true);
  assert.deepEqual(a.passwords, [{ key, fingerprint }]);
  assert.equal(JSON.stringify(a).includes("random-ciphertext"), false);
  assert.deepEqual(h.calls.filter(([method]) => method === "readPasswordRecords"), [
    ["readPasswordRecords", "/scratch/synthetic-chain", `p:${"a".repeat(26)}`, ""],
    ["readPasswordRecords", "/scratch/synthetic-chain", `p:${"a".repeat(26)}`, ""],
  ]);
  assert.match(native, /readPasswordRecords\(folder: string, scope: string, engineProfile: string\)/);
  assert.doesNotMatch(source, /\.readPasswords\s*\(/);
});

test("expired authorization fails instead of reading or treating denial as an empty store", async () => {
  const h = harness({ allowed: false });
  await assert.rejects(h.state("A"), /authorization is absent or expired/);
  assert.equal(h.calls.some(([method]) => method === "readPasswordRecords"), false);
});

test("null, malformed and duplicate records are failures", async () => {
  await assert.rejects(harness({ records: () => null }).passwordRecords("A"), /null is not an empty/);
  await assert.rejects(harness({ records: () => [{ key, value: { version: 1 } }] }).passwordRecords("A"), /Invalid opaque/);
  await assert.rejects(harness({ records: () => [record("one"), record("two")] }).passwordRecords("A"), /Duplicate/);
});

test("known fixture capture requires a stable fingerprint for its exact key", async () => {
  const h = harness();
  const expected = await h.capturePassword("A", "https://fixture.example/", "fixture");
  assert.deepEqual(expected, { key, fingerprint });
  assert.equal(h.hasPassword({ passwords: [{ key, fingerprint }] }, expected), true);
  assert.equal(h.hasPassword({ passwords: [{ key, fingerprint: "changed" }] }, expected), false);
  await assert.rejects(h.capturePassword("A", "https://missing.example", "fixture"), /known fixture is missing/);
  let reads = 0;
  const unstable = harness({ records: () => [{ ...record("sealed"), value: { ...record("sealed").value, fingerprint: Buffer.alloc(32, ++reads).toString("base64") } }] });
  await assert.rejects(unstable.capturePassword("A", "https://fixture.example", "fixture"), /fingerprint is unstable/);
});

test("full mode explicitly opts in before authorization and denial gives actionable alternatives", async () => {
  const h = harness({ allowed: false });
  await assert.rejects(h.authorizePasswords("A"), /ARDIA_BACKGROUND=1 refuses LocalAuthentication.*--non-passwords.*--denial/);
  assert.deepEqual(h.calls, [["setTypeSynced", "passwords", true], ["syncNow"], ["authorizePasswords"]]);
});

test("non-password and stopped-sync state do not call protected record APIs", async () => {
  for (const options of [{ passwords: false }, { enabled: false }]) {
    const h = harness({ allowed: false, ...options });
    const state = await h.state("A");
    assert.equal(state.passwords, null);
    assert.deepEqual(state.chromePasswords, ["https://fixture.example fixture"]);
    assert.deepEqual(h.calls, []);
  }
});
