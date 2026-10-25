import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { docs, heldSaves, saveDocument, writeDocument } from "./test-native-stub.mjs";
import { holdDocumentSaves } from "./test-held-saves.mjs";

test("held save notification follows enqueueing and precedes document mutation and completion", async () => {
  const name = "held-save-fixture";
  let finished = false;
  let notifications = 0;
  heldSaves.on = true;
  heldSaves.onQueued = () => {
    notifications++;
    assert.equal(heldSaves.queue.length, 1);
    assert.equal(docs.has(name), false);
    assert.equal(finished, false);
  };
  const saving = saveDocument(name, "durable").then(() => { finished = true; });
  try {
    assert.equal(notifications, 1);
    assert.equal(finished, false);
    heldSaves.queue.shift()();
    await saving;
    assert.equal(docs.get(name), "durable");
    assert.equal(finished, true);
  } finally {
    heldSaves.onQueued = null;
    heldSaves.on = false;
    for (const land of heldSaves.queue.splice(0)) land();
    await saving;
    docs.delete(name);
  }
});

test("abort synchronously drains held saves and prevents late document writes", { timeout: 5000 }, async (t) => {
  const controller = new AbortController();
  const held = holdDocumentSaves({ signal: controller.signal, after: (cleanup) => t.after(cleanup) }, async () => {
    await saveDocument("aborted-save", "old");
    writeDocument("late-write", "old");
    await saveDocument("late-save", "old");
  });
  await held.queued;
  controller.abort(new Error("fixture cancelled"));
  assert.equal(heldSaves.onQueued, null);
  assert.equal(heldSaves.on, false);
  assert.equal(heldSaves.queue.length, 0);
  assert.equal(docs.has("aborted-save"), false);
  await held.pending;
  assert.equal(docs.has("late-write"), false);
  assert.equal(docs.has("late-save"), false);
});

test("a real test timeout releases the fixture before the next test and quarantines late work", { timeout: 15000 }, () => {
  const stub = new URL("./test-native-stub.mjs", import.meta.url).href;
  const helper = new URL("./test-held-saves.mjs", import.meta.url).href;
  const source = `
import assert from "node:assert/strict";
import { test } from "node:test";
import { docs, heldSaves, saveDocument, writeDocument } from ${JSON.stringify(stub)};
import { holdDocumentSaves } from ${JSON.stringify(helper)};
const delayed = Promise.withResolvers();
let previous;
test("held operation times out", { timeout: 50 }, async (t) => {
  const keepAlive = setTimeout(() => {}, 5000);
  t.after(() => clearTimeout(keepAlive));
  previous = holdDocumentSaves(t, async () => {
    await delayed.promise;
    writeDocument("late-write", "old");
    await saveDocument("late-save", "old");
  });
  await previous.queued;
});
test("next fixture survives the previous operation resuming", { timeout: 1000 }, async (t) => {
  assert.equal(heldSaves.onQueued, null);
  assert.equal(heldSaves.on, false);
  assert.equal(heldSaves.queue.length, 0);
  docs.set("late-save", "next-state");
  const current = holdDocumentSaves(t, () => saveDocument("current-save", "current"));
  await current.queued;
  const listener = heldSaves.onQueued;
  delayed.resolve();
  await previous.pending;
  assert.equal(heldSaves.onQueued, listener);
  assert.equal(heldSaves.on, true);
  assert.equal(heldSaves.queue.length, 1);
  assert.equal(docs.has("late-write"), false);
  assert.equal(docs.get("late-save"), "next-state");
  heldSaves.queue.shift()();
  await current.pending;
  current.close();
  assert.equal(docs.get("current-save"), "current");
  console.log("TIMEOUT_CLEANUP_AND_LATE_WORK_VERIFIED");
});
`;
  const child = spawnSync(process.execPath, ["--no-warnings", "--input-type=module", "--eval", source], { encoding: "utf8", timeout: 10000 });
  assert.equal(child.error, undefined);
  assert.equal(child.signal, null);
  assert.equal(child.status, 1, "only the deliberately timed-out child test fails");
  assert.match(child.stdout, /TIMEOUT_CLEANUP_AND_LATE_WORK_VERIFIED/);
  assert.match(child.stdout, /cancelled 1/);
  assert.match(child.stdout, /pass 1/);
  assert.match(child.stdout, /fail 0/);
});
