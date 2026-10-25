import assert from "node:assert/strict";
import { test } from "node:test";

const timers = new Map();
let timerId = 0;
globalThis.setTimeout = (run, delay) => {
  const id = ++timerId;
  timers.set(id, { run, delay });
  return id;
};
globalThis.clearTimeout = (id) => timers.delete(id);
globalThis.__DEV__ = true;

const folder = new Map();
const keys = new Set();
const forgotten = [];
const folderCalls = [];
let ids = 0;
let chainStatus = "ok";
let nameUnavailable = false;
let onWrite = null;
let beforeWrite = null;
globalThis.acTestNativeModules = {
  ArdiaSync: {
    newDeviceId: () => `dev${++ids}`,
    deviceName: () => {
      if (nameUnavailable) throw new Error("Device name unavailable");
      return "Test Mac";
    },
    createPhrase: async (id) => (keys.add(id), true),
    createChain: async () => { folderCalls.push("createChain"); },
    unlock: async (id) => keys.has(id),
    forget: async (id) => { forgotten.push(id); keys.delete(id); },
    chainStatus: async () => chainStatus,
    write: async (_folder, scope, payload) => {
      folderCalls.push("write");
      beforeWrite?.(JSON.parse(payload));
      if (chainStatus === "missing") throw new Error("Sync data is missing from this folder.");
      const id = `f${folder.size + 1}`;
      folder.set(id, { scope, payload });
      onWrite?.(JSON.parse(payload));
      return id;
    },
    read: async (_folder, scope, known) => {
      folderCalls.push("read");
      const here = [...folder].filter(([, file]) => file.scope === scope);
      return {
        files: here.filter(([id]) => !known.includes(id)).map(([id, file]) => ({ id, payload: file.payload })),
        pending: [],
        damaged: [],
        present: here.map(([id]) => id),
      };
    },
    remove: async (_folder, _scope, list) => { folderCalls.push("remove"); list.forEach((id) => folder.delete(id)); },
    sealLocal: async (text) => `sealed:${text}`,
    openLocal: async (sealed) => sealed.startsWith("sealed:") ? sealed.slice(7) : null,
    readPasswords: async () => null,
  },
};

const shell = await import("@ardia/shell");
const { useBrowser } = await import("../store/browser.ts");
const S = () => useBrowser.getState();
const settle = async () => {
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve));
};
const syncDisk = () => new Map(["sync.json", "sync-state.nns", "sync-journal.nns"].map((name) => [name, shell.docs.get(name)]));
const logs = () => [...folder.values()].map(({ payload }) => JSON.parse(payload)).filter((file) => file.kind === "log");
const freshFolder = () => {
  shell.bookmarkDbs.clear();
  S().hydrate({});
  useBrowser.setState({ bookmarksReady: { default: true } });
  shell.docs.clear();
  folder.clear();
  timers.clear();
  keys.clear();
  forgotten.length = 0;
  folderCalls.length = 0;
  chainStatus = "ok";
  nameUnavailable = false;
  onWrite = null;
  beforeWrite = null;
};
const start = (engine) => {
  engine.startSync();
  return globalThis.acSync.doc;
};
const retry = async () => {
  const entry = [...timers].find(([, timer]) => timer.delay === 15_000);
  assert.ok(entry, "sync automatically retries while the chain is missing");
  timers.delete(entry[0]);
  entry[1].run();
  await settle();
};

test("a missing chain retains the key and local state, then automatically publishes edits when it returns", async () => {
  freshFolder();
  const engine = await import("./engine.ts?missing-live");
  const doc = start(engine);
  assert.ok("ok" in (await engine.turnOnSync("/sync")));
  S().addBookmark({ profileId: "default", url: "https://before.example/", title: "Before" });
  await engine.syncNow();
  await settle();
  assert.equal(engine.useSync.getState().status, "updated");
  const before = structuredClone(doc());
  const disk = syncDisk();
  const calls = folderCalls.length;
  const beforeLog = logs().find((file) => file.ops.some((op) => op.v?.t === "Before"));
  assert.ok(beforeLog);

  chainStatus = "missing";
  S().addBookmark({ profileId: "default", url: "https://queued.example/", title: "Queued" });
  await engine.syncNow();
  await settle();
  assert.deepEqual(forgotten, [], "an untrusted disappearance cannot forget the local key");
  assert.ok(keys.has(before.deviceId));
  assert.equal(engine.useSync.getState().enabled, true);
  assert.equal(engine.useSync.getState().status, "stalled");
  assert.match(engine.useSync.getState().error, /missing/i);
  assert.deepEqual(doc(), before, "clock, seqs, profiles, records and queued state survive");
  assert.deepEqual(syncDisk(), disk);
  await retry();
  assert.equal(folderCalls.length, calls, "no reads, writes, removals or chain creation while the chain is missing");
  assert.deepEqual(syncDisk(), disk);

  chainStatus = "ok";
  await retry();
  assert.equal(engine.useSync.getState().status, "updated");
  assert.equal(engine.useSync.getState().error, null);
  const queued = logs().find((file) => file.ops.some((op) => op.v?.t === "Queued"));
  assert.ok(queued, "the edit made during disappearance is sent after recovery");
  assert.equal(queued.device, before.deviceId);
  assert.equal(queued.seq, beforeLog.seq + 1);
  assert.deepEqual(forgotten, []);
});

test("a missing chain after restart preserves the crash journal and replays its original sequence on recovery", async () => {
  freshFolder();
  const first = await import("./engine.ts?missing-crash-before");
  start(first);
  assert.ok("ok" in (await first.turnOnSync("/sync")));
  await first.syncNow();
  await settle();
  let disk;
  let original;
  onWrite = (file) => {
    if (file.ops?.some((op) => op.v?.t === "Journalled")) {
      disk = syncDisk();
      original = structuredClone(file);
    }
  };
  S().addBookmark({ profileId: "default", url: "https://journalled.example/", title: "Journalled" });
  await first.syncNow();
  await settle();
  onWrite = null;
  assert.ok(disk?.get("sync-journal.nns"));
  assert.ok(original);
  for (const [name, contents] of disk) shell.docs.set(name, contents);
  timers.clear();
  chainStatus = "missing";
  const second = await import("./engine.ts?missing-crash-after");
  const doc = start(second);
  await settle();
  const before = structuredClone(doc());
  const scope = `p:${before.profiles.default.syncId}`;
  assert.deepEqual(before.scopes[scope].journal, [original]);
  const calls = folderCalls.length;
  await second.syncNow();
  await settle();
  assert.deepEqual(forgotten, [], "restart with missing remote data cannot revoke the local key");
  assert.equal(second.useSync.getState().enabled, true);
  assert.equal(second.useSync.getState().status, "stalled");
  assert.deepEqual(doc(), before, "the pending journal and its sequence stay in memory");
  assert.deepEqual(syncDisk(), disk, "missing data cannot clear or rewrite the durable crash journal");
  S().addBookmark({ profileId: "default", url: "https://after-restart.example/", title: "After restart" });
  await second.syncNow();
  await settle();
  assert.equal(folderCalls.length, calls);
  assert.deepEqual(syncDisk(), disk);

  chainStatus = "ok";
  await retry();
  assert.equal(second.useSync.getState().status, "updated");
  const replayed = logs().filter((file) => file.device === original.device && file.seq === original.seq && file.ops.some((op) => op.v?.t === "Journalled"));
  assert.equal(replayed.length, 2, "the crash journal is replayed once after the chain returns");
  for (const file of replayed) assert.deepEqual(file, original);
  const after = logs().find((file) => file.ops.some((op) => op.v?.t === "After restart"));
  assert.ok(after);
  assert.equal(after.seq, original.seq + 1);
  assert.equal(after.device, original.device);
  assert.ok(keys.has(original.device));
  assert.equal(shell.docs.get("sync-journal.nns"), "", "only durable recovery can prune the journal");
});

test("a missing chain preserves an unflushed outbox until automatic recovery", async () => {
  freshFolder();
  const engine = await import("./engine.ts?missing-outbox");
  const doc = start(engine);
  assert.ok("ok" in (await engine.turnOnSync("/sync")));
  await engine.syncNow();
  await settle();
  S().updateSettings({ bookmarksBar: "always" });
  nameUnavailable = true;
  await engine.syncNow();
  await settle();
  nameUnavailable = false;
  assert.equal(engine.useSync.getState().status, "stalled");
  const before = structuredClone(doc());
  assert.ok(before.scopes.app.outbox.length > 0, "an extraction failure leaves edits queued before flush");
  const disk = syncDisk();
  assert.deepEqual(JSON.parse(disk.get("sync-state.nns").slice(7)).app.outbox, before.scopes.app.outbox, "unrelated failures still save the unflushed outbox durably");
  const calls = folderCalls.length;

  chainStatus = "missing";
  await engine.syncNow();
  await settle();
  assert.deepEqual(doc(), before, "missing remote data cannot discard the unflushed outbox");
  assert.deepEqual(syncDisk(), disk);
  assert.equal(folderCalls.length, calls);
  assert.deepEqual(forgotten, []);

  chainStatus = "ok";
  await retry();
  assert.equal(engine.useSync.getState().status, "updated");
  const published = logs().find((file) => file.device === before.deviceId && file.ops.some((op) => op.k === before.scopes.app.outbox[0].k && op.h === before.scopes.app.outbox[0].h));
  assert.ok(published);
  assert.equal(published.seq, before.scopes.app.seq + 1);
  for (const op of before.scopes.app.outbox) assert.ok(published.ops.some((sent) => JSON.stringify(sent) === JSON.stringify(op)));
  assert.deepEqual(doc().scopes.app.outbox, []);
});

test("a chain disappearing after preflight retains the write journal through restart and automatic recovery", async () => {
  freshFolder();
  const first = await import("./engine.ts?missing-during-write-before");
  const doc = start(first);
  assert.ok("ok" in (await first.turnOnSync("/sync")));
  await first.syncNow();
  await settle();
  const before = structuredClone(doc());
  const disk = syncDisk();
  let original;
  let journalAtWrite;
  beforeWrite = (file) => {
    if (!file.ops?.some((op) => op.v?.t === "Interrupted")) return;
    original = structuredClone(file);
    journalAtWrite = shell.docs.get("sync-journal.nns");
    chainStatus = "missing";
  };
  S().addBookmark({ profileId: "default", url: "https://interrupted.example/", title: "Interrupted" });
  await first.syncNow();
  await settle();
  beforeWrite = null;
  assert.ok(original, "the preflight succeeds before the chain disappears at the write");
  assert.ok(journalAtWrite, "the pending batch reaches disk before the transport fails");
  assert.equal(first.useSync.getState().status, "stalled");
  assert.match(first.useSync.getState().error, /missing/i);
  assert.match(first.useSync.getState().error, /local sync data is kept.*retry automatically/i);
  const interruptedMessage = first.useSync.getState().error;
  assert.equal(shell.docs.get("sync-journal.nns"), journalAtWrite, "a missing transport cannot prune the durable journal");
  assert.equal(shell.docs.get("sync-state.nns"), disk.get("sync-state.nns"), "a missing transport cannot replace the last saved state");
  assert.equal(shell.docs.get("sync.json"), disk.get("sync.json"));
  const scope = `p:${before.profiles.default.syncId}`;
  assert.deepEqual(doc().scopes[scope].journal, [original]);
  assert.ok(keys.has(before.deviceId));
  assert.deepEqual(forgotten, []);
  const calls = folderCalls.length;
  await retry();
  assert.equal(first.useSync.getState().error, interruptedMessage, "preflight and interrupted-cycle failures explain retention and retry consistently");
  assert.equal(folderCalls.length, calls);
  assert.equal(shell.docs.get("sync-journal.nns"), journalAtWrite);
  S().addBookmark({ profileId: "default", url: "https://queued-after-interruption.example/", title: "Queued after interruption" });
  await first.syncNow();
  await settle();
  assert.equal(folderCalls.length, calls);
  assert.equal(shell.docs.get("sync-journal.nns"), journalAtWrite);

  timers.clear();
  const second = await import("./engine.ts?missing-during-write-after");
  const restored = start(second);
  await settle();
  assert.deepEqual(restored().scopes[scope].journal, [original]);
  await second.syncNow();
  await settle();
  assert.equal(folderCalls.length, calls);
  assert.equal(shell.docs.get("sync-journal.nns"), journalAtWrite);

  chainStatus = "ok";
  await retry();
  assert.equal(second.useSync.getState().status, "updated");
  const replayed = logs().filter((file) => file.device === original.device && file.seq === original.seq && file.ops.some((op) => op.v?.t === "Interrupted"));
  assert.deepEqual(replayed, [original], "the failed write is replayed with its original identity and payload");
  const queued = logs().find((file) => file.ops.some((op) => op.v?.t === "Queued after interruption"));
  assert.ok(queued);
  assert.equal(queued.seq, original.seq + 1);
  assert.equal(queued.device, original.device);
  assert.equal(shell.docs.get("sync-journal.nns"), "");
  assert.deepEqual(forgotten, []);
});
