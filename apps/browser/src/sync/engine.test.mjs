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
globalThis.__DEV__ = false;

const folder = new Map();
let onWrite = null;
let ids = 0;
let chainStatus = "ok";
const keys = new Set();
const forgotten = [];
const folderCalls = [];
const passwordGrants = new Set();
const passwordCalls = [];
const passwordListeners = new Set();
let consent = true;
let consentWait = null;
let passwordReadWait = null;
let passwordRecords = [];
let passwordApplyResult = true;
let sealFailure = false;
let onPasswordApply = null;
let passwordRevocations = 0;
const passwordKey = (path, scope, profile) => JSON.stringify([path, scope, profile]);
globalThis.acTestNativeModules = {
  ArdiaSync: {
    newDeviceId: () => (++ids).toString(2).padStart(26, "0").replaceAll("0", "a").replaceAll("1", "b"),
    deviceName: () => "Test Mac",
    createPhrase: async (id) => (keys.add(id), true),
    createChain: async () => {},
    unlock: async (id) => keys.has(id),
    forget: async (id) => { forgotten.push(id); keys.delete(id); },
    chainStatus: async () => chainStatus,
    write: async (_folder, scope, payload) => {
      folderCalls.push("write");
      const id = `f${folder.size + 1}`;
      folder.set(id, { scope, payload });
      onWrite?.(JSON.parse(payload));
      return id;
    },
    read: async (_folder, scope, known) => {
      folderCalls.push("read");
      const here = [...folder].filter(([, f]) => f.scope === scope);
      const files = here.filter(([id]) => !known.includes(id)).map(([id, f]) => ({ id, payload: f.payload }));
      return { files, pending: [], damaged: [], present: here.map(([id]) => id) };
    },
    remove: async (_folder, _scope, list) => { folderCalls.push("remove"); list.forEach((id) => folder.delete(id)); },
    sealLocal: async (text) => {
      if (sealFailure) throw new Error("Local sealing failed");
      return `sealed:${text}`;
    },
    openLocal: async (sealed) => {
      if (!sealed.startsWith("sealed:")) throw new Error("Invalid encrypted sync state");
      return sealed.slice(7);
    },
    authorizePasswordSync: async (path, profiles) => {
      assert.ok(profiles.every(({ scope, engineProfile }) => /^p:[a-z2-7]{26}$/.test(scope) && /^[A-Za-z0-9_-]{0,128}$/.test(engineProfile)));
      passwordCalls.push({ kind: "authorize", path, profiles });
      passwordGrants.clear();
      for (const listener of passwordListeners) listener();
      const revision = passwordRevocations;
      if (consentWait) await consentWait;
      if (!consent || revision !== passwordRevocations) return false;
      passwordGrants.clear();
      for (const { scope, engineProfile } of profiles) passwordGrants.add(passwordKey(path, scope, engineProfile));
      return true;
    },
    passwordSyncAuthorized: async (path, scope, profile) => passwordGrants.has(passwordKey(path, scope, profile)),
    revokePasswordSyncAuthorization: () => { passwordRevocations++; passwordGrants.clear(); },
    addListener: (event, listener) => {
      assert.equal(event, "onPasswordSyncInvalidated");
      passwordListeners.add(listener);
      return { remove: () => passwordListeners.delete(listener) };
    },
    readPasswordRecords: async (path, scope, profile) => {
      passwordCalls.push({ kind: "read", path, scope, profile });
      const revision = passwordRevocations;
      if (passwordReadWait) await passwordReadWait;
      return revision === passwordRevocations && passwordGrants.has(passwordKey(path, scope, profile)) ? passwordRecords : null;
    },
    applyPasswordRecords: async (path, scope, profile, changes) => {
      passwordCalls.push({ kind: "apply", path, scope, profile, changes });
      onPasswordApply?.(scope, changes);
      return passwordApplyResult && passwordGrants.has(passwordKey(path, scope, profile));
    },
  },
};

const shell = await import("@ardia/shell");
const { useBrowser } = await import("../store/browser.ts");
const S = () => useBrowser.getState();
const reset = () => (S().hydrate({}), useBrowser.setState({ bookmarksReady: { default: true } }));
const cleanups = [];
const start = (engine) => {
  const cleanup = engine.startSync();
  if (cleanup) cleanups.push(cleanup);
};

test("a crash after a batch lands: after the restart it's sent again as it was, and the next batch gets a new seq", async () => {
  reset();
  const first = await import("./engine.ts?first");
  start(first);
  assert.ok("ok" in (await first.turnOnSync("/sync")));
  S().addBookmark({ profileId: "default", url: "https://one.example/", title: "One" });
  await first.syncNow();

  let disk = null;
  onWrite = (file) => {
    if (!disk && file.ops?.some((op) => op.v?.t === "Two")) disk = new Map(shell.docs);
  };
  S().addBookmark({ profileId: "default", url: "https://two.example/", title: "Two" });
  await first.syncNow();
  await settle();
  onWrite = null;
  assert.ok(disk);
  shell.docs.clear();
  for (const [name, contents] of disk) shell.docs.set(name, contents);

  const second = await import("./engine.ts?second");
  start(second);
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve));
  S().addBookmark({ profileId: "default", url: "https://three.example/", title: "Three" });
  await second.syncNow();
  await settle();

  const batches = new Map();
  for (const { scope, payload } of folder.values()) {
    const file = JSON.parse(payload);
    if (file.kind !== "log") continue;
    const key = `${scope} ${file.device} ${file.seq}`;
    assert.equal(batches.get(key) ?? payload, payload, `${key} was published twice with different changes`);
    batches.set(key, payload);
  }
  const three = [...folder.values()].map((f) => JSON.parse(f.payload)).find((f) => f.ops?.some((op) => op.v?.t === "Three"));
  assert.deepEqual(three.ops.map((op) => op.v?.t), ["Three"], "only what's new");
  assert.equal(shell.docs.get("sync-journal.nns"), "", "the journal is emptied once the saved state has its batches");
});

test("a batch is published only once the journal holding it is on disk", async () => {
  reset();
  const engine = await import("./engine.ts?held");
  start(engine);
  assert.ok("ok" in (await engine.turnOnSync("/sync")));
  await engine.syncNow();
  const published = () => [...folder.values()].map((f) => JSON.parse(f.payload)).filter((f) => f.ops?.some((op) => op.v?.t === "Held"));

  shell.heldSaves.on = true;
  S().addBookmark({ profileId: "default", url: "https://held.example/", title: "Held" });
  const syncing = engine.syncNow();
  for (let i = 0; i < 20; i++) await new Promise((resolve) => setImmediate(resolve));
  assert.equal(published().length, 0, "nothing goes out while the journal save is still pending");
  assert.ok(shell.heldSaves.queue.length > 0, "the journal save is waiting");

  shell.heldSaves.on = false;
  for (const land of shell.heldSaves.queue.splice(0)) land();
  await syncing;
  assert.equal(published().length, 1, "published once the journal landed");
});

const settle = async () => {
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve));
};
const syncDisk = () => new Map(["sync.json", "sync-state.nns", "sync-journal.nns"].map((name) => [name, shell.docs.get(name)]));
const logs = () => [...folder.values()].map(({ payload }) => JSON.parse(payload)).filter((file) => file.kind === "log");
const inspect = (engine) => {
  globalThis.__DEV__ = true;
  start(engine);
  globalThis.__DEV__ = false;
  return globalThis.acSync.doc;
};
const freshFolder = () => {
  for (const cleanup of cleanups.splice(0)) cleanup();
  reset();
  shell.docs.clear();
  folder.clear();
  timers.clear();
  keys.clear();
  forgotten.length = 0;
  folderCalls.length = 0;
  chainStatus = "ok";
  onWrite = null;
  passwordGrants.clear();
  passwordCalls.length = 0;
  passwordListeners.clear();
  consent = true;
  consentWait = null;
  passwordReadWait = null;
  passwordRecords = [];
  passwordApplyResult = true;
  sealFailure = false;
  onPasswordApply = null;
};
test("passwords default off and a saved enabled preference never grants consent", async () => {
  freshFolder();
  const first = await import("./engine.ts?password-preference-before");
  start(first);
  assert.equal(first.useSync.getState().types.passwords, false);
  assert.ok("ok" in (await first.turnOnSync("/sync")));
  await first.syncNow();
  first.setTypeSynced("passwords", true);
  await settle();
  const second = await import("./engine.ts?password-preference-after");
  start(second);
  await settle();
  S().addBookmark({ profileId: "default", url: "https://without-passwords.example/", title: "Without passwords" });
  await second.syncNow();
  assert.equal(second.useSync.getState().types.passwords, true);
  assert.equal(second.useSync.getState().passwordsPaused, true);
  assert.equal(second.useSync.getState().status, "passwordsPaused");
  assert.deepEqual(passwordCalls, []);
  assert.ok(logs().some((file) => file.ops.some((op) => op.v?.t === "Without passwords")));
});

test("one foreground password consent binds only enabled owning profiles and lock invalidation pauses it", async () => {
  freshFolder();
  const engine = await import("./engine.ts?password-bindings");
  const doc = inspect(engine);
  const work = S().createProfile({ name: "Work", color: "blue" });
  const shared = S().createProfile({ name: "Shared", color: "blue", shareWith: "default" });
  const disabled = S().createProfile({ name: "Disabled", color: "blue" });
  const invalid = S().createProfile({ name: "Invalid scope", color: "blue" });
  const privateId = "incognito:window@default";
  useBrowser.setState({ profiles: { ...S().profiles, [privateId]: { ...S().profiles.default, id: privateId } } });
  assert.ok("ok" in (await engine.turnOnSync("/sync")));
  await engine.syncNow();
  engine.setProfileSynced(disabled, false);
  engine.setTypeSynced("passwords", true);
  doc().profiles[privateId] = { syncId: "private", enabled: true };
  doc().profiles[invalid].syncId = "not-a-valid-scope";
  await engine.syncNow();
  assert.deepEqual(passwordCalls, []);
  assert.equal(await engine.authorizePasswords(), true);
  const requests = passwordCalls.filter((call) => call.kind === "authorize");
  assert.equal(requests.length, 1);
  assert.equal(requests[0].path, "/sync");
  assert.deepEqual(requests[0].profiles, [
    { scope: `p:${doc().profiles.default.syncId}`, engineProfile: "" },
    { scope: `p:${doc().profiles[work].syncId}`, engineProfile: work },
  ]);
  assert.ok(!requests[0].profiles.some((binding) => binding.scope === `p:${doc().profiles[shared].syncId}`));
  assert.equal(engine.useSync.getState().passwordsPaused, false);
  assert.equal(engine.useSync.getState().status, "updated");
  assert.ok(passwordCalls.some((call) => call.kind === "read"));
  const calls = passwordCalls.length;
  passwordGrants.clear();
  for (const listener of passwordListeners) listener();
  assert.equal(engine.useSync.getState().passwordsPaused, true);
  await engine.syncNow();
  assert.equal(passwordCalls.length, calls, "background cycles never prompt or use revoked bindings");
  assert.equal(engine.useSync.getState().status, "passwordsPaused");
});

test("native consent is checked again without an invalidation event and never survives engine startup", async () => {
  freshFolder();
  const first = await import("./engine.ts?password-session-before");
  inspect(first);
  assert.ok("ok" in (await first.turnOnSync("/sync")));
  await first.syncNow();
  first.setTypeSynced("passwords", true);
  assert.equal(await first.authorizePasswords(), true);
  passwordGrants.clear();
  const calls = passwordCalls.length;
  await first.syncNow();
  assert.equal(passwordCalls.length, calls);
  assert.equal(first.useSync.getState().status, "passwordsPaused");
  assert.equal(await first.authorizePasswords(), true);
  await settle();
  const second = await import("./engine.ts?password-session-after");
  start(second);
  await settle();
  const restartedCalls = passwordCalls.length;
  await second.syncNow();
  assert.equal(passwordCalls.length, restartedCalls);
  assert.equal(second.useSync.getState().status, "passwordsPaused");
  assert.equal(passwordGrants.size, 0);
});

test("opaque password records use exact native bindings and failed imports remain visibly paused while bookmarks sync", async () => {
  freshFolder();
  const engine = await import("./engine.ts?password-opaque");
  const doc = inspect(engine);
  assert.ok("ok" in (await engine.turnOnSync("/sync")));
  await engine.syncNow();
  engine.setTypeSynced("passwords", true);
  const value = { version: 2, sealed: "opaque-local-record", fingerprint: "local-fingerprint" };
  passwordRecords = [{ key: "pw:local", value, created: 0 }];
  assert.equal(await engine.authorizePasswords(), true);
  const exported = logs().flatMap((file) => file.ops).find((op) => op.k === "pw:local");
  assert.deepEqual(exported.v, value);
  const scope = `p:${doc().profiles.default.syncId}`;
  const { Clock } = await import("@ardia/sync");
  const remote = { version: 2, sealed: "opaque-remote-record", fingerprint: "remote-fingerprint" };
  folder.set("remote-password", { scope, payload: JSON.stringify({ v: 1, kind: "log", device: "remote", seq: 1, at: Date.now(), ops: [{ k: "pw:remote", h: new Clock("remote").tick(), v: remote }] }) });
  passwordApplyResult = false;
  S().addBookmark({ profileId: "default", url: "https://import-paused.example/", title: "Import paused" });
  await engine.syncNow();
  assert.equal(engine.useSync.getState().status, "passwordsPaused");
  assert.match(engine.useSync.getState().passwordError, /haven’t synced/);
  assert.ok(logs().some((file) => file.ops.some((op) => op.v?.t === "Import paused")));
  const applied = passwordCalls.find((call) => call.kind === "apply" && call.changes.some((change) => change.key === "pw:remote"));
  assert.equal(applied.path, "/sync");
  assert.equal(applied.scope, scope);
  assert.equal(applied.profile, "");
  assert.deepEqual(applied.changes.find((change) => change.key === "pw:remote"), { key: "pw:remote", desired: remote, base: null });
  assert.ok(doc().scopes[scope].unapplied.includes("pw:remote"));
  passwordApplyResult = true;
  await engine.syncNow();
  assert.equal(engine.useSync.getState().status, "updated");
  assert.equal(engine.useSync.getState().passwordError, null);
});

test("sync cleanup removes the native password listener", async () => {
  freshFolder();
  const engine = await import("./engine.ts?password-cleanup");
  const cleanup = engine.startSync();
  assert.equal(passwordListeners.size, 1);
  cleanup();
  assert.equal(passwordListeners.size, 0);
});

test("cancelled or invalidated password consent preserves preferences and cannot authorize a changed binding", async () => {
  freshFolder();
  const engine = await import("./engine.ts?password-cancel");
  const doc = inspect(engine);
  assert.ok("ok" in (await engine.turnOnSync("/sync")));
  await engine.syncNow();
  engine.setTypeSynced("passwords", true);
  consent = false;
  assert.equal(await engine.authorizePasswords(), false);
  assert.equal(doc().types.passwords, true);
  assert.ok(keys.has(doc().deviceId));
  consent = true;
  let release;
  consentWait = new Promise((resolve) => { release = resolve; });
  const authorizing = engine.authorizePasswords();
  await settle();
  const revocations = passwordRevocations;
  engine.setProfileSynced("default", false);
  assert.ok(passwordRevocations > revocations, "profile retirement revokes before waiting on the native prompt");
  release();
  assert.equal(await authorizing, false);
  assert.equal(passwordGrants.size, 0);
  assert.equal(passwordCalls.filter((call) => call.kind === "read").length, 0);
});

test("changing a scope requires fresh native consent and a newly scoped adapter", async () => {
  freshFolder();
  const engine = await import("./engine.ts?password-rebinding");
  const doc = inspect(engine);
  assert.ok("ok" in (await engine.turnOnSync("/sync")));
  await engine.syncNow();
  engine.setTypeSynced("passwords", true);
  assert.equal(await engine.authorizePasswords(), true);
  const oldScope = `p:${doc().profiles.default.syncId}`;
  const rebound = "b".repeat(26);
  doc().profiles.default.syncId = rebound;
  const calls = passwordCalls.length;
  await engine.syncNow();
  assert.equal(passwordCalls.length, calls);
  assert.equal(engine.useSync.getState().passwordsPaused, true);
  assert.equal(await engine.authorizePasswords(), true);
  const reads = passwordCalls.slice(calls).filter((call) => call.kind === "read");
  assert.ok(reads.length > 0);
  assert.ok(reads.every((call) => call.scope === `p:${rebound}` && call.path === "/sync" && call.profile === ""));
  assert.equal(passwordGrants.has(passwordKey("/sync", oldScope, "")), false);
  const { setSharedDataIds } = await import("../store/model.ts");
  setSharedDataIds({ default: "remapped-profile" });
  try {
    await engine.syncNow();
    assert.equal(engine.useSync.getState().passwordsPaused, true);
    assert.equal(await engine.authorizePasswords(), true);
    assert.ok(passwordCalls.some((call) => call.kind === "read" && call.scope === `p:${rebound}` && call.profile === "remapped-profile"));
    doc().folder = "/different-sync-folder";
    const previous = passwordCalls.length;
    await engine.syncNow();
    assert.equal(passwordCalls.length, previous);
    assert.equal(await engine.authorizePasswords(), true);
    assert.ok(passwordCalls.slice(previous).some((call) => call.kind === "read" && call.path === "/different-sync-folder" && call.scope === `p:${rebound}` && call.profile === "remapped-profile"));
  } finally {
    setSharedDataIds({});
  }
});

test("disabling passwords and stopping sync revoke in-flight native operations before waiting", async () => {
  freshFolder();
  const engine = await import("./engine.ts?password-stop");
  inspect(engine);
  assert.ok("ok" in (await engine.turnOnSync("/sync")));
  await engine.syncNow();
  engine.setTypeSynced("passwords", true);
  assert.equal(await engine.authorizePasswords(), true);
  let release;
  passwordReadWait = new Promise((resolve) => { release = resolve; });
  const syncing = engine.syncNow();
  await settle();
  const revocations = passwordRevocations;
  engine.setTypeSynced("passwords", false);
  assert.ok(passwordRevocations > revocations);
  const stopping = engine.stopSync();
  assert.ok(passwordRevocations > revocations + 1);
  release();
  await syncing;
  await stopping;
  assert.equal(engine.useSync.getState().status, "off");
  assert.equal(passwordGrants.size, 0);
});

test("unreadable encrypted state stalls startup without overwriting files or republishing empty state", async () => {
  freshFolder();
  const first = await import("./engine.ts?state-failure-before");
  start(first);
  assert.ok("ok" in (await first.turnOnSync("/sync")));
  await first.syncNow();
  await settle();
  shell.docs.set("sync-state.nns", "damaged encrypted state");
  const disk = syncDisk();
  const calls = folderCalls.length;
  const second = await import("./engine.ts?state-failure-after");
  start(second);
  await settle();
  assert.equal(second.useSync.getState().status, "stalled");
  assert.match(second.useSync.getState().error, /encrypted sync state/i);
  await second.syncNow();
  second.setTypeSynced("passwords", true);
  await settle();
  assert.equal(folderCalls.length, calls);
  assert.deepEqual(syncDisk(), disk);
  assert.deepEqual(forgotten, []);
});

for (const [tag, name, content] of [
  ["journal-authentication", "sync-journal.nns", "damaged journal"],
  ["state-json", "sync-state.nns", "sealed:{broken"],
  ["journal-json", "sync-journal.nns", "sealed:{broken"],
]) {
  test(`startup preserves local files when ${tag} fails`, async () => {
    freshFolder();
    const first = await import(`./engine.ts?${tag}-before`);
    start(first);
    assert.ok("ok" in (await first.turnOnSync("/sync")));
    await first.syncNow();
    await settle();
    shell.docs.set(name, content);
    const disk = syncDisk();
    const calls = folderCalls.length;
    const second = await import(`./engine.ts?${tag}-after`);
    start(second);
    await settle();
    assert.equal(second.useSync.getState().status, "stalled");
    assert.equal(second.useSync.getState().enabled, true);
    await second.syncNow();
    assert.equal(await second.authorizePasswords(), false);
    await settle();
    assert.equal(folderCalls.length, calls);
    assert.deepEqual(syncDisk(), disk);
    assert.deepEqual(forgotten, []);
  });
}

const persistenceFixture = async (tag) => {
  freshFolder();
  const engine = await import(`./engine.ts?persist-${tag}`);
  const doc = inspect(engine);
  assert.ok("ok" in (await engine.turnOnSync("/sync")));
  await engine.syncNow();
  await settle();
  return { engine, doc };
};
const savedScopes = () => JSON.parse(shell.docs.get("sync-state.nns").slice(7));
const landSave = async () => {
  assert.equal(shell.heldSaves.queue.length, 1, "only one state write may be in flight");
  shell.heldSaves.queue.shift()();
  await settle();
};

test("persistScopes holds an effect and sequence metadata until its exact snapshot lands", async () => {
  const { engine, doc } = await persistenceFixture("held");
  const disk = syncDisk();
  doc().scopes.app.pending = 17;
  doc().scopes.app.seq++;
  const snapshot = structuredClone(doc().scopes);
  let effects = 0;
  shell.heldSaves.on = true;
  try {
    const applying = engine.persistScopes().then(() => { effects++; });
    await settle();
    assert.equal(effects, 0);
    assert.deepEqual(syncDisk(), disk, "metadata cannot claim a sequence with neither state nor journal on disk");
    await landSave();
    await applying;
    assert.equal(effects, 1);
    assert.deepEqual(savedScopes(), snapshot);
    assert.equal(JSON.parse(shell.docs.get("sync.json")).seqs.app, snapshot.app.seq);
  } finally {
    shell.heldSaves.on = false;
    for (const land of shell.heldSaves.queue.splice(0)) land();
  }
});

for (const failure of ["seal", "disk"]) {
  test(`persistScopes rejects a ${failure} failure before mutation and retries the same snapshot`, async () => {
    const { engine, doc } = await persistenceFixture(failure);
    const disk = syncDisk();
    doc().scopes.app.pending = 23;
    doc().scopes.app.seq++;
    const snapshot = structuredClone(doc().scopes);
    let effects = 0;
    const originalSet = shell.docs.set;
    if (failure === "seal") sealFailure = true;
    else shell.docs.set = function (name, contents) {
      if (name === "sync-state.nns") throw new Error("State disk write failed");
      return originalSet.call(this, name, contents);
    };
    try {
      await assert.rejects(engine.persistScopes().then(() => { effects++; }), /failed/);
      assert.equal(effects, 0);
      assert.deepEqual(syncDisk(), disk);
    } finally {
      sealFailure = false;
      shell.docs.set = originalSet;
    }
    await engine.persistScopes().then(() => { effects++; });
    assert.equal(effects, 1, "a failed write never marks its snapshot as already saved");
    assert.deepEqual(savedScopes(), snapshot);
  });
}

test("persistScopes rejects snapshot serialization failure without changing durable files", async () => {
  const { engine, doc } = await persistenceFixture("serialization");
  const disk = syncDisk();
  const scope = doc().scopes.app;
  scope.invalidCycle = scope;
  try {
    const saving = engine.persistScopes();
    assert.ok(saving instanceof Promise);
    await assert.rejects(saving, /circular/i);
    assert.deepEqual(syncDisk(), disk);
  } finally {
    delete scope.invalidCycle;
  }
});

test("normal saves and barriers serialize exact snapshots without acknowledging later edits or overwriting newer state", async () => {
  const { engine, doc } = await persistenceFixture("ordered");
  shell.heldSaves.on = true;
  try {
    doc().scopes.app.pending = 1;
    engine.setTypeSynced("history", false);
    await settle();
    doc().scopes.app.pending = 2;
    let firstDone = false;
    const first = engine.persistScopes().then(() => { firstDone = true; });
    doc().scopes.app.pending = 3;
    let secondDone = false;
    const second = engine.persistScopes().then(() => { secondDone = true; });
    await settle();
    await landSave();
    assert.equal(savedScopes().app.pending, 1);
    assert.equal(firstDone, false);
    assert.equal(secondDone, false);
    await landSave();
    await first;
    assert.equal(savedScopes().app.pending, 2);
    assert.equal(firstDone, true);
    assert.equal(secondDone, false, "the earlier snapshot cannot satisfy the later barrier");
    await landSave();
    await second;
    assert.equal(savedScopes().app.pending, 3);
    assert.equal(shell.heldSaves.queue.length, 0, "no older normal save remains to overwrite the barrier");
    await engine.persistScopes();
    assert.equal(savedScopes().app.pending, 3);
  } finally {
    shell.heldSaves.on = false;
    for (const land of shell.heldSaves.queue.splice(0)) land();
  }
});

test("a barrier matching the current disk still waits for and supersedes an older queued save", async () => {
  const { engine, doc } = await persistenceFixture("reverted");
  const original = structuredClone(doc().scopes);
  shell.heldSaves.on = true;
  try {
    doc().scopes.app.pending = 81;
    engine.setTypeSynced("history", false);
    await settle();
    doc().scopes.app.pending = original.app.pending;
    let done = false;
    const barrier = engine.persistScopes().then(() => { done = true; });
    await settle();
    assert.equal(done, false);
    await landSave();
    assert.equal(savedScopes().app.pending, 81);
    assert.equal(done, false, "a matching snapshot before the queued write is not a durable acknowledgement");
    await landSave();
    await barrier;
    assert.deepEqual(savedScopes(), original);
  } finally {
    shell.heldSaves.on = false;
    for (const land of shell.heldSaves.queue.splice(0)) land();
  }
});

test("an older snapshot cannot prune a newer durable journal when the following normal state save fails", async () => {
  const { engine, doc } = await persistenceFixture("journal-coverage");
  const scope = `p:${doc().profiles.default.syncId}`;
  const previousSeq = doc().scopes[scope].seq;
  doc().scopes.app.pending = 41;
  shell.heldSaves.on = true;
  try {
    const older = engine.persistScopes();
    await settle();
    S().addBookmark({ profileId: "default", url: "https://durable-journal.example/", title: "Durable journal" });
    const syncing = engine.syncNow();
    await settle();
    assert.equal(shell.heldSaves.queue.length, 2, "the older state and newer journal are both waiting");
    let finished = false;
    void syncing.then(() => { finished = true; });
    for (let attempt = 0; attempt < 10 && !finished; attempt++) {
      for (const land of shell.heldSaves.queue.splice(1)) land();
      await settle();
    }
    assert.equal(finished, true, "journal writes finish while the older state snapshot remains held");
    assert.equal(shell.heldSaves.queue.length, 1, "only the older snapshot remains held after the journal lands");
    await syncing;
    const journal = shell.docs.get("sync-journal.nns");
    const batch = JSON.parse(journal.slice(7)).journal[scope].find((file) => file.ops.some((op) => op.v?.t === "Durable journal"));
    assert.equal(batch.seq, previousSeq + 1);
    sealFailure = true;
    await landSave();
    await older;
    assert.equal(shell.docs.get("sync-journal.nns"), journal);
    assert.equal(savedScopes()[scope].seq, previousSeq);
    assert.equal(JSON.parse(shell.docs.get("sync.json")).seqs[scope], previousSeq);
    sealFailure = false;
    shell.heldSaves.on = false;
    const restarted = await import("./engine.ts?persist-journal-coverage-restarted");
    start(restarted);
    await settle();
    S().addBookmark({ profileId: "default", url: "https://after-journal.example/", title: "After journal" });
    await restarted.syncNow();
    await settle();
    const replay = logs().filter((file) => file.device === batch.device && file.seq === batch.seq && file.ops.some((op) => op.v?.t === "Durable journal"));
    assert.equal(replay.length, 2);
    for (const file of replay) assert.deepEqual(file, batch);
    assert.equal(logs().find((file) => file.ops.some((op) => op.v?.t === "After journal")).seq, batch.seq + 1);
  } finally {
    sealFailure = false;
    shell.heldSaves.on = false;
    for (const land of shell.heldSaves.queue.splice(0)) land();
  }
});

test("the scope persistence hook puts password apply provenance on disk before native mutation", async () => {
  const { engine, doc } = await persistenceFixture("native-effect");
  engine.setTypeSynced("passwords", true);
  assert.equal(await engine.authorizePasswords(), true);
  await settle();
  const scope = `p:${doc().profiles.default.syncId}`;
  const { Clock } = await import("@ardia/sync");
  const value = { version: 2, sealed: "opaque-before-effect", fingerprint: "before-effect" };
  folder.set("remote-before-effect", { scope, payload: JSON.stringify({ v: 1, kind: "log", device: "remote", seq: 1, at: Date.now(), ops: [{ k: "pw:effect", h: new Clock("remote").tick(), v: value }] }) });
  let effects = 0;
  let atEffect;
  onPasswordApply = (appliedScope, changes) => {
    if (!changes.some((change) => change.key === "pw:effect")) return;
    effects++;
    atEffect = { scope: appliedScope, state: savedScopes()[scope] };
  };
  shell.heldSaves.on = true;
  try {
    const syncing = engine.syncNow();
    await settle();
    assert.equal(effects, 0);
    assert.equal(shell.heldSaves.queue.length, 1);
    shell.heldSaves.on = false;
    shell.heldSaves.queue.shift()();
    await syncing;
    assert.equal(effects, 1);
    assert.equal(atEffect.scope, scope);
    assert.deepEqual(atEffect.state.applyProvenance["pw:effect"], [value]);
  } finally {
    onPasswordApply = null;
    shell.heldSaves.on = false;
    for (const land of shell.heldSaves.queue.splice(0)) land();
  }
});

for (const checkpoint of ["current", "historical"]) {
  test(`a ${checkpoint} preapply checkpoint preserves a genuine local password edit after a skewed remote clock`, async () => {
    const { engine, doc } = await persistenceFixture(`clock-${checkpoint}`);
    engine.setTypeSynced("passwords", true);
    assert.equal(await engine.authorizePasswords(), true);
    await settle();
    const scope = `p:${doc().profiles.default.syncId}`;
    const key = "pw:https://clock.example\nalice";
    const staleClock = doc().clock;
    const { Clock } = await import("@ardia/sync");
    const remote = { version: 2, sealed: "opaque-clock-remote", fingerprint: "clock-remote" };
    const local = { version: 2, sealed: "opaque-clock-local", fingerprint: "clock-local" };
    const remoteHlc = new Clock("remote", null, () => Date.now() + 60_000).tick();
    folder.set("clock-remote", { scope, payload: JSON.stringify({ v: 1, kind: "log", device: "remote", seq: 1, at: Date.now(), ops: [{ k: key, h: remoteHlc, v: remote }] }) });
    let diskAtEffect;
    onPasswordApply = (_scope, changes) => {
      if (!changes.some((change) => change.key === key)) return;
      diskAtEffect ??= syncDisk();
      passwordRecords = changes.filter((change) => change.desired).map((change) => ({ key: change.key, value: change.desired, created: 0 }));
    };
    await engine.syncNow();
    await settle();
    assert.ok(diskAtEffect);
    const meta = JSON.parse(diskAtEffect.get("sync.json"));
    if (checkpoint === "current") {
      assert.ok(new Clock(meta.deviceId, meta.clock, () => 0).tick() > remoteHlc, "the preapply snapshot carries the active cycle’s observed clock");
    } else {
      diskAtEffect.set("sync.json", JSON.stringify({ ...meta, clock: staleClock }));
    }
    for (const cleanup of cleanups.splice(0)) cleanup();
    for (const [name, contents] of diskAtEffect) shell.docs.set(name, contents);
    passwordGrants.clear();
    passwordRecords = [{ key, value: local, created: 0 }];
    const restarted = await import(`./engine.ts?clock-${checkpoint}-restarted`);
    const restoredDoc = inspect(restarted);
    await settle();
    assert.ok(new Clock(meta.deviceId, restoredDoc().clock, () => 0).tick() > remoteHlc, "startup restores a causal lower bound before publishing anything");
    assert.equal(await restarted.authorizePasswords(), true);
    await restarted.syncNow();
    await settle();
    assert.deepEqual(passwordRecords, [{ key, value: local, created: 0 }]);
    const published = logs().flatMap((file) => file.ops).find((op) => op.k === key && op.v?.fingerprint === local.fingerprint);
    assert.ok(published, "the genuine local edit is published rather than overwritten by the remote value");
    assert.ok(published.h > remoteHlc);
  });
}

for (const source of ["outbox", "state journal", "disk journal"]) {
  test(`startup recovers the clock lower bound from a historical ${source} even when its sequence is already saved`, async () => {
    const { doc } = await persistenceFixture(`clock-${source}`);
    const { Clock } = await import("@ardia/sync");
    const state = savedScopes();
    const h = new Clock("future", null, () => Date.now() + 120_000).tick();
    const op = { k: "clock:retained", h, v: null };
    const file = { v: 1, kind: "log", device: doc().deviceId, seq: state.app.seq, at: Date.now(), ops: [op] };
    for (const cleanup of cleanups.splice(0)) cleanup();
    if (source === "outbox") state.app.outbox = [op];
    else if (source === "state journal") state.app.journal = [file];
    else shell.docs.set("sync-journal.nns", `sealed:${JSON.stringify({ journal: { app: [file] } })}`);
    shell.docs.set("sync-state.nns", `sealed:${JSON.stringify(state)}`);
    const restarted = await import(`./engine.ts?clock-${source}-startup`);
    const restored = inspect(restarted);
    await settle();
    assert.ok(new Clock(restored().deviceId, restored().clock, () => 0).tick() > h);
  });
}

test("a rejected password checkpoint stays visibly paused until its unapplied records succeed", async () => {
  const { engine, doc } = await persistenceFixture("checkpoint-status");
  engine.setTypeSynced("passwords", true);
  assert.equal(await engine.authorizePasswords(), true);
  await settle();
  const scope = `p:${doc().profiles.default.syncId}`;
  const { Clock } = await import("@ardia/sync");
  const value = { version: 2, sealed: "opaque-checkpoint-status", fingerprint: "checkpoint-status" };
  folder.set("checkpoint-status", { scope, payload: JSON.stringify({ v: 1, kind: "log", device: "remote", seq: 1, at: Date.now(), ops: [{ k: "pw:checkpoint", h: new Clock("remote").tick(), v: value }] }) });
  const calls = passwordCalls.filter((call) => call.kind === "apply").length;
  const originalSet = shell.docs.set;
  shell.docs.set = function (name, contents) {
    if (name === "sync-state.nns") throw new Error("Checkpoint disk write failed");
    return originalSet.call(this, name, contents);
  };
  try {
    await engine.syncNow();
    await settle();
    assert.equal(passwordCalls.filter((call) => call.kind === "apply").length, calls, "failed checkpoint prevents native mutation");
    assert.ok(doc().scopes[scope].unapplied.includes("pw:checkpoint"));
    assert.equal(engine.useSync.getState().status, "passwordsPaused");
    assert.equal(engine.useSync.getState().passwordsPaused, true);
    assert.match(engine.useSync.getState().passwordError, /haven’t synced/);
  } finally {
    shell.docs.set = originalSet;
  }
  await engine.syncNow();
  assert.equal(engine.useSync.getState().status, "updated");
  assert.equal(engine.useSync.getState().passwordError, null);
  assert.ok(!doc().scopes[scope].unapplied.includes("pw:checkpoint"));
});
