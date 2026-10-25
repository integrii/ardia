import assert from "node:assert/strict";
import { after, afterEach, test } from "node:test";

const timers = new Map();
let timerId = 0;
const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
globalThis.setTimeout = (run, delay) => {
  const id = ++timerId;
  timers.set(id, { run: () => { timers.delete(id); run(); }, delay });
  return id;
};
globalThis.clearTimeout = (id) => timers.delete(id);
globalThis.__DEV__ = false;

const folder = new Map();
let onWrite = null;
let ids = 0;
let chainStatus = "ok";
let chainWait = null;
let stateOpens = 0;
let phraseResult = { ok: true };
let phraseWait = null;
let phraseFailure = false;
let serialNative = false;
let nativeQueue = Promise.resolve();
const nativeEvents = [];
let onForget = null;
let createWait = null;
let createChainWait = null;
let deleteWait = null;
let forgetWait = null;
const deleted = [];
const nativeCall = (kind, run) => {
  const execute = async () => {
    nativeEvents.push(`${kind}:start`);
    try { return await run(); }
    finally { nativeEvents.push(`${kind}:finish`); }
  };
  if (!serialNative) return execute();
  const result = nativeQueue.then(execute);
  nativeQueue = result.catch(() => {});
  return result;
};
const phraseCalls = [];
let keyRevision = 0;
const keyEvents = [];
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
    createPhrase: (id) => nativeCall("create", async () => { if (createWait) await createWait; keys.add(id); return true; }),
    createChain: () => nativeCall("createChain", async () => { if (createChainWait) await createChainWait; }),
    unlock: async (id) => keys.has(id),
    enterPhrase: (id, text, path) => nativeCall("phrase", async () => {
      phraseCalls.push({ id, text, folder: path });
      const result = phraseResult;
      if (phraseWait) await phraseWait;
      if (phraseFailure) throw new Error("Native recovery failed");
      if ("ok" in result) {
        keys.add(id);
        keyRevision++;
        keyEvents.push({ kind: "phrase", revision: keyRevision });
      }
      return result;
    }),
    forget: (id) => nativeCall("forget", async () => { onForget?.(id); if (forgetWait) await forgetWait; forgotten.push(id); keys.delete(id); }),
    deleteChain: async (path) => { deleted.push(path); if (deleteWait) await deleteWait; },
    chainStatus: async () => { if (chainWait) await chainWait; return chainStatus; },
    write: async (_folder, scope, payload) => {
      folderCalls.push("write");
      keyEvents.push({ kind: "write", revision: keyRevision });
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
      keyEvents.push({ kind: "seal", revision: keyRevision });
      if (sealFailure) throw new Error("Local sealing failed");
      return `sealed:${text}`;
    },
    openLocal: async (sealed) => {
      stateOpens++;
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
afterEach(async () => {
  shell.heldSaves.on = false;
  for (const land of shell.heldSaves.queue.splice(0)) land();
  for (const cleanup of cleanups.splice(0)) cleanup();
  await settle();
  assert.equal(passwordListeners.size, 0, "every engine fixture releases its native subscription");
  assert.equal(shell.heldSaves.queue.length, 0, "no held document write crosses a test boundary");
  timers.clear();
});
after(() => {
  globalThis.setTimeout = realSetTimeout;
  globalThis.clearTimeout = realClearTimeout;
});

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
  chainWait = null;
  stateOpens = 0;
  phraseResult = { ok: true };
  phraseWait = null;
  phraseFailure = false;
  serialNative = false;
  nativeQueue = Promise.resolve();
  nativeEvents.length = 0;
  onForget = null;
  createWait = null;
  createChainWait = null;
  deleteWait = null;
  forgetWait = null;
  deleted.length = 0;
  phraseCalls.length = 0;
  keyRevision = 0;
  keyEvents.length = 0;
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

test("entering a phrase with ready state preserves unsaved scopes without reopening disk", async () => {
  const { engine, doc } = await persistenceFixture("phrase-ready");
  const scopes = doc().scopes;
  scopes.app.pending = 17;
  const opens = stateOpens;
  assert.ok("ok" in await engine.enterRecoveryPhrase("/sync", "fixture phrase"));
  assert.equal(doc().scopes, scopes);
  assert.equal(doc().scopes.app.pending, 17);
  assert.equal(stateOpens, opens);
  await engine.persistScopes();
  assert.equal(savedScopes().app.pending, 17);
});

test("entering a phrase during a cycle preserves its unsaved batch and exact scope objects", async () => {
  const { engine, doc } = await persistenceFixture("phrase-midcycle");
  const scopes = doc().scopes;
  const opens = stateOpens;
  shell.heldSaves.on = true;
  S().addBookmark({ profileId: "default", url: "https://phrase.example/", title: "Phrase midcycle" });
  const syncing = engine.syncNow();
  let recovering;
  let result;
  try {
    await settle();
    assert.ok(shell.heldSaves.queue.length > 0, "the real cycle is suspended before publishing its batch");
    keyEvents.length = 0;
    recovering = engine.enterRecoveryPhrase("/other-folder", "fixture phrase").then((value) => { result = value; });
    await settle();
    assert.deepEqual(phraseCalls, [], "native key replacement must not start while the old cycle is held");
    assert.equal(keyRevision, 0);
    assert.equal(result, undefined);
    assert.equal(doc().scopes, scopes, "a live cycle must never lose its scope references");
    assert.equal(stateOpens, opens, "ready scopes are not reloaded from an older disk checkpoint");
  } finally {
    shell.heldSaves.on = false;
    for (const land of shell.heldSaves.queue.splice(0)) land();
    await syncing;
    await recovering;
    await settle();
  }
  const batches = logs().filter((file) => file.ops.some((op) => op.v?.t === "Phrase midcycle"));
  assert.equal(batches.length, 1);
  assert.ok("ok" in result);
  assert.deepEqual(phraseCalls, [{ id: doc().deviceId, text: "fixture phrase", folder: "/sync" }]);
  const keyChange = keyEvents.findIndex(({ kind }) => kind === "phrase");
  assert.ok(keyChange > 0);
  assert.ok(keyEvents.slice(0, keyChange).some(({ kind }) => kind === "write"), "the old cycle publishes before the native key changes");
  assert.ok(keyEvents.slice(0, keyChange).some(({ kind }) => kind === "seal"), "the old cycle saves local state before the native key changes");
  assert.ok(keyEvents.filter(({ kind }) => kind !== "phrase").every(({ revision }) => revision === 0), "no old-cycle write or seal uses the replaced key");
  assert.equal(doc().scopes, scopes);
  assert.equal(stateOpens, opens);
  assert.ok(Object.values(savedScopes()).some((state) => Object.values(state.records).some((record) => record.v?.t === "Phrase midcycle")));
});

for (const timeout of [false, true]) {
  test(`phrase recovery ${timeout ? "times out instead of reloading over" : "waits before reloading after"} an active cycle when state is not ready`, async () => {
    const { engine } = await persistenceFixture(`phrase-not-ready-${timeout}`);
    let finish;
    chainWait = new Promise((resolve) => { finish = resolve; });
    const syncing = engine.syncNow();
    await settle();
    keys.clear();
    start(engine);
    await settle();
    assert.equal(engine.useSync.getState().status, "locked");
    const opens = stateOpens;
    let result;
    const recovering = engine.enterRecoveryPhrase("/sync", "fixture phrase").then((value) => { result = value; });
    try {
      await settle();
      assert.equal(result, undefined, "the old cycle still owns the state");
      assert.equal(stateOpens, opens);
      assert.deepEqual(phraseCalls, [], "a non-ready engine must also wait before mutating the native key");
      assert.equal(keyRevision, 0);
      if (timeout) {
        const waiting = [...timers.values()].filter(({ delay }) => delay === 10_000);
        assert.equal(waiting.length, 1, "cycle recovery has a bounded deadline");
        waiting[0].run();
        await recovering;
        assert.deepEqual(result, { error: "unavailable" });
        assert.equal(engine.useSync.getState().status, "stalled");
        assert.equal(stateOpens, opens);
        assert.deepEqual(phraseCalls, [], "a recovery timeout never invokes the native key mutation");
        assert.equal(keyRevision, 0);
      }
    } finally {
      chainStatus = "unavailable";
      finish();
      await syncing;
      chainWait = null;
      await recovering;
    }
    if (!timeout) {
      assert.ok("ok" in result);
      assert.ok(stateOpens > opens);
      assert.equal(engine.useSync.getState().status, "starting");
    }
    assert.equal([...timers.values()].filter(({ delay }) => delay === 10_000).length, 0);
  });
}

test("phrase recovery pauses new cycles and duplicate recovery until native validation finishes", async () => {
  const { engine, doc } = await persistenceFixture("phrase-native-pause");
  let finish;
  phraseWait = new Promise((resolve) => { finish = resolve; });
  const recovering = engine.enterRecoveryPhrase("/ignored", "held fixture phrase");
  let duplicate;
  try {
    await settle();
    assert.deepEqual(phraseCalls, [{ id: doc().deviceId, text: "held fixture phrase", folder: "/sync" }]);
    const calls = folderCalls.length;
    S().addBookmark({ profileId: "default", url: "https://paused-recovery.example/", title: "Paused recovery" });
    await engine.syncNow();
    assert.equal(folderCalls.length, calls, "no new cycle can read or write while native recovery is pending");
    duplicate = engine.enterRecoveryPhrase("/sync", "duplicate fixture phrase");
    await settle();
    assert.equal(phraseCalls.length, 1, "only one native recovery can own the pause");
  } finally {
    finish();
    await recovering;
    await duplicate;
    phraseWait = null;
  }
  assert.deepEqual(await duplicate, { error: "unavailable" });
  await engine.syncNow();
  assert.ok(logs().some((file) => file.ops.some((op) => op.v?.t === "Paused recovery")), "cycles resume after recovery finishes");
});

test("invalid phrase results preserve ready scopes, exact native arguments and the old key, then release the recovery pause", async () => {
  const { engine, doc } = await persistenceFixture("phrase-invalid-ready");
  const scopes = doc().scopes;
  scopes.app.pending = 23;
  const opens = stateOpens;
  const text = "  INVALID fixture phrase\nwith exact spacing  ";
  phraseResult = { error: "unknownWord", word: "INVALID" };
  assert.deepEqual(await engine.enterRecoveryPhrase("/not-the-configured-folder", text), phraseResult);
  assert.deepEqual(phraseCalls, [{ id: doc().deviceId, text, folder: "/sync" }]);
  assert.equal(keyRevision, 0);
  assert.equal(stateOpens, opens);
  assert.equal(doc().scopes, scopes);
  assert.equal(scopes.app.pending, 23);
  S().addBookmark({ profileId: "default", url: "https://invalid-phrase.example/", title: "After invalid phrase" });
  await engine.syncNow();
  assert.ok(logs().some((file) => file.ops.some((op) => op.v?.t === "After invalid phrase")), "a rejected phrase cannot leave sync paused");
});

test("invalid phrase while joining forwards its folder and never begins sync or installs a key", async () => {
  freshFolder();
  const engine = await import("./engine.ts?phrase-invalid-join");
  const doc = inspect(engine);
  const before = doc();
  const disk = syncDisk();
  phraseResult = { error: "mismatch" };
  assert.deepEqual(await engine.enterRecoveryPhrase("/requested-join-folder", "invalid join fixture"), phraseResult);
  assert.equal(phraseCalls.length, 1);
  assert.equal(phraseCalls[0].text, "invalid join fixture");
  assert.equal(phraseCalls[0].folder, "/requested-join-folder");
  assert.match(phraseCalls[0].id, /^[a-z2-7]{26}$/);
  assert.equal(keys.has(phraseCalls[0].id), false);
  assert.equal(keyRevision, 0);
  assert.equal(doc(), before);
  assert.equal(engine.useSync.getState().enabled, false);
  await settle();
  assert.deepEqual(syncDisk(), disk);
});

test("phrase recovery drains an outstanding state save before invoking native key replacement", async () => {
  const { engine, doc } = await persistenceFixture("phrase-held-state-writer");
  doc().scopes.app.pending = 29;
  shell.heldSaves.on = true;
  const saving = engine.persistScopes();
  await settle();
  const recovering = engine.enterRecoveryPhrase("/sync", "fixture phrase");
  try {
    await settle();
    assert.deepEqual(phraseCalls, [], "a save queued outside a cycle still belongs to the old key");
    assert.equal(keyRevision, 0);
  } finally {
    shell.heldSaves.on = false;
    for (const land of shell.heldSaves.queue.splice(0)) land();
    await saving;
    await recovering;
  }
  assert.equal(keyRevision, 1);
  assert.equal(savedScopes().app.pending, 29);
});

for (const timeout of [false, true]) {
  test(`phrase recovery ${timeout ? "times out without key mutation" : "waits"} while the completed cycle's final state writer is held`, async () => {
    const { engine, doc } = await persistenceFixture(`phrase-final-state-writer-${timeout}`);
    let held = false;
    const unsubscribe = engine.useSync.subscribe((state) => {
      if (held || state.status !== "updated") return;
      held = true;
      doc().scopes.app.pending = 31;
      shell.heldSaves.on = true;
    });
    await engine.syncNow();
    unsubscribe();
    await settle();
    assert.ok(held);
    assert.equal(shell.heldSaves.queue.length, 1, "the cycle has returned but its final state save has not landed");
    const recovering = engine.enterRecoveryPhrase("/sync", "fixture phrase");
    try {
      await settle();
      assert.deepEqual(phraseCalls, [], "running=false is not proof that old-key local writes have drained");
      assert.equal(keyRevision, 0);
      if (timeout) {
        const waiting = [...timers.values()].filter(({ delay }) => delay === 10_000);
        assert.equal(waiting.length, 1);
        waiting[0].run();
        assert.deepEqual(await recovering, { error: "unavailable" });
        assert.deepEqual(phraseCalls, []);
        assert.equal(keyRevision, 0);
      }
    } finally {
      shell.heldSaves.on = false;
      for (const land of shell.heldSaves.queue.splice(0)) land();
      await recovering;
      await settle();
    }
    assert.equal(savedScopes().app.pending, 31);
    assert.equal(keyRevision, timeout ? 0 : 1);
    assert.equal([...timers.values()].filter(({ delay }) => delay === 10_000).length, 0);
  });
}

test("configuration saves cannot submit old-state sealing while native phrase validation is pending", async () => {
  const { engine, doc } = await persistenceFixture("phrase-native-writer-pause");
  const before = syncDisk();
  let finish;
  phraseWait = new Promise((resolve) => { finish = resolve; });
  const recovering = engine.enterRecoveryPhrase("/sync", "fixture phrase");
  try {
    await settle();
    const seals = keyEvents.filter(({ kind }) => kind === "seal").length;
    engine.setTypeSynced("tabs", false);
    await settle();
    assert.equal(keyEvents.filter(({ kind }) => kind === "seal").length, seals);
    assert.deepEqual(syncDisk(), before, "normal state saves are deferred through native key validation");
    await assert.rejects(engine.persistScopes(), /recover/i, "explicit checkpointing cannot submit work across a paused key transition");
  } finally {
    finish();
    await recovering;
    phraseWait = null;
    await settle();
  }
  assert.deepEqual(await recovering, { error: "unavailable" }, "the post-native configuration generation is rechecked");
  assert.equal(doc().types.tabs, false);
  assert.equal(JSON.parse(shell.docs.get("sync.json")).types.tabs, false, "deferred saves resume without losing the configuration edit");
});

test("phrase recovery rejects configuration changes during its bounded drain even after an ABA toggle", async () => {
  const { engine } = await persistenceFixture("phrase-configuration-epoch");
  let finish;
  chainWait = new Promise((resolve) => { finish = resolve; });
  const syncing = engine.syncNow();
  await settle();
  const recovering = engine.enterRecoveryPhrase("/sync", "stale fixture phrase");
  engine.setTypeSynced("tabs", false);
  engine.setTypeSynced("tabs", true);
  try {
    await settle();
    assert.deepEqual(phraseCalls, []);
  } finally {
    chainStatus = "unavailable";
    finish();
    await syncing;
    chainWait = null;
  }
  assert.deepEqual(await recovering, { error: "unavailable" });
  assert.deepEqual(phraseCalls, [], "a stale request must not touch the native key after the cycle drains");
  assert.equal(keyRevision, 0);
});

test("phrase recovery rejects a replaced document after native validation instead of joining a stale configuration", async () => {
  freshFolder();
  const engine = await import("./engine.ts?phrase-document-replaced");
  const doc = inspect(engine);
  let finish;
  phraseWait = new Promise((resolve) => { finish = resolve; });
  const recovering = engine.enterRecoveryPhrase("/stale-join-folder", "fixture phrase");
  await settle();
  shell.docs.set("sync.json", JSON.stringify({ ...doc(), folder: "/current-folder" }));
  start(engine);
  const current = doc();
  finish();
  assert.deepEqual(await recovering, { error: "unavailable" });
  phraseWait = null;
  assert.equal(doc(), current);
  assert.equal(engine.useSync.getState().enabled, false);
});

for (const outcome of ["success", "invalid", "rejection"]) {
  test(`stop drains held ${outcome} recovery before publishing device and tab retirement, then forgets once`, { timeout: 20_000 }, async () => {
    const { engine, doc } = await persistenceFixture(`stop-recovery-${outcome}`);
    serialNative = true;
    engine.setTypeSynced("passwords", true);
    assert.equal(await engine.authorizePasswords(), true);
    const target = doc();
    const scopes = target.scopes;
    const device = target.deviceId;
    const scope = `p:${target.profiles.default.syncId}`;
    const firstLog = logs().length;
    const opens = stateOpens;
    const queuedTimers = [...timers.values()];
    let release;
    phraseWait = new Promise((resolve) => { release = resolve; });
    if (outcome === "invalid") phraseResult = { error: "mismatch" };
    phraseFailure = outcome === "rejection";
    const recovering = engine.enterRecoveryPhrase("/ignored", "held phrase");
    await settle();
    const calls = folderCalls.length;
    const revocations = passwordRevocations;
    const stopping = engine.stopSync();
    assert.ok(passwordRevocations > revocations, "consent revocation is immediate, before recovery drains");
    assert.equal(passwordGrants.size, 0);
    assert.equal(engine.stopSync({ deleteData: true }), stopping, "first caller owns the options and cleanup");
    onForget = (id) => {
      assert.equal(id, device);
      assert.equal(doc(), target);
      assert.equal(doc().scopes, scopes, "ready recovery never reloads or drops the owned scopes");
      const retirement = logs().slice(firstLog).flatMap((file) => file.ops);
      assert.ok(retirement.some((op) => op.k === `dev:${device}` && op.v === null));
      assert.ok(retirement.some((op) => op.k === `tabs:${device}` && op.v === null));
      assert.equal(scopes.app.records[`dev:${device}`].v, null);
      assert.equal(scopes[scope].records[`tabs:${device}`].v, null);
    };
    let result;
    stopping.then((value) => { result = value; });
    try {
      engine.setTypeSynced("tabs", false);
      engine.setProfileSynced("default", false);
      engine.adoptProfileTheme("default");
      assert.equal(engine.addRemoteProfile("not-present"), null);
      assert.equal(engine.startSync(), undefined);
      await engine.syncNow();
      assert.equal(await engine.authorizePasswords(), false);
      assert.ok("error" in await engine.turnOnSync("/replacement"));
      assert.deepEqual(await engine.enterRecoveryPhrase("/replacement", "new phrase"), { error: "unavailable" });
      for (const timer of queuedTimers) timer.run();
      await settle();
      assert.equal(result, undefined);
      assert.equal(folderCalls.length, calls, "no retiring or normal folder IO while native recovery is held");
      assert.deepEqual(forgotten, []);
      assert.deepEqual(deleted, []);
      assert.equal(target.types.tabs, true);
      assert.equal(target.profiles.default.enabled, true);
      assert.equal(nativeEvents.filter((event) => event === "forget:start").length, 0);
    } finally {
      release();
      await recovering;
      phraseWait = null;
    }
    assert.deepEqual(await stopping, { ok: true });
    assert.equal(stateOpens, opens);
    assert.deepEqual(forgotten, [device]);
    assert.deepEqual(deleted, [], "a second caller cannot escalate keep-data into deletion");
    assert.ok(nativeEvents.indexOf("phrase:finish") < nativeEvents.indexOf("forget:start"));
    assert.equal(engine.useSync.getState().enabled, false);
    assert.equal(JSON.parse(shell.docs.get("sync.json")).enabled, false);
  });
}

test("a stop deadline reports incomplete without releasing the recovery ownership gate", { timeout: 20_000 }, async () => {
  const { engine } = await persistenceFixture("stop-native-deadline");
  serialNative = true;
  let release;
  phraseWait = new Promise((resolve) => { release = resolve; });
  const recovering = engine.enterRecoveryPhrase("/sync", "held phrase");
  await settle();
  const calls = folderCalls.length;
  const stopping = engine.stopSync({ deleteData: true });
  const deadlines = [...timers.values()].filter(({ delay }) => delay === 10_000);
  assert.equal(deadlines.length, 1);
  deadlines[0].run();
  try {
    assert.match((await stopping).error, /hasn’t stopped yet/);
    assert.equal(engine.stopSync(), stopping);
    assert.deepEqual(await engine.enterRecoveryPhrase("/sync", "late phrase"), { error: "unavailable" });
    assert.ok("error" in await engine.turnOnSync("/replacement"));
    await engine.syncNow();
    assert.equal(folderCalls.length, calls);
    assert.deepEqual(forgotten, []);
    assert.deepEqual(deleted, []);
    assert.equal(engine.useSync.getState().enabled, true, "a report timeout is not native completion");
  } finally {
    release();
    await recovering;
    phraseWait = null;
    await settle();
  }
  assert.equal(engine.useSync.getState().enabled, false);
  assert.deepEqual(deleted, ["/sync"]);
  assert.equal(forgotten.length, 1);
});

test("stop waits for a deferred recovery save and reports a held writer without forgetting", { timeout: 20_000 }, async () => {
  const { engine, doc } = await persistenceFixture("stop-held-writer");
  serialNative = true;
  let release;
  phraseWait = new Promise((resolve) => { release = resolve; });
  const recovering = engine.enterRecoveryPhrase("/sync", "held phrase");
  await settle();
  engine.setTypeSynced("tabs", false);
  shell.heldSaves.on = true;
  const stopping = engine.stopSync();
  release();
  await recovering;
  await settle();
  assert.equal(shell.heldSaves.queue.length, 1, "the owned deferred save was enqueued before recovery completed");
  const deadlines = [...timers.values()].filter(({ delay }) => delay === 10_000);
  assert.equal(deadlines.length, 1);
  deadlines[0].run();
  try {
    assert.ok("error" in await stopping);
    assert.deepEqual(forgotten, []);
    assert.equal(doc().enabled, true);
    assert.deepEqual(await engine.enterRecoveryPhrase("/sync", "late phrase"), { error: "unavailable" });
  } finally {
    shell.heldSaves.on = false;
    for (const land of shell.heldSaves.queue.splice(0)) land();
    await settle();
    phraseWait = null;
  }
  assert.equal(engine.useSync.getState().enabled, false);
  assert.equal(forgotten.length, 1);
});

for (const valid of [true, false]) {
  test(`stop after held ${valid ? "valid" : "invalid"} locked recovery ${valid ? "retires restored scopes" : "reports refusal without forgetting"}`, { timeout: 20_000 }, async () => {
    const { engine, doc } = await persistenceFixture(`stop-locked-${valid}`);
    serialNative = true;
    const device = doc().deviceId;
    keys.clear();
    start(engine);
    await settle();
    assert.equal(engine.useSync.getState().status, "locked");
    let release;
    phraseWait = new Promise((resolve) => { release = resolve; });
    phraseResult = valid ? { ok: true } : { error: "mismatch" };
    const recovering = engine.enterRecoveryPhrase("/sync", "held phrase");
    await settle();
    const stopping = engine.stopSync();
    release();
    await recovering;
    phraseWait = null;
    const result = await stopping;
    if (valid) {
      assert.deepEqual(result, { ok: true });
      assert.deepEqual(forgotten, [device]);
      assert.ok(logs().some((file) => file.ops.some((op) => op.k === `dev:${device}` && op.v === null)));
    } else {
      assert.match(result.error, /couldn’t retire/);
      assert.deepEqual(forgotten, []);
      assert.equal(engine.useSync.getState().enabled, true);
      assert.equal(doc().deviceId, device);
    }
  });
}

test("stop owns a joining recovery even before enabled becomes true", { timeout: 20_000 }, async () => {
  freshFolder();
  serialNative = true;
  const engine = await import("./engine.ts?stop-joining");
  const doc = inspect(engine);
  const before = doc();
  let release;
  phraseWait = new Promise((resolve) => { release = resolve; });
  const recovering = engine.enterRecoveryPhrase("/join-folder", "held phrase");
  await settle();
  const stopping = engine.stopSync();
  assert.equal(doc().enabled, false);
  assert.equal(engine.stopSync({ deleteData: true }), stopping);
  release();
  await recovering;
  phraseWait = null;
  assert.deepEqual(await stopping, { ok: true });
  assert.notEqual(doc(), before, "the owned begin transition is accepted, not mistaken for external replacement");
  assert.equal(doc().enabled, false);
  assert.equal(doc().folder, "/join-folder");
  assert.deepEqual(forgotten, [phraseCalls[0].id]);
  assert.deepEqual(deleted, []);
});

test("stop cancels in-flight setup admission and waits for its serial native cleanup", { timeout: 20_000 }, async () => {
  freshFolder();
  serialNative = true;
  const engine = await import("./engine.ts?stop-starting");
  const doc = inspect(engine);
  let release;
  createWait = new Promise((resolve) => { release = resolve; });
  const starting = engine.turnOnSync("/setup-folder");
  await settle();
  const stopping = engine.stopSync();
  let result;
  stopping.then((value) => { result = value; });
  await settle();
  assert.equal(result, undefined);
  assert.deepEqual(forgotten, []);
  release();
  assert.ok("error" in await starting);
  createWait = null;
  assert.deepEqual(await stopping, { ok: true });
  assert.equal(doc().enabled, false);
  assert.equal(engine.useSync.getState().enabled, false);
  assert.equal(forgotten.length, 1);
  assert.ok(nativeEvents.indexOf("create:finish") < nativeEvents.indexOf("forget:start"));
});

test("a setup already creating its chain cannot call begin after stop intent", { timeout: 20_000 }, async () => {
  freshFolder();
  serialNative = true;
  const engine = await import("./engine.ts?stop-creating-chain");
  const doc = inspect(engine);
  let release;
  createChainWait = new Promise((resolve) => { release = resolve; });
  const starting = engine.turnOnSync("/setup-folder");
  await settle();
  assert.equal(nativeEvents.at(-1), "createChain:start");
  const stopping = engine.stopSync();
  release();
  assert.ok("error" in await starting);
  createChainWait = null;
  assert.deepEqual(await stopping, { ok: true });
  assert.equal(doc().enabled, false);
  assert.equal(forgotten.length, 1);
  assert.ok(nativeEvents.indexOf("createChain:finish") < nativeEvents.indexOf("forget:start"));
});

test("a timed-out pre-native recovery drain cannot let stop bypass its held state writer", { timeout: 20_000 }, async () => {
  const { engine, doc } = await persistenceFixture("stop-recovery-drain-timeout");
  doc().scopes.app.pending = 53;
  shell.heldSaves.on = true;
  const saving = engine.persistScopes();
  await settle();
  const recovering = engine.enterRecoveryPhrase("/sync", "not-yet-native");
  await settle();
  const stopping = engine.stopSync();
  const deadlines = [...timers.values()].filter(({ delay }) => delay === 10_000);
  assert.equal(deadlines.length, 2);
  deadlines[0].run();
  assert.deepEqual(await recovering, { error: "unavailable" });
  deadlines[1].run();
  assert.ok("error" in await stopping);
  try {
    assert.deepEqual(phraseCalls, []);
    assert.deepEqual(forgotten, []);
    assert.equal(engine.stopSync(), stopping);
    assert.equal(doc().enabled, true);
  } finally {
    shell.heldSaves.on = false;
    for (const land of shell.heldSaves.queue.splice(0)) land();
    await saving;
    await settle();
  }
  assert.deepEqual(phraseCalls, []);
  assert.equal(engine.useSync.getState().enabled, false);
  assert.equal(forgotten.length, 1);
});

test("cleanup during the retiring cycle refuses before delete or forget", { timeout: 20_000 }, async () => {
  const { engine, doc } = await persistenceFixture("stop-retiring-cleanup");
  let release;
  chainWait = new Promise((resolve) => { release = resolve; });
  const stopping = engine.stopSync({ deleteData: true });
  await settle();
  const calls = folderCalls.length;
  for (const cleanup of cleanups.splice(0)) cleanup();
  doc().deviceId = "replacement-device";
  doc().folder = "/replacement-folder";
  release();
  assert.ok("error" in await stopping);
  chainWait = null;
  assert.equal(folderCalls.length, calls);
  assert.deepEqual(deleted, []);
  assert.deepEqual(forgotten, []);
  assert.equal(doc().deviceId, "replacement-device");
});

test("an unavailable retiring cycle reports failure and keeps the device key and document", { timeout: 20_000 }, async () => {
  const { engine, doc } = await persistenceFixture("stop-offline");
  const before = doc();
  chainStatus = "unavailable";
  assert.match((await engine.stopSync()).error, /couldn’t retire/);
  assert.deepEqual(forgotten, []);
  assert.equal(doc(), before);
  assert.equal(doc().enabled, true);
  chainStatus = "ok";
  assert.deepEqual(await engine.stopSync(), { ok: true }, "a completed failed attempt releases only its own admission gate");
  assert.equal(forgotten.length, 1);
});

test("cleanup during held recovery invalidates stop ownership without targeting replacement identity", { timeout: 20_000 }, async () => {
  const { engine, doc } = await persistenceFixture("stop-cleanup");
  serialNative = true;
  let release;
  phraseWait = new Promise((resolve) => { release = resolve; });
  const recovering = engine.enterRecoveryPhrase("/sync", "held phrase");
  await settle();
  const stopping = engine.stopSync({ deleteData: true });
  for (const cleanup of cleanups.splice(0)) cleanup();
  doc().folder = "/replacement-folder";
  doc().deviceId = "replacement-device";
  release();
  assert.deepEqual(await recovering, { error: "unavailable" });
  phraseWait = null;
  assert.match((await stopping).error, /Sync changed/);
  assert.deepEqual(forgotten, []);
  assert.deepEqual(deleted, []);
  assert.equal(doc().deviceId, "replacement-device");
});

for (const stage of ["delete", "forget"]) {
  test(`cleanup while ${stage} is pending prevents resetting a replacement document`, { timeout: 20_000 }, async () => {
    const { engine, doc } = await persistenceFixture(`stop-${stage}-replacement`);
    serialNative = true;
    let release;
    const wait = new Promise((resolve) => { release = resolve; });
    if (stage === "delete") deleteWait = wait;
    else forgetWait = wait;
    const stopping = engine.stopSync({ deleteData: stage === "delete" });
    await settle();
    if (stage === "delete") assert.deepEqual(deleted, ["/sync"]);
    else assert.equal(nativeEvents.at(-1), "forget:start");
    for (const cleanup of cleanups.splice(0)) cleanup();
    doc().folder = "/replacement-folder";
    doc().deviceId = "replacement-device";
    release();
    assert.match((await stopping).error, /Sync changed/);
    assert.equal(doc().folder, "/replacement-folder");
    assert.equal(doc().deviceId, "replacement-device");
    assert.ok(!forgotten.includes("replacement-device"));
    if (stage === "delete") assert.deepEqual(forgotten, []);
  });
}

test("a late password consent cannot restart IO or grant authority during stop intent", { timeout: 20_000 }, async () => {
  const { engine } = await persistenceFixture("stop-late-consent");
  engine.setTypeSynced("passwords", true);
  let consentRelease;
  consentWait = new Promise((resolve) => { consentRelease = resolve; });
  const authorizing = engine.authorizePasswords();
  await settle();
  let release;
  phraseWait = new Promise((resolve) => { release = resolve; });
  const recovering = engine.enterRecoveryPhrase("/sync", "held phrase");
  await settle();
  const stopping = engine.stopSync();
  const calls = folderCalls.length;
  consentRelease();
  assert.equal(await authorizing, false);
  assert.equal(passwordGrants.size, 0);
  assert.equal(folderCalls.length, calls);
  release();
  await recovering;
  phraseWait = null;
  consentWait = null;
  assert.deepEqual(await stopping, { ok: true });
});

for (const file of ["sync-journal.nns", "sync-state.nns", "sync.json"]) {
  test(`stop retries failed final ${file} until disabled metadata is durable without repeating native cleanup`, { timeout: 20_000 }, async () => {
    const { engine, doc } = await persistenceFixture(`stop-finalization-${file}`);
    const deleteData = file !== "sync.json";
    const originalSet = shell.docs.set;
    shell.docs.set = function (name, contents) {
      if (forgotten.length && name === file) throw new Error(`Final ${file} failed`);
      return originalSet.call(this, name, contents);
    };
    try {
      assert.match((await engine.stopSync({ deleteData })).error, /failed/);
      assert.equal(doc().enabled, false);
      assert.equal(JSON.parse(shell.docs.get("sync.json")).enabled, true);
      assert.equal(forgotten.length, 1);
      assert.deepEqual(deleted, deleteData ? ["/sync"] : []);
      const types = { ...doc().types };
      const calls = folderCalls.length;
      engine.setTypeSynced("tabs", false);
      assert.deepEqual(doc().types, types);
      assert.ok("error" in await engine.turnOnSync("/new-chain"));
      assert.deepEqual(await engine.enterRecoveryPhrase("/sync", "new phrase"), { error: "unavailable" });
      assert.equal(engine.startSync(), undefined);
      await engine.syncNow();
      assert.equal(folderCalls.length, calls, "retryable finalization retains the admission gate");
      shell.docs.set = originalSet;
      assert.deepEqual(await engine.stopSync({ deleteData: !deleteData }), { ok: true });
      assert.equal(JSON.parse(shell.docs.get("sync.json")).enabled, false);
      assert.equal(shell.docs.get("sync-state.nns"), "");
      assert.equal(shell.docs.get("sync-journal.nns"), "");
      assert.equal(forgotten.length, 1, "a successful forget is never repeated for a disk retry");
      assert.deepEqual(deleted, deleteData ? ["/sync"] : [], "retry preserves the original accepted option");
    } finally {
      shell.docs.set = originalSet;
    }
  });
}

test("stop retries a rejected forget and then a failed state save without repeating completed deletion or forget", { timeout: 20_000 }, async () => {
  const { engine } = await persistenceFixture("stop-forget-and-state-retry");
  let rejectForget = true;
  onForget = () => { if (rejectForget) throw new Error("Forget rejected"); };
  assert.match((await engine.stopSync({ deleteData: true })).error, /Forget rejected/);
  assert.deepEqual(deleted, ["/sync"]);
  assert.deepEqual(forgotten, []);
  rejectForget = false;
  const originalSet = shell.docs.set;
  shell.docs.set = function (name, contents) {
    if (forgotten.length && name === "sync-state.nns") throw new Error("Final state failed");
    return originalSet.call(this, name, contents);
  };
  try {
    assert.match((await engine.stopSync()).error, /Final state failed/);
    assert.equal(forgotten.length, 1);
    assert.deepEqual(deleted, ["/sync"]);
  } finally {
    shell.docs.set = originalSet;
  }
  assert.deepEqual(await engine.stopSync(), { ok: true });
  assert.equal(JSON.parse(shell.docs.get("sync.json")).enabled, false);
  assert.deepEqual(deleted, ["/sync"]);
  assert.equal(forgotten.length, 1);
  assert.equal(nativeEvents.filter((event) => event === "forget:start").length, 2, "only the rejected forget is retried");
});

for (const offline of [false, true]) {
  test(`stop drains existing startup and held state writer ${offline ? "without stranding readiness after an offline refusal" : "before retiring"}`, { timeout: 20_000 }, async () => {
    const { engine, doc } = await persistenceFixture(`stop-startup-drain-${offline}`);
    doc().scopes.app.pending++;
    shell.heldSaves.on = true;
    const saving = engine.persistScopes();
    await settle();
    assert.equal(shell.heldSaves.queue.length, 1);
    const native = globalThis.acTestNativeModules.ArdiaSync;
    const unlock = native.unlock;
    let release;
    native.unlock = () => new Promise((resolve) => { release = resolve; });
    try {
      start(engine);
      const stopping = engine.stopSync();
      release(true);
      await settle();
      assert.deepEqual(forgotten, []);
      chainStatus = offline ? "unavailable" : "ok";
      shell.heldSaves.on = false;
      for (const land of shell.heldSaves.queue.splice(0)) land();
      await saving.catch(() => {});
      const result = await stopping;
      if (offline) {
        assert.ok("error" in result);
        assert.equal(doc().enabled, true);
        chainStatus = "ok";
        const calls = folderCalls.length;
        await engine.syncNow();
        assert.ok(folderCalls.length > calls, "the owned startup completed and restored readiness despite stop intent");
        assert.deepEqual(await engine.stopSync(), { ok: true });
      } else assert.deepEqual(result, { ok: true });
      assert.equal(doc().enabled, false);
      assert.equal(JSON.parse(shell.docs.get("sync.json")).enabled, false);
      assert.equal(forgotten.length, 1);
    } finally {
      native.unlock = unlock;
      shell.heldSaves.on = false;
      for (const land of shell.heldSaves.queue.splice(0)) land();
      await saving.catch(() => {});
    }
  });
}

const stopSheetFixture = async (engine) => {
  const { readFileSync } = await import("node:fs");
  const { runInNewContext } = await import("node:vm");
  const ts = (await import("typescript")).default;
  const source = readFileSync(new URL("../components/settings/panes/SyncSheets.tsx", import.meta.url), "utf8");
  const component = source.slice(source.indexOf("function DeleteDataSheet()"), source.indexOf("export function folderLabel"));
  const compiled = ts.transpileModule(component, { compilerOptions: { target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.React, jsxFactory: "h", jsxFragmentFactory: "Fragment" } }).outputText;
  const state = [true, false, null];
  let index = 0;
  let closed = 0;
  const choices = [];
  const scope = {
    h: (type, props, ...children) => ({ type, props: props ?? {}, children: children.flat(Infinity) }),
    useState: (initial) => {
      const at = index++;
      if (!(at in state)) state[at] = initial;
      return [state[at], (value) => { state[at] = value; }];
    },
    useRef: (initial) => {
      const at = index++;
      if (!(at in state)) state[at] = { current: initial };
      return state[at];
    },
    stopSync: (options) => { choices.push(options.deleteData); return engine.stopSync(options); },
    closeSettingsSheet: () => { closed++; },
    Fragment: "Fragment", Sheet: "Sheet", Title: "Title", Body: "Body", View: "View", Checkbox: "Checkbox", Buttons: "Buttons", Button: "Button",
  };
  runInNewContext(compiled, scope);
  return {
    render: () => { index = 0; return scope.DeleteDataSheet(); },
    find: function find(node, title) {
      return node && typeof node === "object" ? node.props.title === title ? node : node.children.map((child) => find(child, title)).find(Boolean) : undefined;
    },
    choices,
    closed: () => closed,
  };
};

for (const chainCreating of [false, true]) {
  test(`stop retains rejected cleanup of an unadopted setup ${chainCreating ? "already creating a chain" : "creating a phrase"}`, { timeout: 20_000 }, async () => {
    freshFolder();
    serialNative = true;
    const engine = await import(`./engine.ts?stop-rejected-setup-${chainCreating}`);
    const doc = inspect(engine);
    let release;
    const wait = new Promise((resolve) => { release = resolve; });
    if (chainCreating) createChainWait = wait;
    else createWait = wait;
    const attempts = [];
    let refusing = true;
    onForget = (id) => { attempts.push(id); if (refusing) throw new Error("Setup forget rejected"); };
    const starting = engine.turnOnSync("/setup-folder").catch((error) => ({ error: error.message }));
    await settle();
    const stopping = engine.stopSync();
    assert.equal(engine.stopSync({ deleteData: true }), stopping);
    release();
    assert.ok("error" in await starting);
    const result = await stopping;
    assert.match(result.error, /Setup forget rejected/);
    assert.equal(result.pending, true);
    assert.equal(keys.size, 1);
    const generated = [...keys][0];
    assert.ok(attempts.every((id) => id === generated));
    assert.deepEqual(forgotten, []);
    assert.ok("error" in await engine.turnOnSync("/another-folder"));
    assert.deepEqual(await engine.enterRecoveryPhrase("/sync", "new phrase"), { error: "unavailable" });
    assert.equal(engine.startSync(), undefined);
    refusing = false;
    assert.deepEqual(await engine.stopSync({ deleteData: true }), { ok: true });
    assert.deepEqual(forgotten, [generated]);
    assert.equal(keys.size, 0);
    assert.deepEqual(deleted, [], "a retry cannot escalate the first stop's keep choice");
    assert.equal(doc().enabled, false);
    assert.deepEqual(await engine.stopSync(), { ok: true });
    assert.deepEqual(forgotten, [generated]);
  });
}

test("setup without stop retains its rejected cleanup and retries it before generating another identity", { timeout: 20_000 }, async () => {
  freshFolder();
  serialNative = true;
  const engine = await import("./engine.ts?setup-rejected-cleanup-no-stop");
  inspect(engine);
  const native = globalThis.acTestNativeModules.ArdiaSync;
  const createChain = native.createChain;
  const chooseFolder = native.chooseFolder;
  let refusing = true;
  native.createChain = async () => { throw new Error("Chain failed"); };
  onForget = () => { if (refusing) throw new Error("Cleanup failed"); };
  try {
    const first = await engine.turnOnSync("/bad-folder").catch((error) => ({ error: error.message }));
    assert.ok("error" in first);
    const generated = [...keys][0];
    assert.ok(generated);
    assert.equal(engine.startSync(), undefined, "a pending setup cleanup cannot be replaced by startup");
    native.chooseFolder = async () => "/replacement-folder";
    assert.equal(await engine.chooseSyncFolder(), null, "a pending setup cleanup retains its folder context");
    assert.ok("error" in await engine.turnOnSync("/bad-folder"));
    assert.equal(keys.size, 1);
    refusing = false;
    native.createChain = createChain;
    assert.deepEqual(await engine.turnOnSync("/good-folder"), { ok: true });
    assert.deepEqual(forgotten, [generated]);
    assert.equal(keys.size, 1);
    assert.ok(!keys.has(generated));
    assert.deepEqual(await engine.stopSync(), { ok: true });
    assert.equal(keys.size, 0);
  } finally {
    native.createChain = createChain;
    native.chooseFolder = chooseFolder;
  }
});

test("a declined phrase creation does not forget a device that was never created", { timeout: 20_000 }, async () => {
  freshFolder();
  const engine = await import("./engine.ts?setup-not-created");
  inspect(engine);
  const native = globalThis.acTestNativeModules.ArdiaSync;
  const createPhrase = native.createPhrase;
  let release;
  native.createPhrase = () => new Promise((resolve) => { release = resolve; });
  try {
    const starting = engine.turnOnSync("/sync");
    const stopping = engine.stopSync();
    release(false);
    assert.ok("error" in await starting);
    assert.deepEqual(await stopping, { ok: true });
    assert.deepEqual(forgotten, []);
    assert.equal(nativeEvents.filter((event) => event === "forget:start").length, 0);
  } finally {
    native.createPhrase = createPhrase;
  }
});

test("setup cleanup can retry a synchronous native bridge rejection and coalesces the retry", { timeout: 20_000 }, async () => {
  freshFolder();
  const engine = await import("./engine.ts?setup-cleanup-bridge-rejection");
  inspect(engine);
  const native = globalThis.acTestNativeModules.ArdiaSync;
  const forget = native.forget;
  let releaseCreate;
  let releaseForget;
  createWait = new Promise((resolve) => { releaseCreate = resolve; });
  native.forget = () => { throw new Error("Bridge rejected cleanup"); };
  try {
    const starting = engine.turnOnSync("/sync");
    const stopping = engine.stopSync();
    releaseCreate();
    assert.ok("error" in await starting);
    assert.equal((await stopping).pending, true);
    const generated = [...keys][0];
    native.forget = forget;
    forgetWait = new Promise((resolve) => { releaseForget = resolve; });
    const retry = engine.stopSync();
    assert.equal(engine.stopSync({ deleteData: true }), retry);
    await settle();
    assert.equal(nativeEvents.filter((event) => event === "forget:start").length, 1);
    assert.deepEqual(forgotten, []);
    releaseForget();
    assert.deepEqual(await retry, { ok: true });
    assert.deepEqual(forgotten, [generated]);
    assert.deepEqual(deleted, []);
  } finally {
    releaseCreate();
    releaseForget?.();
    native.forget = forget;
  }
});

test("a setup cleanup timeout retains exclusion and the generated identity across lifecycle cleanup", { timeout: 20_000 }, async () => {
  freshFolder();
  serialNative = true;
  const engine = await import("./engine.ts?setup-cleanup-held-timeout");
  const doc = inspect(engine);
  let releaseCreate;
  let releaseForget;
  createWait = new Promise((resolve) => { releaseCreate = resolve; });
  forgetWait = new Promise((resolve) => { releaseForget = resolve; });
  const starting = engine.turnOnSync("/sync");
  await settle();
  const stopping = engine.stopSync();
  releaseCreate();
  await settle();
  const generated = [...keys][0];
  const deadlines = [...timers.values()].filter(({ delay }) => delay === 10_000);
  assert.equal(deadlines.length, 1);
  deadlines[0].run();
  assert.equal((await stopping).pending, true);
  for (const cleanup of cleanups.splice(0)) cleanup();
  doc().deviceId = "foreign-device";
  doc().folder = "/foreign-folder";
  keys.add("foreign-device");
  assert.equal(engine.stopSync(), stopping);
  assert.deepEqual(forgotten, []);
  assert.ok("error" in await engine.turnOnSync("/other"));
  releaseForget();
  await starting;
  await settle();
  assert.deepEqual(forgotten, [generated]);
  assert.ok(keys.has("foreign-device"));
  assert.equal(doc().deviceId, "foreign-device");
  assert.deepEqual(deleted, []);
});

test("stale setup cleanup cannot borrow a replacement document device for forget", { timeout: 20_000 }, async () => {
  freshFolder();
  const engine = await import("./engine.ts?setup-stale-target-cleanup");
  const doc = inspect(engine);
  const target = doc();
  const folder = target.folder;
  let release;
  createWait = new Promise((resolve) => { release = resolve; });
  const starting = engine.turnOnSync("/setup-folder");
  for (const cleanup of cleanups.splice(0)) cleanup();
  target.deviceId = "replacement-device";
  target.folder = "/replacement-folder";
  keys.add("replacement-device");
  release();
  assert.ok("error" in await starting);
  assert.deepEqual(forgotten, []);
  assert.ok("error" in await engine.stopSync());
  assert.deepEqual(forgotten, []);
  assert.equal(doc().deviceId, "replacement-device");
  target.deviceId = null;
  target.folder = folder;
  assert.deepEqual(await engine.stopSync(), { ok: true });
  assert.equal(forgotten.length, 1);
  assert.notEqual(forgotten[0], "replacement-device");
  assert.ok(keys.has("replacement-device"));
});

test("the actual stop sheet can dismiss a definitive locked refusal to reach recovery", { timeout: 20_000 }, async () => {
  const { engine } = await persistenceFixture("stop-sheet-definitive-refusal");
  const native = globalThis.acTestNativeModules.ArdiaSync;
  const unlock = native.unlock;
  native.unlock = async () => false;
  try {
    start(engine);
    await settle();
    assert.equal(engine.useSync.getState().status, "locked");
    const sheet = await stopSheetFixture(engine);
    sheet.find(sheet.render(), "Keep Sync Data").props.onPress();
    await settle();
    const refusal = sheet.render();
    assert.ok(sheet.find(refusal, "Close"));
    const choices = sheet.choices.length;
    refusal.props.onClose();
    await settle();
    assert.equal(sheet.closed(), 1);
    assert.equal(sheet.choices.length, choices, "dismissal must not start another refused stop");
    assert.deepEqual(forgotten, []);
    assert.equal(engine.useSync.getState().enabled, true);
    assert.ok("ok" in await engine.enterRecoveryPhrase("/sync", "recovered phrase"));
    assert.deepEqual(await engine.stopSync(), { ok: true });
  } finally {
    native.unlock = unlock;
  }
});

test("the actual stop sheet cannot dismiss or change a parked post-forget finalization", { timeout: 20_000 }, async () => {
  const { engine } = await persistenceFixture("stop-sheet-parked-finalization");
  const originalSet = shell.docs.set;
  shell.docs.set = function (name, contents) {
    if (forgotten.length && name === "sync.json") throw new Error("Final metadata failed");
    return originalSet.call(this, name, contents);
  };
  try {
    const sheet = await stopSheetFixture(engine);
    sheet.find(sheet.render(), "Keep Sync Data").props.onPress();
    await settle();
    const parked = sheet.render();
    assert.equal(sheet.find(parked, "Close"), undefined);
    assert.equal(sheet.find(parked, "Delete My Sync Data"), undefined);
    parked.props.onClose();
    await settle();
    assert.equal(sheet.closed(), 0);
    assert.deepEqual(sheet.choices, [false, false]);
    assert.ok("error" in await engine.turnOnSync("/new-folder"));
    shell.docs.set = originalSet;
    sheet.find(sheet.render(), "Retry Stop").props.onPress();
    await settle();
    assert.equal(sheet.closed(), 1);
    assert.equal(JSON.parse(shell.docs.get("sync.json")).enabled, false);
    assert.equal(forgotten.length, 1);
    assert.deepEqual(deleted, []);
  } finally {
    shell.docs.set = originalSet;
  }
});

test("startup configuration edits before stop do not discard the owned readiness restoration", { timeout: 20_000 }, async () => {
  const { engine } = await persistenceFixture("stop-startup-config-edit");
  const native = globalThis.acTestNativeModules.ArdiaSync;
  const unlock = native.unlock;
  let release;
  native.unlock = () => new Promise((resolve) => { release = resolve; });
  try {
    start(engine);
    engine.setTypeSynced("tabs", false);
    const stopping = engine.stopSync();
    release(true);
    assert.deepEqual(await stopping, { ok: true });
    assert.equal(JSON.parse(shell.docs.get("sync.json")).enabled, false);
  } finally {
    native.unlock = unlock;
  }
});

test("owned cleanup releases a parked finalization gate without repeating completed native work", { timeout: 20_000 }, async () => {
  const { engine } = await persistenceFixture("stop-finalization-cleanup");
  const originalSet = shell.docs.set;
  shell.docs.set = function (name, contents) {
    if (forgotten.length && name === "sync.json") throw new Error("Final metadata failed");
    return originalSet.call(this, name, contents);
  };
  try {
    assert.ok("error" in await engine.stopSync());
  } finally {
    shell.docs.set = originalSet;
  }
  for (const cleanup of cleanups.splice(0)) cleanup();
  const cleanup = engine.startSync();
  assert.equal(typeof cleanup, "function");
  cleanups.push(cleanup);
  await settle();
  assert.equal(engine.useSync.getState().status, "locked");
  assert.equal(forgotten.length, 1);
});

test("recovery and stop can drain the same existing startup without a dependency cycle", { timeout: 20_000 }, async () => {
  const { engine } = await persistenceFixture("stop-startup-recovery");
  const native = globalThis.acTestNativeModules.ArdiaSync;
  const unlock = native.unlock;
  let release;
  native.unlock = () => new Promise((resolve) => { release = resolve; });
  try {
    start(engine);
    const recovering = engine.enterRecoveryPhrase("/sync", "held startup phrase");
    const stopping = engine.stopSync();
    await settle();
    assert.deepEqual(phraseCalls, []);
    assert.deepEqual(forgotten, []);
    release(true);
    assert.ok("ok" in await recovering);
    assert.deepEqual(await stopping, { ok: true });
    assert.equal(forgotten.length, 1);
    assert.equal(JSON.parse(shell.docs.get("sync.json")).enabled, false);
  } finally {
    native.unlock = unlock;
  }
});

test("a startup-load stop deadline does not cancel its owner or restore readiness after cleanup", { timeout: 20_000 }, async () => {
  const { engine, doc } = await persistenceFixture("stop-startup-load-cleanup");
  const native = globalThis.acTestNativeModules.ArdiaSync;
  const openLocal = native.openLocal;
  let release;
  let held = true;
  const wait = new Promise((resolve) => { release = resolve; });
  native.openLocal = async (text) => {
    if (held) { held = false; await wait; }
    return openLocal(text);
  };
  try {
    start(engine);
    await settle();
    assert.equal(held, false, "startup is awaiting a real state decryption result");
    const stopping = engine.stopSync();
    const deadlines = [...timers.values()].filter(({ delay }) => delay === 10_000);
    assert.equal(deadlines.length, 1);
    deadlines[0].run();
    assert.ok("error" in await stopping);
    assert.equal(engine.stopSync(), stopping);
    assert.deepEqual(forgotten, []);
    for (const cleanup of cleanups.splice(0)) cleanup();
    const target = doc();
    const scopes = target.scopes;
    target.deviceId = "replacement-device";
    target.folder = "/replacement-folder";
    release();
    await settle();
    assert.equal(doc(), target);
    assert.equal(doc().scopes, scopes, "the stale startup cannot install a decoded state snapshot");
    assert.deepEqual(forgotten, []);
    assert.deepEqual(deleted, []);
    const calls = folderCalls.length;
    await engine.syncNow();
    assert.equal(folderCalls.length, calls, "cleanup cannot be undone by a late readiness callback");
  } finally {
    release();
    native.openLocal = openLocal;
  }
});

for (const deleteData of [false, true]) {
  test(`the actual stop sheet retains its accepted ${deleteData ? "delete" : "keep"} choice after a report timeout`, { timeout: 20_000 }, async () => {
    const { engine } = await persistenceFixture(`stop-sheet-choice-${deleteData}`);
    let release;
    phraseWait = new Promise((resolve) => { release = resolve; });
    const recovering = engine.enterRecoveryPhrase("/sync", "held phrase");
    await settle();
    const sheet = await stopSheetFixture(engine);
    const title = deleteData ? "Delete My Sync Data" : "Keep Sync Data";
    sheet.find(sheet.render(), title).props.onPress();
    await settle();
    const deadlines = [...timers.values()].filter(({ delay }) => delay === 10_000);
    assert.equal(deadlines.length, 1);
    deadlines[0].run();
    await settle();
    try {
      assert.equal(sheet.closed(), 0);
      const after = sheet.render();
      assert.equal(sheet.find(after, "Delete My Sync Data"), undefined, "a timeout cannot reopen the destructive choice");
      assert.equal(sheet.find(after, "Keep Sync Data"), undefined);
      assert.equal(sheet.find(after, "Retry Stop").props.disabled, false);
      release();
      await recovering;
      phraseWait = null;
      await settle();
      assert.deepEqual(deleted, deleteData ? ["/sync"] : []);
      sheet.find(sheet.render(), "Retry Stop").props.onPress();
      await settle();
      assert.equal(sheet.closed(), 1);
      assert.deepEqual(sheet.choices, [deleteData, deleteData]);
      assert.deepEqual(deleted, deleteData ? ["/sync"] : []);
    } finally {
      release();
      await recovering;
      phraseWait = null;
    }
  });
}

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
