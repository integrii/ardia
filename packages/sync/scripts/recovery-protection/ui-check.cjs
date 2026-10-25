const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto");
const os = require("node:os");
const root = path.resolve(__dirname, "../../../..");
const ts = require(path.join(root, "node_modules/typescript"));
const source = fs.readFileSync(path.join(root, "apps/browser/src/components/settings/panes/SyncSheets.tsx"), "utf8");
const ast = ts.createSourceFile("SyncSheets.tsx", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
const hook = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === "useRecoveryAccess");
assert.ok(hook);
const compiled = ts.transpileModule(hook.getText(ast) + "\nglobalThis.makeAccess = useRecoveryAccess;", { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
function setup() {
  const auth = deferred();
  const authorizations = [auth];
  let invalidate;
  let cleanup;
  let clears = 0;
  let revocations = 0;
  let closed = 0;
  let rendered = null;
  const states = [];
  const context = {
    useRef: current => ({ current }),
    useState: value => {
      const index = states.length;
      states.push(value);
      return [value, next => { states[index] = next; }];
    },
    useEffect: effect => { cleanup = effect(); },
    SyncNative: {
      authorizeRecovery: () => {
        assert.ok(authorizations.length, "each authorization has an independent deferred response");
        return authorizations.shift().promise;
      },
      revokeRecoveryAuthorization: () => { revocations++; },
      addListener: (event, handler) => {
        assert.equal(event, "onRecoveryInvalidated");
        invalidate = handler;
        return { remove() {} };
      },
    },
    closeSettingsSheet: () => { closed++; },
  };
  vm.createContext(context);
  vm.runInContext(compiled, context);
  const access = context.makeAccess(() => { clears++; rendered = null; });
  return {
    access, auth, states, invalidate: () => invalidate(), cleanup: () => cleanup(),
    clears: () => clears, revocations: () => revocations, closed: () => closed,
    render: value => { rendered = value; }, rendered: () => rendered,
    queueAuth: () => { const next = deferred(); authorizations.push(next); return next; },
  };
}

const paneSource = fs.readFileSync(path.join(root, "apps/browser/src/components/settings/panes/Sync.tsx"), "utf8");
const paneAst = ts.createSourceFile("Sync.tsx", paneSource, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
const pane = paneAst.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === "SyncOn");
const advanced = pane.body.statements.find(node => ts.isVariableStatement(node) && node.declarationList.declarations[0].name.getText(paneAst) === "advanced");
assert.ok(advanced);
const advancedCompiled = ts.transpileModule(advanced.getText(paneAst) + "\nglobalThis.advanced = advanced;", { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
function setupAdvanced(result) {
  const errors = [];
  const arguments = [];
  let revocations = 0;
  const context = {
    info: null,
    showMenu: async () => "copy", setRecoveryError: error => errors.push(error),
    SyncNative: {
      copyRecoveryPhrase: (...args) => { arguments.push(args); return result; },
      revokeRecoveryAuthorization: () => { revocations++; },
    },
  };
  vm.createContext(context);
  vm.runInContext(advancedCompiled, context);
  return { run: context.advanced, errors, arguments, revocations: () => revocations };
}

async function checkRecoveryFixtureBootstrap() {
  const e2e = fs.readFileSync(path.join(root, "packages/sync/scripts/e2e.mjs"), "utf8");
  const bootstrapStart = e2e.indexOf("  const deniedWords =");
  const bootstrapEnd = e2e.indexOf('  check("the phrase is 24 words"', bootstrapStart);
  assert.ok(bootstrapStart >= 0 && bootstrapEnd > bootstrapStart);
  const bip39Start = e2e.indexOf("function bip39(");
  const bip39End = e2e.indexOf("\n}\n", bip39Start) + 2;
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "recovery-bootstrap-"));
  try {
    const wordlist = fs.readFileSync(path.join(root, "packages/sync/ios/Core/Wordlist.swift"), "utf8");
    fs.writeFileSync(path.join(scratch, "english.txt"), [...wordlist.matchAll(/"([a-z]+)"/g)].map(match => match[1]).join("\n"));
    const syntheticKey = path.join(scratch, "sync-key-synthetic");
    fs.writeFileSync(syntheticKey, Buffer.alloc(32));
    const run = async denied => {
      const context = {
        fs, path, crypto, WORK: scratch, DEV: { A: { dir: scratch } },
        ev: async (device, expression) => {
          assert.equal(device, "A");
          assert.equal(expression, "return acSync.native.recoveryWords()");
          return denied;
        },
        check: (name, allowed) => assert.equal(allowed, true, name),
      };
      vm.createContext(context);
      vm.runInContext(e2e.slice(bip39Start, bip39End), context);
      return vm.runInContext("(async () => {\n" + e2e.slice(bootstrapStart, bootstrapEnd) + "\nreturn phrase; })()", context);
    };
    assert.equal(await run(null), [...Array(23).fill("abandon"), "art"].join(" "));
    await assert.rejects(run(["unauthorized secret"]), /authorization/);
    fs.writeFileSync(syntheticKey, Buffer.alloc(31));
    await assert.rejects(run(null), /32 bytes/);
    fs.writeFileSync(path.join(scratch, "sync-key-second"), Buffer.alloc(32));
    await assert.rejects(run(null), /one synthetic sync key/);
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

function checkNativeRecoveryBoundaries() {
  const native = fs.readFileSync(path.join(root, "packages/sync/ios/SyncModule.swift"), "utf8");
  for (const name of ["recoveryWords", "qrCode", "recoveryKitPreview", "saveRecoveryKit", "copyRecoveryKit", "shareRecoveryKit", "copyRecoveryPhrase"]) {
    const start = native.indexOf('AsyncFunction("' + name + '")');
    const end = native.indexOf("}.runOnQueue(.main)", start);
    assert.ok(start >= 0 && end > start);
    assert.match(native.slice(start, end), /self\.(?:recoveryOperation|authorizeRecovery)(?:\(|\s*\{)/, name + " retains native authorization");
  }
  const exports = fs.readFileSync(path.join(root, "packages/sync/ios/Core/RecoveryExports.swift"), "utf8");
  const opens = exports.split("\n").filter(line => /\bopen(?:at)?\(/.test(line));
  assert.equal(opens.length, 5);
  for (const open of opens) assert.ok(open.includes("O_CLOEXEC"), open);
  assert.match(native, /return self\.clipboard\(\)\.write\(url as NSURL\)/);
  assert.match(native, /endAuthorization: endAuthorization == true/);
}
(async () => {
  {
    const test = setup();
    const image = deferred();
    let loads = 0;
    let accepted = 0;
    const pending = test.access.run(() => { loads++; return image.promise; }, () => { accepted++; }, true);
    assert.equal(loads, 0);
    test.auth.resolve(true);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(loads, 1);
    test.invalidate();
    image.resolve("mock-secret-image");
    await pending;
    assert.equal(accepted, 0);
    assert.equal(test.clears(), 1);
    assert.equal(test.states[0], false);
  }
  {
    const test = setup();
    const words = deferred();
    let accepted = 0;
    const pending = test.access.run(() => words.promise, () => { accepted++; }, true);
    test.auth.resolve(true);
    await new Promise(resolve => setImmediate(resolve));
    test.cleanup();
    words.resolve(["mock secret"]);
    await pending;
    assert.equal(accepted, 0);
    assert.equal(test.revocations(), 1);
  }
  {
    const test = setup();
    let loads = 0;
    const pending = test.access.run(async () => { loads++; return "mock"; }, undefined, true);
    test.invalidate();
    test.auth.resolve(true);
    await pending;
    assert.equal(loads, 0);
  }
  {
    const test = setup();
    let loads = 0;
    const pending = test.access.run(async () => { loads++; return "mock"; }, undefined, true);
    test.auth.resolve(false);
    await pending;
    assert.equal(loads, 0);
    assert.deepEqual(test.states, [false, false, null]);
  }
  {
    const test = setup();
    const pending = test.access.run(async () => "mock", undefined, true);
    test.access.close();
    test.auth.resolve(true);
    await pending;
    assert.equal(test.closed(), 1);
    assert.equal(test.revocations(), 1);
    assert.equal(test.states[0], false);
    assert.equal(test.clears(), 1);
  }
  {
    const test = setup();
    const pending = test.access.run(async () => "accepted mock preview", test.render, true);
    test.auth.resolve(true);
    await pending;
    assert.equal(test.rendered(), "accepted mock preview");
    assert.deepEqual(test.states, [true, false, null]);
    test.access.close();
    assert.equal(test.rendered(), null);
    assert.equal(test.clears(), 1);
    assert.equal(test.closed(), 1);
  }
  {
    const test = setup();
    let oldLoads = 0;
    const old = test.access.run(async () => { oldLoads++; return "old secret"; }, test.render, true);
    test.invalidate();
    const nextAuth = test.queueAuth();
    const newer = test.access.run(async () => "new secret", test.render, true);
    nextAuth.resolve(true);
    await newer;
    test.auth.resolve(true);
    await old;
    assert.equal(oldLoads, 0);
    assert.equal(test.rendered(), "new secret");
    assert.equal(test.clears(), 1);
    assert.deepEqual(test.states, [true, false, null]);
  }
  {
    const test = setup();
    const oldResult = deferred();
    const old = test.access.run(() => oldResult.promise, test.render, true);
    test.auth.resolve(true);
    await new Promise(resolve => setImmediate(resolve));
    test.invalidate();
    const nextAuth = test.queueAuth();
    const newResult = deferred();
    const newer = test.access.run(() => newResult.promise, test.render, true);
    nextAuth.resolve(true);
    await new Promise(resolve => setImmediate(resolve));
    oldResult.resolve(null);
    await old;
    assert.equal(test.states[1], true);
    newResult.resolve("new secret survives old result");
    await newer;
    assert.equal(test.rendered(), "new secret survives old result");
    assert.equal(test.clears(), 1);
    assert.equal(test.revocations(), 0);
    assert.deepEqual(test.states, [true, false, null]);
  }
  for (const result of [false, null, undefined]) {
    const test = setupAdvanced(Promise.resolve(result));
    await test.run();
    assert.match(test.errors[1], /wasn’t copied.*Unlock/);
    assert.equal(test.revocations(), 0);
    assert.deepEqual(test.arguments, [[true]]);
  }
  {
    const test = setupAdvanced(Promise.reject(new Error("write failed")));
    await test.run();
    assert.match(test.errors[1], /Couldn’t copy/);
  }
  {
    const copy = deferred();
    const test = setupAdvanced(copy.promise);
    const pending = test.run();
    await new Promise(resolve => setImmediate(resolve));
    copy.resolve(null);
    await pending;
    assert.equal(test.revocations(), 0, "late Advanced Copy cannot globally revoke a newer sheet grant");
  }
  {
    const test = setupAdvanced(Promise.resolve(true));
    await test.run();
    assert.deepEqual(test.errors, [null]);
    assert.deepEqual(test.arguments, [[true]]);
  }
  console.log("PASS: 14 production recovery UI scenarios; success acceptance, independent newer sessions, dismissal clearing, copy denial and scoped cleanup");
  await checkRecoveryFixtureBootstrap();
  console.log("PASS: 4 production E2E bootstrap scenarios; denied words, synthetic fixture only, malformed and ambiguous fixture rejection");
  checkNativeRecoveryBoundaries();
  console.log("PASS: 7 native recovery authorization boundaries and all 5 close-on-exec open sites retained");
})().catch(error => { console.error(error); process.exitCode = 1; });
