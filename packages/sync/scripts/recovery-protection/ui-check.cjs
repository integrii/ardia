const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto");
const os = require("node:os");
const childProcess = require("node:child_process");
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
    access, auth, states, native: context.SyncNative, invalidate: () => invalidate(), cleanup: () => cleanup(),
    clears: () => clears, revocations: () => revocations, closed: () => closed,
    render: value => { rendered = value; }, rendered: () => rendered,
    queueAuth: () => { const next = deferred(); authorizations.push(next); return next; },
  };
}

function setupSheetCopy(test, component, title, response, choice = "copy") {
  const sheet = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === component);
  assert.ok(sheet);
  let press;
  const find = node => {
    if (ts.isJsxSelfClosingElement(node) && node.tagName.getText(ast) === "Button") {
      const attributes = node.attributes.properties;
      const label = attributes.find(attribute => ts.isJsxAttribute(attribute) && attribute.name.getText(ast) === "title");
      if (label?.initializer && ts.isStringLiteral(label.initializer) && label.initializer.text === title) {
        press = attributes.find(attribute => ts.isJsxAttribute(attribute) && attribute.name.getText(ast) === "onPress")?.initializer?.expression;
      }
    }
    ts.forEachChild(node, find);
  };
  find(sheet);
  assert.ok(press, title + " retains its production button callback");
  const more = sheet.body.statements.find(node => ts.isVariableStatement(node) && node.declarationList.declarations[0].name.getText(ast) === "more");
  let pending;
  const calls = [];
  const copy = (...args) => { calls.push(args); return response(); };
  test.native.copyRecoveryPhrase = copy;
  test.native.copyRecoveryKit = copy;
  const context = {
    access: { ...test.access, run: (...args) => { pending = test.access.run(...args); return pending; } },
    SyncNative: test.native, showMenu: async () => choice, setSaved: () => {},
  };
  vm.createContext(context);
  const callback = (more ? more.getText(ast) + "\n" : "") + "globalThis.press = " + press.getText(ast) + ";";
  vm.runInContext(ts.transpileModule(callback, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText, context);
  return { calls, press: async () => { context.press(); assert.ok(pending); await pending; } };
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

function checkRunnerWithoutPython() {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "recovery-runner-node-"));
  try {
    const bin = path.join(scratch, "bin");
    fs.mkdirSync(bin);
    for (const command of ["dirname", "mkdir", "mktemp", "rm"]) {
      const executable = childProcess.execFileSync("/usr/bin/which", [command], { encoding: "utf8" }).trim();
      fs.symlinkSync(executable, path.join(bin, command));
    }
    const node = path.join(scratch, "configured-node");
    fs.writeFileSync(node, '#!/bin/bash\nif [[ "${1:-}" == */ui-check.cjs ]]; then exit 0; fi\nexec ' + JSON.stringify(process.execPath) + ' "$@"\n', { mode: 0o700 });
    const proof = path.join(scratch, "compiled-fixture");
    const compiler = `#!${process.execPath}
const fs = require("node:fs");
const assert = require("node:assert/strict");
const args = process.argv.slice(2);
const source = fs.readFileSync(process.env.RECOVERY_TEST_SOURCE, "utf8");
const start = source.indexOf("  private func recoveryOperation<");
const end = source.indexOf("\\n  private func clipboard()", start);
const expected = "import Foundation\\nextension RecoveryOperationFixture {\\n" + source.slice(start, end).replace("private func", "func") + "\\n}\\n";
const fixture = args.find(value => value.endsWith("/RecoveryOperationFixture.swift"));
assert.equal(fs.readFileSync(fixture, "utf8"), expected);
fs.writeFileSync(process.env.RECOVERY_TEST_PROOF, expected);
const output = args[args.indexOf("-o") + 1];
fs.writeFileSync(output, "#!/bin/bash\\nexit 0\\n", { mode: 0o700 });
`;
    fs.writeFileSync(path.join(bin, "swiftc"), compiler, { mode: 0o700 });
    const script = path.join(root, "packages/sync/scripts/recovery-protection.sh");
    const native = path.join(root, "packages/sync/ios/SyncModule.swift");
    const environment = { ...process.env, PATH: bin, NODE: node, RECOVERY_TEST_SOURCE: native, RECOVERY_TEST_PROOF: proof };
    const run = runner => childProcess.spawnSync("/bin/bash", [runner, path.join(scratch, "caller")], { env: environment, encoding: "utf8", timeout: 20_000 });
    const result = run(script);
    assert.equal(result.status, 0, result.stderr);
    assert.ok(fs.readFileSync(proof, "utf8").includes("func recoveryOperation<"));
    assert.deepEqual(fs.readdirSync(path.join(scratch, "caller")), []);
    const fakeRoot = path.join(scratch, "source-drift");
    const fakeScript = path.join(fakeRoot, "packages/sync/scripts/recovery-protection.sh");
    const fakeNative = path.join(fakeRoot, "packages/sync/ios/SyncModule.swift");
    fs.mkdirSync(path.dirname(fakeScript), { recursive: true });
    fs.mkdirSync(path.dirname(fakeNative), { recursive: true });
    fs.copyFileSync(script, fakeScript);
    const source = fs.readFileSync(native, "utf8");
    for (const drift of [
      source.replace("  private func recoveryOperation<", "  private func renamedRecoveryOperation<"),
      source.replace("\n  private func clipboard()", "\n  private func renamedClipboard()"),
      "\n  private func clipboard()\n  private func recoveryOperation<",
      source + "\n  private func recoveryOperation<",
    ]) {
      fs.rmSync(proof);
      fs.writeFileSync(fakeNative, drift);
      const invalid = run(fakeScript);
      assert.notEqual(invalid.status, 0);
      assert.match(invalid.stderr, /unique bounded recoveryOperation fixture body/);
      assert.equal(fs.existsSync(proof), false, "source drift fails before compilation");
      fs.writeFileSync(proof, "reset");
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
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
  for (const [component, title, label, args] of [
    ["ConnectDeviceSheet", "Copy Words", "phrase", [false]],
    ["RecoveryKitSheet", "Other Options", "kit", []],
  ]) {
    for (const result of [false, null, undefined, new Error("clipboard failed"), true]) {
      const test = setup();
      const unlock = test.access.run(async () => "unlocked mock", undefined, true);
      test.auth.resolve(true);
      await unlock;
      const button = setupSheetCopy(test, component, title, () => result instanceof Error ? Promise.reject(result) : Promise.resolve(result));
      await button.press();
      assert.deepEqual(button.calls, [args]);
      assert.equal(test.states[1], false);
      if (result === true) assert.equal(test.states[2], null);
      else assert.match(test.states[2], new RegExp("Recovery " + label + " wasn’t copied"));
    }
    const test = setup();
    const unlock = test.access.run(async () => "unlocked mock", undefined, true);
    test.auth.resolve(true);
    await unlock;
    const copy = deferred();
    const button = setupSheetCopy(test, component, title, () => copy.promise);
    const pending = button.press();
    await new Promise(resolve => setImmediate(resolve));
    test.invalidate();
    copy.reject(new Error("late clipboard failure"));
    await pending;
    assert.equal(test.states[2], null);
    assert.equal(test.states[0], false);
  }
  {
    const test = setup();
    const unlock = test.access.run(async () => "unlocked mock", undefined, true);
    test.auth.resolve(true);
    await unlock;
    const button = setupSheetCopy(test, "RecoveryKitSheet", "Other Options", () => Promise.resolve(false), null);
    await button.press();
    assert.equal(button.calls.length, 0);
    assert.equal(test.states[2], null);
  }
  console.log("PASS: 27 production recovery UI scenarios; action-specific copy feedback, actual sheet buttons, stale failures, success, dismissal and scoped cleanup");
  await checkRecoveryFixtureBootstrap();
  console.log("PASS: 4 production E2E bootstrap scenarios; denied words, synthetic fixture only, malformed and ambiguous fixture rejection");
  checkNativeRecoveryBoundaries();
  console.log("PASS: 7 native recovery authorization boundaries and all 5 close-on-exec open sites retained");
  checkRunnerWithoutPython();
  console.log("PASS: 5 runner scenarios; configured Node extracts actual Swift body without Python and rejects missing, reversed or ambiguous bounds");
})().catch(error => { console.error(error); process.exitCode = 1; });
