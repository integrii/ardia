const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
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
  let invalidate;
  let cleanup;
  let clears = 0;
  let revocations = 0;
  let closed = 0;
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
      authorizeRecovery: () => auth.promise,
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
  const access = context.makeAccess(() => { clears++; });
  return { access, auth, states, invalidate: () => invalidate(), cleanup: () => cleanup(), clears: () => clears, revocations: () => revocations, closed: () => closed };
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
  }
  console.log("PASS: 5 production recovery hook scenarios; no pre-auth generation, no late image/word disclosure, denial and dismissal");
})().catch(error => { console.error(error); process.exitCode = 1; });
