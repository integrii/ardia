import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const directory = dirname(fileURLToPath(import.meta.url));
const root = resolve(directory, "../../..");
const source = readFileSync(join(root, "engine/chromium/src/chrome/browser/ardia/ac_passwords.cc"), "utf8");

test("production snapshot policy and typed conditional-mutation ABI", () => {
  const scratch = mkdtempSync(join(process.env.ARDIA_NATIVE_POLICY_SCRATCH ?? tmpdir(), "ardia-password-policy-"));
  try {
    const binary = join(scratch, "native-policy-test");
    const compiled = spawnSync(process.env.CXX ?? "clang++", [
      "-std=c++20", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
      "-I", join(root, "engine/chromium/src"),
      join(directory, "PasswordSyncNativePolicyTests.cc"), "-o", binary,
    ], { encoding: "utf8", timeout: 120_000 });
    assert.equal(compiled.status, 0, compiled.error?.message ?? compiled.stderr);
    const executed = spawnSync(binary, [], { encoding: "utf8", timeout: 20_000 });
    assert.equal(executed.status, 0, executed.error?.message ?? executed.stderr);
    assert.match(executed.stdout, /Production snapshot policy: 22 cases/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("native read validates the whole collection before sending any rows", () => {
  const read = source.slice(source.indexOf('extern "C" AC_ENGINE_EXPORT void ac_passwords_sync_read('),
    source.indexOf('extern "C" AC_ENGINE_EXPORT void ac_passwords_sync_compare_and_set('));
  assert.match(read, /SyncCredentials credentials[^;]*;\s*if \(!ardia::SyncSnapshotSupported\(credentials\.entries, ardia::Syncable,\s*ardia::SyncOrigins\)\) \{\s*return request->Finish\(false\);\s*\}\s*for \(const auto& credential : credentials\.entries\)/);
  assert.ok(read.indexOf("SyncSnapshotSupported") < read.indexOf("request->Send(row)"));
});

test("production read request preserves old Boolean-status consumers", () => {
  const scratch = mkdtempSync(join(process.env.ARDIA_NATIVE_POLICY_SCRATCH ?? tmpdir(), "ardia-password-read-compat-"));
  try {
    const start = source.indexOf("class SyncRequest {");
    const end = source.indexOf("\n};", start);
    assert.ok(start >= 0 && end > start);
    writeFileSync(join(scratch, "password_sync_read_request.inc"), source.slice(start, end + 3));
    const binary = join(scratch, "read-compat-test");
    const compiled = spawnSync(process.env.CXX ?? "clang++", [
      "-std=c++20", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
      "-I", join(root, "engine/chromium/src"), "-I", scratch,
      join(directory, "PasswordSyncReadCompatibilityTests.cc"), "-o", binary,
    ], { encoding: "utf8", timeout: 120_000 });
    assert.equal(compiled.status, 0, compiled.error?.message ?? compiled.stderr);
    const executed = spawnSync(binary, [], { encoding: "utf8", timeout: 20_000 });
    assert.equal(executed.status, 0, executed.error?.message ?? executed.stderr);
    assert.match(executed.stdout, /Production read request: 8 old-consumer compatibility cases/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("linked production native reply buffer discards failed and revoked snapshots", () => {
  const scratch = mkdtempSync(join(process.env.ARDIA_NATIVE_POLICY_SCRATCH ?? tmpdir(), "ardia-password-buffer-"));
  try {
    const native = join(root, "packages/ardiacore/ios");
    const sources = [join(directory, "PasswordSyncNativeBufferTests.mm"), join(native, "ArdiaCorePasswordSyncPrivate.mm")];
    const objects = sources.map((_, index) => join(scratch, `native-buffer-${index}.o`));
    for (const [index, file] of sources.entries()) {
      const compiled = spawnSync(process.env.CXX ?? "clang++", [
        "-std=c++20", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-I", native, "-c", file, "-o", objects[index],
      ], { encoding: "utf8", timeout: 120_000 });
      assert.equal(compiled.status, 0, compiled.error?.message ?? compiled.stderr);
    }
    const binary = join(scratch, "native-buffer-test");
    const linked = spawnSync(process.env.CXX ?? "clang++", [
      "-fsanitize=address,undefined", "-framework", "Foundation", "-Wl,-export_dynamic", ...objects, "-o", binary,
    ], { encoding: "utf8", timeout: 120_000 });
    assert.equal(linked.status, 0, linked.error?.message ?? linked.stderr);
    const symbols = spawnSync("nm", ["-gU", binary], { encoding: "utf8", timeout: 20_000 });
    assert.equal(symbols.status, 0, symbols.error?.message ?? symbols.stderr);
    assert.doesNotMatch(symbols.stdout, /ardiacore_password_sync/);
    const executed = spawnSync(binary, [], { encoding: "utf8", timeout: 20_000 });
    assert.equal(executed.status, 0, executed.error?.message ?? executed.stderr);
    assert.match(executed.stdout, /Production native reply buffer/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

for (const sanitizer of ["address,undefined", "thread"]) {
  test(`production revocable lease concurrency (${sanitizer})`, () => {
    const scratch = mkdtempSync(join(process.env.ARDIA_NATIVE_POLICY_SCRATCH ?? tmpdir(), "ardia-password-lease-"));
    try {
      const binary = join(scratch, "native-lease-test");
      const compiled = spawnSync(process.env.CXX ?? "clang++", [
        "-std=c++20", "-Wall", "-Wextra", "-Werror", "-pthread", `-fsanitize=${sanitizer}`,
        "-I", join(root, "packages/ardiacore/ios"), join(directory, "PasswordSyncNativeLeaseTests.cc"), "-o", binary,
      ], { encoding: "utf8", timeout: 120_000 });
      assert.equal(compiled.status, 0, compiled.error?.message ?? compiled.stderr);
      const executed = spawnSync(binary, [], { encoding: "utf8", timeout: 30_000 });
      assert.equal(executed.status, 0, executed.error?.message ?? executed.stderr);
      assert.match(executed.stdout, /Production lease: 14 concurrency\/deadline\/lifetime cases and 400 commit\/revoke\/registration races passed/);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
}

for (const legacyOnly of [false, true]) {
  test(`production native bridge ${legacyOnly ? "refuses legacy-only mutation engine" : "uses versioned lease mutation"}`, () => {
    const scratch = mkdtempSync(join(process.env.ARDIA_NATIVE_POLICY_SCRATCH ?? tmpdir(), "ardia-password-native-bridge-"));
    try {
      const native = join(root, "packages/ardiacore/ios");
      const binary = join(scratch, "native-bridge-test");
      const compiled = spawnSync(process.env.CXX ?? "clang++", [
        "-std=c++20", "-fobjc-arc", "-fblocks", "-fsanitize=address,undefined",
        "-Wno-incomplete-implementation", "-Wno-objc-property-implementation",
        ...(legacyOnly ? ["-DARDIA_TEST_OLD_TYPED_ENGINE=1"] : []),
        "-I", join(root, "engine/ardiacore/src/ardia/core/public"), "-I", native,
        join(native, "ArdiaCoreEngineBridge.mm"), join(native, "ArdiaCorePasswordSyncPrivate.mm"),
        join(directory, "PasswordSyncNativeBridgeTests.mm"),
        "-framework", "Foundation", "-framework", "AppKit", "-Wl,-export_dynamic", "-o", binary,
      ], { encoding: "utf8", timeout: 120_000 });
      assert.equal(compiled.status, 0, compiled.error?.message ?? compiled.stderr);
      const executed = spawnSync(binary, [], { encoding: "utf8", timeout: 20_000 });
      assert.equal(executed.status, 0, executed.error?.message ?? executed.stderr);
      assert.match(executed.stdout, legacyOnly ? /old five-argument engine denied without calling legacy symbol/ : /19 native and 12 generic-denial completions/);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
}

for (const sanitizer of ["address", "thread"]) {
  test(`production Swift key mutation and native registry share a synchronous revocation barrier (${sanitizer})`, () => {
    const scratch = mkdtempSync(join(process.env.ARDIA_NATIVE_POLICY_SCRATCH ?? tmpdir(), "ardia-password-key-state-"));
    try {
      const native = join(root, "packages/ardiacore/ios");
      const module = readFileSync(join(root, "packages/sync/ios/SyncModule.swift"), "utf8");
      const start = module.indexOf("private final class KeyState {");
      assert.ok(start >= 0);
      const swift = join(scratch, "KeyStateTests.swift");
      writeFileSync(swift, readFileSync(join(directory, "PasswordSyncKeyStateTests.swift"), "utf8") + "\n" + module.slice(start));
      const objects = ["ArdiaCorePasswordSyncPrivate.mm", "PasswordSyncKeyStateTestSupport.mm"].map((name, index) => {
        const object = join(scratch, `key-state-${index}.o`);
        const compiled = spawnSync(process.env.CXX ?? "clang++", [
          "-std=c++20", "-fobjc-arc", "-fblocks", `-fsanitize=${sanitizer}`, "-I", native,
          "-c", join(index ? directory : native, name), "-o", object,
        ], { encoding: "utf8", timeout: 120_000 });
        assert.equal(compiled.status, 0, compiled.error?.message ?? compiled.stderr);
        return object;
      });
      const binary = join(scratch, "key-state-test");
      const compiled = spawnSync("swiftc", [
        "-parse-as-library", `-sanitize=${sanitizer}`, "-import-objc-header", join(directory, "PasswordSyncKeyStateTestSupport.h"),
        "-Xcc", "-I" + native, swift, ...objects, "-lc++", "-o", binary,
      ], { encoding: "utf8", timeout: 120_000 });
      assert.equal(compiled.status, 0, compiled.error?.message ?? compiled.stderr);
      const executed = spawnSync(binary, [], { encoding: "utf8", timeout: 20_000 });
      assert.equal(executed.status, 0, executed.error?.message ?? executed.stderr);
      assert.match(executed.stdout, /Production Swift KeyState \+ native registry/);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
}

test("production grant expiry starts at native authentication rather than delayed main delivery", () => {
  const scratch = mkdtempSync(join(process.env.ARDIA_NATIVE_POLICY_SCRATCH ?? tmpdir(), "ardia-password-grant-expiry-"));
  try {
    const binary = join(scratch, "grant-expiry-test");
    const compiled = spawnSync("swiftc", [
      "-sanitize=address", join(root, "packages/sync/ios/Core/DeviceOwnerAuthorization.swift"),
      join(directory, "PasswordSyncGrantExpiryTests.swift"), "-o", binary,
    ], { encoding: "utf8", timeout: 120_000 });
    assert.equal(compiled.status, 0, compiled.error?.message ?? compiled.stderr);
    const executed = spawnSync(binary, [], { encoding: "utf8", timeout: 20_000, env: { ...process.env, ARDIA_BACKGROUND: "1" } });
    assert.equal(executed.status, 0, executed.error?.message ?? executed.stderr);
    assert.match(executed.stdout, /Production grant expiry: original native callback uptime retained/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
