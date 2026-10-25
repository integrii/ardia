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

test("production snapshot policy and native unsupported mutation boundary", () => {
  const scratch = mkdtempSync(join(process.env.ARDIA_NATIVE_POLICY_SCRATCH ?? tmpdir(), "ardia-password-policy-"));
  try {
    const start = source.indexOf('extern "C" AC_ENGINE_EXPORT void ac_passwords_sync_compare_and_set(');
    assert.ok(start >= 0);
    const end = source.indexOf("\n}", start);
    assert.ok(end > start);
    writeFileSync(join(scratch, "password_sync_mutation_endpoint.inc"), source.slice(start, end + 2));
    const binary = join(scratch, "native-policy-test");
    const compiled = spawnSync(process.env.CXX ?? "clang++", [
      "-std=c++20", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
      "-I", join(root, "engine/chromium/src"), "-I", scratch,
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

test("production native reply buffer discards failed and revoked snapshots", () => {
  const scratch = mkdtempSync(join(process.env.ARDIA_NATIVE_POLICY_SCRATCH ?? tmpdir(), "ardia-password-buffer-"));
  try {
    const bridge = readFileSync(join(root, "packages/ardiacore/ios/ArdiaCoreEngineBridge.mm"), "utf8");
    const start = bridge.indexOf("void WipeSecret(");
    const end = bridge.indexOf("void StartPasswordSync(", start);
    assert.ok(start >= 0 && end > start);
    writeFileSync(join(scratch, "password_sync_reply_buffer.inc"), bridge.slice(start, end));
    const binary = join(scratch, "native-buffer-test");
    const compiled = spawnSync(process.env.CXX ?? "clang++", [
      "-std=c++20", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra", "-Werror",
      "-fsanitize=address,undefined", "-framework", "Foundation",
      "-I", join(root, "engine/chromium/src"), "-I", scratch,
      join(directory, "PasswordSyncNativeBufferTests.mm"), "-o", binary,
    ], { encoding: "utf8", timeout: 120_000 });
    assert.equal(compiled.status, 0, compiled.error?.message ?? compiled.stderr);
    const executed = spawnSync(binary, [], { encoding: "utf8", timeout: 20_000 });
    assert.equal(executed.status, 0, executed.error?.message ?? executed.stderr);
    assert.match(executed.stdout, /Production native reply buffer/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
