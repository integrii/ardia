import Foundation

@MainActor
private final class FixtureStore: PasswordSyncStore {
  var values: [String: PasswordSyncLogin] = [:]
  var reads = 0
  var writes = 0
  var unavailable = false
  var failWrite = false
  var failSettle = false
  var beforeRead: (() -> Void)?
  var beforeWrite: (() -> Void)?
  var delayedWrite: (() -> Void)?
  var delayWrite = false
  var extraRows: [PasswordSyncLogin] = []

  func read(profile: String, authorized: @escaping () -> Bool, completion: @escaping ([PasswordSyncLogin]?) -> Void) {
    reads += 1
    beforeRead?()
    completion(authorized() && !unavailable ? Array(values.values) + extraRows : nil)
  }

  func compareAndSet(profile: String, key: String, expected: PasswordSyncLogin?, desired: PasswordSyncLogin?,
                     authorized: @escaping () -> Bool, completion: @escaping (Bool?) -> Void) {
    let write = {
      self.beforeWrite?()
      guard authorized(), !self.failWrite, self.values[key] == expected else { completion(false); return }
      self.writes += 1
      if !self.failSettle { self.values[key] = desired }
      completion(true)
    }
    if delayWrite { delayedWrite = write }
    else { write() }
  }
}

@main
private struct PasswordSyncBridgeTests {
  @MainActor
  static func main() async throws {
    let keys = SyncKeys(entropy: Data(repeating: 7, count: 32))
    let binding = PasswordSyncBinding(chain: keys.chainTag, folder: "/fixture", scope: "p", profile: "")
    let codec = PasswordSyncRecords(keys: keys)
    let store = FixtureStore()
    var granted = false
    var generation = 0
    let sync = PasswordSync(store: store, timeout: 0.1, settleChecks: 2, settleNanoseconds: 0) { requested in
      let captured = generation
      return PasswordSyncAccess(binding: binding, codec: codec, authorized: { granted && captured == generation && requested == binding })
    }
    let old = PasswordSyncLogin(origin: "https://bank.example", username: "alice", password: "old-secret", created: 1)
    let desired = PasswordSyncLogin(origin: old.origin, username: old.username, password: "new-secret", created: nil)
    let edited = PasswordSyncLogin(origin: old.origin, username: old.username, password: "local-secret", created: 1)
    let key = old.key!
    store.values[key] = old
    let base = try codec.seal(old, key: key, binding: binding).json
    let wanted = try codec.seal(desired, key: key, binding: binding).json
    let changes: [[String: Any]] = [["key": key, "desired": wanted, "base": base]]

    let deniedRead = await sync.read(binding)
    let deniedApply = await sync.apply(binding, changes: changes)
    precondition(deniedRead == nil && !deniedApply && store.reads == 0 && store.writes == 0)

    granted = true
    let rows = await sync.read(binding)
    let json = String(decoding: try JSONSerialization.data(withJSONObject: rows!), as: UTF8.self)
    precondition(!json.contains(old.password) && !json.contains("\"password\""))
    precondition((rows?.first?["value"] as? [String: Any])?["fingerprint"] as? String == base["fingerprint"] as? String)

    store.values[key] = edited
    let conflict = await sync.apply(binding, changes: changes)
    precondition(!conflict && store.values[key] == edited && store.writes == 0)
    store.values[key] = old
    store.beforeWrite = { store.values[key] = edited }
    let concurrent = await sync.apply(binding, changes: changes)
    precondition(!concurrent && store.values[key] == edited && store.writes == 0)
    store.beforeWrite = nil

    store.values[key] = old
    store.failWrite = true
    let failed = await sync.apply(binding, changes: changes)
    precondition(!failed && store.values[key] == old && store.writes == 0)
    store.failWrite = false
    store.failSettle = true
    let unsettled = await sync.apply(binding, changes: changes)
    precondition(!unsettled && store.values[key] == old)
    store.failSettle = false
    let retried = await sync.apply(binding, changes: changes)
    precondition(retried && store.values[key] == desired)
    let writes = store.writes
    let idempotent = await sync.apply(binding, changes: changes)
    precondition(idempotent && store.writes == writes)

    store.values[key] = old
    store.beforeWrite = { generation += 1 }
    let revokedMutation = await sync.apply(binding, changes: changes)
    precondition(!revokedMutation && store.values[key] == old)
    store.beforeWrite = nil
    store.beforeRead = { generation += 1 }
    let revokedRead = await sync.read(binding)
    precondition(revokedRead == nil)
    store.beforeRead = nil

    store.unavailable = true
    let missing = await sync.read(binding)
    let missingApply = await sync.apply(binding, changes: changes)
    precondition(missing == nil && !missingApply && store.values[key] == old)
    store.unavailable = false
    let wrongScope = PasswordSyncBinding(chain: binding.chain, folder: binding.folder, scope: "other", profile: binding.profile)
    let wrongScopeRead = await sync.read(wrongScope)
    precondition(wrongScopeRead == nil)
    var tampered = wanted
    tampered["fingerprint"] = "forged"
    let badFingerprint = await sync.apply(binding, changes: [["key": key, "desired": tampered, "base": base]])
    let plaintext = await sync.apply(binding, changes: [["key": key, "desired": ["o": old.origin, "u": old.username, "p": desired.password], "base": base]])
    let invalidKey = await sync.apply(binding, changes: [["key": "pw:invalid", "desired": NSNull(), "base": NSNull()]])
    precondition(!badFingerprint && !plaintext && !invalidKey && store.values[key] == old)

    store.delayWrite = true
    let timedOut = await sync.apply(binding, changes: changes)
    precondition(!timedOut && store.values[key] == old)
    store.delayedWrite?()
    precondition(store.values[key] == old)
    store.delayWrite = false
    store.delayedWrite = nil

    let composed = PasswordSyncLogin(origin: old.origin, username: old.username, password: "\u{e9}", created: 0)
    let decomposed = PasswordSyncLogin(origin: old.origin, username: old.username, password: "e\u{301}", created: 0)
    store.values[key] = composed
    let composedValue = try codec.seal(composed, key: key, binding: binding).json
    let decomposedValue = try codec.seal(decomposed, key: key, binding: binding).json
    let unicodeEdit = await sync.apply(binding, changes: [["key": key, "desired": decomposedValue, "base": composedValue]])
    precondition(unicodeEdit && store.values[key]?.password.utf8.elementsEqual(decomposed.password.utf8) == true)
    store.values[key] = old

    let composedUser = PasswordSyncLogin(origin: old.origin, username: "\u{e9}", password: "first-user-secret", created: 0)
    let decomposedUser = PasswordSyncLogin(origin: old.origin, username: "e\u{301}", password: "second-user-secret", created: 0)
    store.extraRows = [composedUser, decomposedUser]
    let distinctUsers = await sync.read(binding)
    precondition(distinctUsers?.count == 3)
    let identityChanges = try store.extraRows.map { login in
      ["key": login.key!, "desired": try codec.seal(login, key: login.key!, binding: binding).json, "base": NSNull()] as [String: Any]
    }
    let identitiesApplied = await sync.apply(binding, changes: identityChanges)
    precondition(identitiesApplied)
    store.extraRows = []

    let epochLogin = PasswordSyncLogin(origin: old.origin, username: "epoch-user", password: "epoch-secret", created: 0)
    let undatedLogin = PasswordSyncLogin(origin: old.origin, username: "undated-user", password: "undated-secret", created: nil)
    store.extraRows = [epochLogin, undatedLogin]
    let datedRows = await sync.read(binding)
    precondition(datedRows?.first(where: { $0["key"] as? String == epochLogin.key })?["created"] as? Double == 0)
    precondition(datedRows?.first(where: { $0["key"] as? String == undatedLogin.key })?["created"] is NSNull)
    precondition(datedRows?.first(where: { $0["key"] as? String == old.key })?["created"] as? Double == 1)
    store.extraRows = []

    let deleted = await sync.apply(binding, changes: [["key": key, "desired": NSNull(), "base": base]])
    precondition(deleted && store.values[key] == nil)
    let localDeletion = await sync.apply(binding, changes: changes)
    precondition(!localDeletion && store.values[key] == nil)
    print("PasswordSync bridge: authorization, opaque output, conflicts, failure, settle/retry, revocation, unavailable stores, scope, tampering, timeout, and deletion checks passed")
  }
}
