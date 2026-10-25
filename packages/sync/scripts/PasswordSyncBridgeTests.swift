import Foundation

private struct ExactLoginStore {
  private var rows: [Data: PasswordSyncLogin] = [:]
  var values: [PasswordSyncLogin] { Array(rows.values) }
  subscript(key: String) -> PasswordSyncLogin? {
    get { rows[Data(key.utf8)] }
    set { rows[Data(key.utf8)] = newValue }
  }
}

@MainActor
private final class FixtureStore: PasswordSyncStore, PasswordSyncStoreLifecycle {
  var values = ExactLoginStore()
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
  var cancellations = 0
  var requestDeadlines: [TimeInterval] = []

  func beginAuthorization(profiles: [String], expiresAt: TimeInterval, generation: UInt64) -> Bool { true }
  func revokeAuthorization() { cancelPendingRequests() }
  func cancelPendingRequests() { cancellations += 1 }

  func read(profile: String, expiresAt: TimeInterval, authorized: @escaping () -> Bool, completion: @escaping ([PasswordSyncLogin]?) -> Void) {
    requestDeadlines.append(expiresAt)
    reads += 1
    beforeRead?()
    completion(authorized() && !unavailable ? Array(values.values) + extraRows : nil)
  }

  func compareAndSet(profile: String, key: String, expected: PasswordSyncLogin?, desired: PasswordSyncLogin?,
                     expiresAt: TimeInterval, authorized: @escaping () -> Bool, completion: @escaping (Bool?) -> Void) {
    requestDeadlines.append(expiresAt)
    let write = {
      self.beforeWrite?()
      let current = self.values[key]
      let matches = current == nil ? expected == nil : expected.map { current!.password.utf8.elementsEqual($0.password.utf8) } == true
      guard authorized(), !self.failWrite, matches else { completion(false); return }
      self.writes += 1
      if !self.failSettle {
        self.values[key] = desired.map { login in
          PasswordSyncLogin(origin: login.origin, username: login.username, password: login.password,
                            created: current == nil ? login.created : current?.created)
        }
      }
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
    store.requestDeadlines = []
    let retried = await sync.apply(binding, changes: changes)
    precondition(retried && store.values[key]?.password == desired.password)
    precondition(store.values[key]?.created == old.created, "password update must preserve the native creation date")
    precondition(store.requestDeadlines.count >= 3 && Set(store.requestDeadlines).count == 1, "read, CAS, and settle share the original absolute operation deadline")
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
    let cancellationsBeforeTimeout = store.cancellations
    let timedOut = await sync.apply(binding, changes: changes)
    precondition(!timedOut && store.values[key] == old)
    precondition(store.cancellations > cancellationsBeforeTimeout, "timeout cancels native requests before the caller resumes")
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
    store.extraRows = []
    let writesBeforeIdentities = store.writes
    let identitiesApplied = await sync.apply(binding, changes: identityChanges)
    precondition(identitiesApplied && store.writes == writesBeforeIdentities + 2, "both exact Unicode identities must be inserted")
    precondition(store.values[composedUser.key!]?.password == composedUser.password, "NFC identity must retain its own password")
    precondition(store.values[decomposedUser.key!]?.password == decomposedUser.password, "NFD identity must retain its own password")
    store.values[composedUser.key!] = nil
    store.values[decomposedUser.key!] = nil

    let epochLogin = PasswordSyncLogin(origin: old.origin, username: "epoch-user", password: "epoch-secret", created: 0)
    let undatedLogin = PasswordSyncLogin(origin: old.origin, username: "undated-user", password: "undated-secret", created: nil)
    store.extraRows = [epochLogin, undatedLogin]
    let datedRows = await sync.read(binding)
    precondition(datedRows?.first(where: { $0["key"] as? String == epochLogin.key })?["created"] as? Double == 0)
    precondition(datedRows?.first(where: { $0["key"] as? String == undatedLogin.key })?["created"] is NSNull)
    precondition(datedRows?.first(where: { $0["key"] as? String == old.key })?["created"] as? Double == 1)
    store.extraRows = []

    for created: Double? in [nil, 0, 1_234_567_890_123.5] {
      let source = PasswordSyncLogin(origin: old.origin, username: "source-date", password: "dated-secret", created: created)
      let sourceKey = source.key!
      store.values[sourceKey] = source
      let sourceRows = await sync.read(binding)
      let sourceRow = sourceRows!.first { $0["key"] as? String == sourceKey }!
      let value = sourceRow["value"] as! [String: Any]
      let authenticated = try codec.open(PasswordSyncEnvelope(value)!, key: sourceKey, binding: binding)
      precondition(authenticated.created == created, "native read seals the original source date")
      store.values[sourceKey] = nil
      let inserted = await sync.apply(binding, changes: [["key": sourceKey, "desired": value, "base": NSNull()]])
      precondition(inserted && store.values[sourceKey]?.created == created, "incoming authenticated source date reaches fixture insertion")
      let dateOnly = PasswordSyncLogin(origin: source.origin, username: source.username, password: source.password, created: 999)
      let writesBeforeDateOnly = store.writes
      let dateOnlyValue = try codec.seal(dateOnly, key: sourceKey, binding: binding).json
      let unchanged = await sync.apply(binding, changes: [["key": sourceKey, "desired": dateOnlyValue, "base": value]])
      precondition(unchanged && store.writes == writesBeforeDateOnly && store.values[sourceKey]?.created == created, "date-only metadata differences neither rewrite existing dates nor conflict")
      let update = PasswordSyncLogin(origin: source.origin, username: source.username, password: "updated-dated-secret", created: 123)
      let updateValue = try codec.seal(update, key: sourceKey, binding: binding).json
      let updated = await sync.apply(binding, changes: [["key": sourceKey, "desired": updateValue, "base": dateOnlyValue]])
      precondition(updated && store.values[sourceKey]?.created == created, "existing fixture creation date wins over incoming update metadata")
      store.values[sourceKey] = nil
    }
    store.values[key] = old
    store.beforeWrite = { store.values[key] = PasswordSyncLogin(origin: old.origin, username: old.username, password: old.password, created: 765) }
    let dateRace = await sync.apply(binding, changes: changes)
    precondition(dateRace && store.values[key]?.password == desired.password && store.values[key]?.created == 765, "date-only concurrent changes do not block password CAS")
    store.beforeWrite = nil
    store.values[key] = old
    let forgedDate = await sync.apply(binding, changes: [["key": key, "desired": wanted, "base": base, "created": 5]])
    precondition(!forgedDate && store.values[key] == old, "JS date outside sealed credentials is rejected")

    let deleted = await sync.apply(binding, changes: [["key": key, "desired": NSNull(), "base": base]])
    precondition(deleted && store.values[key] == nil)
    let localDeletion = await sync.apply(binding, changes: changes)
    precondition(!localDeletion && store.values[key] == nil)
    print("PasswordSync bridge with hypothetical conditional-mutation store, not Chromium: authorization, opaque output, creation dates, distinct Unicode insertions, conflicts, failure, settle/retry, revocation, unavailable stores, scope, tampering, timeout, and deletion checks passed")
  }
}
