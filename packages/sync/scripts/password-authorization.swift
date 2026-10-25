import AppKit
import Foundation

final class AuthorizationFixtureAuthentication: DeviceOwnerAuthenticating {
  var calls = 0
  var answer: Bool? = true
  var pending: ((Bool) -> Void)?
  var onEvaluate: (() -> Void)?
  func evaluate(reason: String, completion: @escaping (Bool) -> Void) {
    calls += 1
    onEvaluate?()
    if let answer { completion(answer) }
    else { pending = completion }
  }
  func cancel() {}
}

@MainActor
final class AuthorizationFixtureStore: PasswordSyncStore {
  var reads = 0
  var writes = 0
  var onRead: (() -> Void)?
  func read(profile: String, authorized: @escaping () -> Bool, completion: @escaping ([PasswordSyncLogin]?) -> Void) {
    let allowed = authorized()
    reads += 1
    onRead?()
    completion(allowed ? [] : nil)
  }
  func compareAndSet(profile: String, key: String, expected: PasswordSyncLogin?, desired: PasswordSyncLogin?,
                     authorized: @escaping () -> Bool, completion: @escaping (Bool?) -> Void) {
    writes += 1
    completion(authorized())
  }
}

@main
struct PasswordAuthorizationChecks {
  @MainActor
  static func main() async throws {
    var checks = 0
    var failures = 0
    func check(_ value: @autoclosure () -> Bool, _ message: String) {
      checks += 1
      if !value() { failures += 1; print("FAIL: \(message)") }
    }
    let authentication = AuthorizationFixtureAuthentication()
    var now: TimeInterval = 10
    let authorization = DeviceOwnerAuthorization(authentication: authentication, lifetime: 60, now: { now }, observeSystem: false)
    var reasons: [DeviceOwnerAuthorization.Revocation] = []
    var secretAlive = false
    authorization.onInvalidate = { reason in
      reasons.append(reason)
      if reason == .system || reason == .keyChanged { secretAlive = false }
    }
    func grant(_ binding: String = "fixture") -> DeviceOwnerAuthorization.Grant? {
      var issued: DeviceOwnerAuthorization.Grant?
      authorization.authorize(binding: binding, reason: "fixture", currentBinding: { binding }) { issued = $0 }
      return issued
    }
    authorization.revoke()
    authorization.revoke()
    check(reasons.isEmpty, "empty initial sessions do not emit invalidation events")
    let first = grant()!
    check(authorization.validate(first, binding: "fixture"), "fresh authorization is valid")
    secretAlive = true
    authorization.revoke()
    check(reasons == [.session], "an active grant emits exactly one session invalidation")
    check(secretAlive, "session dismissal preserves the independently expiring recovery clipboard")
    authorization.revoke()
    authorization.revoke(.expired)
    check(reasons == [.session], "repeated empty session and stale expiry do not emit events")
    authorization.revoke(.system)
    check(reasons.last == .system && !secretAlive, "system invalidation still cleans secrets after session revocation")
    secretAlive = true
    authorization.revoke(.keyChanged)
    check(reasons.last == .keyChanged && !secretAlive, "key changes still clean secrets without a remaining grant")
    reasons.removeAll()
    let expiring = grant()!
    now = 69.999
    check(authorization.validate(expiring, binding: "fixture"), "grant remains valid before its exact deadline")
    now = 70
    check(!authorization.validate(expiring, binding: "fixture"), "validation rejects a grant at its deadline")
    check(reasons == [.expired], "validation reports expiry rather than session dismissal")
    check(!authorization.validate(expiring, binding: "fixture") && reasons == [.expired], "an expired candidate does not emit twice")
    let replaced = grant()!
    check(!authorization.validate(replaced, binding: "new-key"), "a changed key binding revokes access")
    check(reasons.last == .keyChanged, "binding changes report their own cleanup reason")
    reasons.removeAll()
    authentication.answer = nil
    var lateGrant: DeviceOwnerAuthorization.Grant?
    authorization.authorize(binding: "fixture", reason: "fixture", currentBinding: { "fixture" }) { lateGrant = $0 }
    authorization.revoke()
    authentication.pending?(true)
    check(lateGrant == nil && reasons == [.session], "pending authentication emits one invalidation and cannot return a late grant")
    authorization.revoke()
    check(reasons == [.session], "a cancelled pending request does not keep an active session")

    let base = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: base) }
    let keys = SyncKeys(entropy: Data(repeating: 19, count: 32))
    let scope = "p:" + String(repeating: "a", count: 26)
    let profiles = [["scope": scope, "engineProfile": ""]]
    for entry in ["status", "read", "apply"] {
      let folder = base.appendingPathComponent(entry, isDirectory: true)
      let vault = SyncVault(folder: folder, keys: keys)
      try vault.createChain()
      let auth = AuthorizationFixtureAuthentication()
      let store = AuthorizationFixtureStore()
      var invalidations = 0
      let coordinator = PasswordSyncCoordinator(store: store, authentication: auth,
        snapshot: { PasswordSyncKeySnapshot(keys: keys, generation: 1) }, foreground: { true }, observeSystem: false,
        onInvalidate: { invalidations += 1 })
      let allowed = await coordinator.authorize(folder: folder.path, profiles: profiles)
      check(allowed && auth.calls == 1 && invalidations == 0, "\(entry): first consent does not invalidate an empty session")
      check(coordinator.status(folder: folder.path, scope: scope, profile: ""), "\(entry): consent authorizes an existing chain")
      try FileManager.default.removeItem(at: vault.chainURL)
      switch entry {
      case "status": check(!coordinator.status(folder: folder.path, scope: scope, profile: ""), "status revokes a deleted approved chain")
      case "read":
        let rows = await coordinator.read(folder: folder.path, scope: scope, profile: "")
        check(rows == nil, "read revokes a deleted approved chain")
      default:
        let applied = await coordinator.apply(folder: folder.path, scope: scope, profile: "", changes: [])
        check(!applied, "apply revokes a deleted approved chain")
      }
      check(invalidations == 1, "\(entry): deletion emits exactly one real invalidation")
      check(store.reads == 0 && store.writes == 0, "\(entry): deletion is detected before native credential-store access")
      try vault.createChain()
      check(!coordinator.status(folder: folder.path, scope: scope, profile: ""), "\(entry): recreating a chain does not resurrect its grant")
      let readAfterRecreate = await coordinator.read(folder: folder.path, scope: scope, profile: "")
      let applyAfterRecreate = await coordinator.apply(folder: folder.path, scope: scope, profile: "", changes: [])
      check(readAfterRecreate == nil && !applyAfterRecreate && store.reads == 0, "\(entry): recreated chains remain denied before native reads")
      let reapproved = await coordinator.authorize(folder: folder.path, profiles: profiles)
      check(reapproved && auth.calls == 2, "\(entry): recreated chains require new device-owner authentication")
    }
    let changingFolder = base.appendingPathComponent("changing", isDirectory: true)
    let changingVault = SyncVault(folder: changingFolder, keys: keys)
    try changingVault.createChain()
    let changingAuth = AuthorizationFixtureAuthentication()
    let changingStore = AuthorizationFixtureStore()
    let changing = PasswordSyncCoordinator(store: changingStore, authentication: changingAuth,
      snapshot: { PasswordSyncKeySnapshot(keys: keys, generation: 1) }, foreground: { true }, observeSystem: false, onInvalidate: {})
    changingAuth.onEvaluate = { try! FileManager.default.removeItem(at: changingVault.chainURL) }
    let vanishedDuringAuth = await changing.authorize(folder: changingFolder.path, profiles: profiles)
    check(!vanishedDuringAuth, "chain deletion during authentication cannot issue a grant")
    try changingVault.createChain()
    changingAuth.onEvaluate = nil
    let changingApproved = await changing.authorize(folder: changingFolder.path, profiles: profiles)
    check(changingApproved && changingAuth.calls == 2, "a chain recreated after pending deletion requires another prompt")
    changingStore.onRead = { try! FileManager.default.removeItem(at: changingVault.chainURL) }
    let vanishedDuringRead = await changing.read(folder: changingFolder.path, scope: scope, profile: "")
    check(vanishedDuringRead == nil && changingStore.reads == 1, "chain existence is revalidated after a native callback in the same operation")
    try changingVault.createChain()
    check(!changing.status(folder: changingFolder.path, scope: scope, profile: ""), "a callback-detected deletion cannot regain authorization on recreation")

    let original = base.appendingPathComponent("original", isDirectory: true)
    let parked = base.appendingPathComponent("parked", isDirectory: true)
    let replacement = base.appendingPathComponent("replacement", isDirectory: true)
    try SyncVault(folder: original, keys: keys).createChain()
    try SyncVault(folder: replacement, keys: keys).createChain()
    let targetAuth = AuthorizationFixtureAuthentication()
    let targetStore = AuthorizationFixtureStore()
    var targetInvalidations = 0
    let target = PasswordSyncCoordinator(store: targetStore, authentication: targetAuth,
      snapshot: { PasswordSyncKeySnapshot(keys: keys, generation: 1) }, foreground: { true }, observeSystem: false,
      onInvalidate: { targetInvalidations += 1 })
    let targetApproved = await target.authorize(folder: original.path, profiles: profiles)
    check(targetApproved, "a canonical folder can be approved")
    try FileManager.default.moveItem(at: original, to: parked)
    try FileManager.default.createSymbolicLink(at: original, withDestinationURL: replacement)
    check(SyncVault(folder: original, keys: keys).chainExists(), "retargeted folder still contains the same chain tag")
    check(!target.status(folder: original.path, scope: scope, profile: "") && targetInvalidations == 1,
          "a symlink target change revokes even with an unchanged key generation and existing chain")
    check(targetStore.reads == 0 && targetStore.writes == 0, "retargeting is denied before native credentials are accessed")
    try FileManager.default.removeItem(at: original)
    try FileManager.default.moveItem(at: parked, to: original)
    check(!target.status(folder: original.path, scope: scope, profile: ""), "restoring the original folder target cannot resurrect a revoked grant")
    print("\(failures == 0 ? "PASS" : "FAIL"): \(checks) password authorization checks, \(failures) failures")
    if failures > 0 { exit(1) }
  }
}
