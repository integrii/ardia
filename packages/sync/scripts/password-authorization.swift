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
final class AuthorizationFixtureStore: PasswordSyncStore, PasswordSyncStoreLifecycle {
  var reads = 0
  var writes = 0
  var nativeGrants: [(profiles: [String], expiresAt: TimeInterval, generation: UInt64)] = []
  var allowNativeGrant = true
  var revocations = 0
  var cancellations = 0
  var onRead: (() -> Void)?
  func beginAuthorization(profiles: [String], expiresAt: TimeInterval, generation: UInt64) -> Bool {
    nativeGrants.append((profiles, expiresAt, generation))
    return allowNativeGrant
  }
  func revokeAuthorization() { revocations += 1; cancelPendingRequests() }
  func cancelPendingRequests() { cancellations += 1 }
  func read(profile: String, expiresAt: TimeInterval, authorized: @escaping () -> Bool, completion: @escaping ([PasswordSyncLogin]?) -> Void) {
    let allowed = authorized()
    reads += 1
    onRead?()
    completion(allowed ? [] : nil)
  }
  func compareAndSet(profile: String, key: String, expected: PasswordSyncLogin?, desired: PasswordSyncLogin?,
                     expiresAt: TimeInterval, authorized: @escaping () -> Bool, completion: @escaping (Bool?) -> Void) {
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

    let leaseFolder = base.appendingPathComponent("lease", isDirectory: true)
    try SyncVault(folder: leaseFolder, keys: keys).createChain()
    let leaseAuth = AuthorizationFixtureAuthentication()
    let leaseStore = AuthorizationFixtureStore()
    var leaseNow: TimeInterval = 123
    var leaseGeneration: UInt64 = 42
    let lease = PasswordSyncCoordinator(store: leaseStore, authentication: leaseAuth,
      snapshot: { PasswordSyncKeySnapshot(keys: keys, generation: leaseGeneration) }, foreground: { true },
      now: { leaseNow }, observeSystem: false, onInvalidate: {})
    leaseAuth.onEvaluate = { check(leaseStore.nativeGrants.isEmpty, "native lease does not start before device-owner approval") }
    leaseAuth.answer = false
    let deniedLease = await lease.authorize(folder: leaseFolder.path, profiles: profiles)
    check(!deniedLease && leaseStore.nativeGrants.isEmpty, "rejected authentication cannot begin a native lease")
    leaseAuth.answer = true
    let approvedLease = await lease.authorize(folder: leaseFolder.path, profiles: profiles)
    check(approvedLease && leaseStore.nativeGrants.count == 1, "successful device-owner approval starts one native lease")
    check(leaseStore.nativeGrants.first?.profiles == [""], "native lease receives only approved engine profiles")
    check(leaseStore.nativeGrants.first?.expiresAt == 123 + 24 * 60 * 60, "native lease receives the original absolute grant expiry")
    check(leaseStore.nativeGrants.first?.generation == 42, "native lease carries the key snapshot generation")
    leaseAuth.onEvaluate = nil
    leaseNow += 30
    let reusedLease = await lease.authorize(folder: leaseFolder.path, profiles: profiles)
    check(reusedLease && leaseAuth.calls == 2 && leaseStore.nativeGrants.count == 1, "reusing consent never renews its native expiry")
    let revocationsBeforeGeneration = leaseStore.revocations
    leaseGeneration += 1
    check(!lease.status(folder: leaseFolder.path, scope: scope, profile: ""), "key generation change denies the approved binding")
    check(leaseStore.revocations == revocationsBeforeGeneration + 1, "key generation change revokes the native lease exactly once")
    leaseStore.allowNativeGrant = false
    let rejectedNativeLease = await lease.authorize(folder: leaseFolder.path, profiles: profiles)
    check(!rejectedNativeLease && leaseStore.nativeGrants.count == 2, "native lease registration rejection fails authorization closed")
    check(!lease.status(folder: leaseFolder.path, scope: scope, profile: ""), "native lease rejection leaves no approved session")
    leaseStore.allowNativeGrant = true
    let retriedLease = await lease.authorize(folder: leaseFolder.path, profiles: profiles)
    check(retriedLease && leaseAuth.calls == 4, "retry after native lease rejection requires another device-owner grant")
    check(leaseStore.nativeGrants.last?.generation == 43, "replacement lease uses the new generation")
    let revocationsBeforeExpiry = leaseStore.revocations
    leaseNow = leaseStore.nativeGrants.last!.expiresAt
    check(!lease.status(folder: leaseFolder.path, scope: scope, profile: ""), "exact grant deadline denies coordinator access")
    check(leaseStore.revocations == revocationsBeforeExpiry + 1, "grant expiry revokes the native lease exactly once")
    lease.revoke()
    lease.revoke()
    check(leaseStore.revocations == revocationsBeforeExpiry + 1, "repeated revocation of an expired session does not revoke a second native lease")
    let cancellationsBeforeDeniedRead = leaseStore.cancellations
    let readWithoutLease = await lease.read(folder: leaseFolder.path, scope: scope, profile: "")
    check(readWithoutLease == nil && leaseStore.reads == 0, "revoked authorization never reaches a native read")
    check(leaseStore.cancellations == cancellationsBeforeDeniedRead, "denied operations do not create requests requiring cancellation")

    let handoffStore = AuthorizationFixtureStore()
    var handoffSnapshots = 0
    let handoff = PasswordSyncCoordinator(store: handoffStore, authentication: AuthorizationFixtureAuthentication(),
      snapshot: {
        handoffSnapshots += 1
        return handoffSnapshots == 4 ? nil : PasswordSyncKeySnapshot(keys: keys, generation: 1)
      }, foreground: { true }, observeSystem: false, onInvalidate: {})
    let changedAtHandoff = await handoff.authorize(folder: leaseFolder.path, profiles: profiles)
    check(!changedAtHandoff && handoffStore.nativeGrants.isEmpty, "key change at grant handoff never registers a native lease")
    check(handoffStore.revocations == 1, "invalid grant handoff revokes the just-issued approval exactly once")
    print("\(failures == 0 ? "PASS" : "FAIL"): \(checks) password authorization checks, \(failures) failures")
    if failures > 0 { exit(1) }
  }
}
