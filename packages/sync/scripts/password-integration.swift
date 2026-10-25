import AppKit
import Foundation

final class FixtureAuthentication: DeviceOwnerAuthenticating {
  var calls = 0
  var answer: Bool? = true
  var pending: ((Bool) -> Void)?
  func evaluate(reason: String, completion: @escaping (Bool) -> Void) {
    calls += 1
    if let answer { completion(answer) }
    else { pending = completion }
  }
  func cancel() {}
}

@MainActor
final class FixturePasswordStore: PasswordSyncStore, PasswordSyncStoreLifecycle {
  var reads = 0
  var writes = 0
  var logins: [PasswordSyncLogin] = []
  var deferRead = false
  var pending: (([PasswordSyncLogin]?) -> Void)?
  var nativeAuthorized = false
  var authorizedProfiles: [String] = []
  var authorizationDeadlines: [TimeInterval] = []
  var authorizationGenerations: [UInt64] = []
  var revocations = 0
  var cancellations = 0
  var rejectAuthorization = false
  func beginAuthorization(profiles: [String], expiresAt: TimeInterval, generation: UInt64) -> Bool {
    authorizationDeadlines.append(expiresAt)
    authorizationGenerations.append(generation)
    authorizedProfiles = profiles
    nativeAuthorized = !rejectAuthorization
    return nativeAuthorized
  }
  func revokeAuthorization() {
    nativeAuthorized = false
    revocations += 1
    cancelPendingRequests()
  }
  func cancelPendingRequests() { cancellations += 1 }
  func read(profile: String, expiresAt: TimeInterval, authorized: @escaping () -> Bool, completion: @escaping ([PasswordSyncLogin]?) -> Void) {
    guard nativeAuthorized, authorizedProfiles.contains(profile), authorized() else { return completion(nil) }
    reads += 1
    if deferRead { pending = completion }
    else { completion(logins) }
  }
  func compareAndSet(profile: String, key: String, expected: PasswordSyncLogin?, desired: PasswordSyncLogin?,
                     expiresAt: TimeInterval, authorized: @escaping () -> Bool, completion: @escaping (Bool?) -> Void) {
    guard nativeAuthorized, authorizedProfiles.contains(profile), authorized(), logins.first(where: { $0.key?.utf8.elementsEqual(key.utf8) == true }) == expected else { return completion(false) }
    writes += 1
    logins.removeAll { $0.key?.utf8.elementsEqual(key.utf8) == true }
    if let desired {
      logins.append(PasswordSyncLogin(origin: desired.origin, username: desired.username, password: desired.password,
                                     created: expected == nil ? desired.created : expected?.created))
    }
    completion(true)
  }
}

@main
struct PasswordIntegrationChecks {
  @MainActor
  static func main() async throws {
    var checks = 0
    func check(_ value: @autoclosure () -> Bool, _ message: String) {
      precondition(value(), message)
      checks += 1
    }
    func encode(_ json: Any) throws -> Data { try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys]) }
    func text(_ json: Any) throws -> String { String(decoding: try encode(json), as: UTF8.self) }
    func denied(_ message: String, _ operation: () throws -> Void) {
      do { try operation(); preconditionFailure(message) }
      catch { checks += 1 }
    }
    let keys = SyncKeys(entropy: Data(repeating: 7, count: 32))
    let payloads = PasswordBridgePayloads(keys: keys)
    let scope = "p:" + String(repeating: "a", count: 26)
    let secondScope = "p:" + String(repeating: "b", count: 26)
    let password = "fixture-password-never-crosses-JS"
    let key = "pw:https://example.test\nfixture"
    let legacy: [String: Any] = ["o": "https://example.test", "u": "fixture", "p": password]
    let op: [String: Any] = ["k": key, "h": "1:0:device", "v": legacy]
    let log: [String: Any] = ["v": 1, "kind": "log", "device": "device", "seq": 3, "at": 123, "ops": [op]]
    let incoming = try payloads.read(scope: scope, payload: encode(log))
    check(!incoming.contains(password), "incoming log contains only opaque password values")
    let outgoing = try payloads.write(scope: scope, payload: incoming)
    let outgoingObject = try JSONSerialization.jsonObject(with: outgoing) as! [String: Any]
    check(NSDictionary(dictionary: outgoingObject).isEqual(log), "outgoing wire restores legacy format only inside native")
    denied("raw password accepted for outgoing wire") { _ = try payloads.write(scope: scope, payload: text(log)) }
    denied("opaque password accepted in another scope") { _ = try payloads.write(scope: secondScope, payload: incoming) }
    let record: [String: Any] = ["h": "1:0:device", "v": legacy, "o": ["device", 3]]
    let snapshot: [String: Any] = ["v": 1, "kind": "snapshot", "device": "device", "at": 123, "vv": ["device": 3], "seen": ["device": 2], "records": [key: record]]
    let opaqueSnapshot = try payloads.read(scope: scope, payload: encode(snapshot))
    check(!opaqueSnapshot.contains(password), "incoming snapshot contains only opaque passwords")
    let state: [String: Any] = [
      "records": [key: record], "base": [key: try text(legacy)], "outbox": [op], "journal": [log],
      "vv": ["device": 3], "seq": 3, "unapplied": [key], "files": [:], "extra": [:], "damaged": [:],
      "pendingSince": [:], "seen": ["device": 2], "joined": true, "awaitRemote": false,
      "applyAs": ["pw:": "joined"], "snapshotAt": 123, "pending": 0,
    ]
    let local = try text([scope: state])
    let legacySealed = try keys.seal(Data(local.utf8), scopeTag: "local", fileId: "state").base64EncodedString()
    let migrated = try payloads.openLocal(legacySealed)
    check(!migrated.contains(password), "legacy records, base, outbox and journal migrate before JS")
    var migratedScopes = try JSONSerialization.jsonObject(with: Data(migrated.utf8)) as! [String: Any]
    var migratedState = migratedScopes[scope] as! [String: Any]
    check(migratedState["seq"] as? Int == 3 && migratedState["snapshotAt"] as? Int == 123, "state metadata survives")
    let resealed = try payloads.sealLocal(migrated)
    let reopened = try payloads.openLocal(resealed)
    check(reopened == migrated, "opaque local state roundtrips")
    let envelope = ((migratedState["records"] as! [String: Any])[key] as! [String: Any])["v"] as! [String: Any]
    migratedState["base"] = [key: "{\"version\":2,\"sealed\":\"\(envelope["sealed"]!)\",\"fingerprint\":\"\(envelope["fingerprint"]!)\"}"]
    migratedScopes[scope] = migratedState
    _ = try payloads.sealLocal(text(migratedScopes))
    checks += 1
    denied("JS plaintext minted a password envelope") { _ = try payloads.sealLocal(local) }
    denied("arbitrary JSON accepted as local state") { _ = try payloads.sealLocal("{\"secret\":\"fixture\"}") }
    let malformed = try keys.seal(Data("not-json".utf8), scopeTag: "local", fileId: "state").base64EncodedString()
    denied("malformed authenticated state fell back") { _ = try payloads.openLocal(malformed) }
    denied("unauthenticated local state fell back") { _ = try payloads.openLocal("invalid") }
    let journal = try keys.seal(encode(["journal": [scope: [log]]]), scopeTag: "local", fileId: "state").base64EncodedString()
    let migratedJournal = try payloads.openLocal(journal)
    check(!migratedJournal.contains(password), "independent journal migrated before JS")
    _ = try payloads.sealLocal(migratedJournal)
    checks += 1

    let codec = PasswordRecords(keys: keys)
    let unicodeCredentials = [
      PasswordRecords.Credentials(origin: "https://example.test", username: "\u{00e9}", password: "unicode-fixture-first"),
      PasswordRecords.Credentials(origin: "https://example.test", username: "e\u{0301}", password: "unicode-fixture-second"),
    ]
    let unicodeScopes = ["p:\u{00e9}", "p:e\u{0301}"]
    let locations = ["records", "base", "outbox", "journal", "applyProvenance"]
    var unicodeMixed = 0
    var unicodeHealthy = 0
    func unicodeState(_ values: [(PasswordRecords.Credentials, Any)], location: String) throws -> NSDictionary {
      let indexed = NSMutableDictionary()
      var operations: [[String: Any]] = []
      for (credential, value) in values {
        let stored: Any
        switch location {
        case "records": stored = ["h": "1:0:device", "v": value, "o": ["device", 3]]
        case "base": stored = try text(value)
        default: stored = [value]
        }
        indexed.setObject(stored, forKey: credential.recordKey as NSString)
        operations.append(["k": credential.recordKey, "h": "1:0:device", "v": value])
      }
      var state: [String: Any] = ["records": NSDictionary(), "base": NSDictionary(), "outbox": NSArray()]
      switch location {
      case "outbox": state[location] = operations
      case "journal": state[location] = [["v": 1, "kind": "log", "device": "device", "seq": 3, "at": 123, "ops": operations]]
      default: state[location] = indexed
      }
      return state as NSDictionary
    }
    func verifyUnicode(_ json: Any, contexts: [(String, [PasswordRecords.Credentials])], wrapper: String, location: String) throws {
      let source = try text(json)
      denied("mixed raw Unicode password accepted in \(wrapper)/\(location)") { _ = try payloads.sealLocal(source) }
      unicodeMixed += 1
      let oldSealed = try keys.seal(Data(source.utf8), scopeTag: "local", fileId: "state").base64EncodedString()
      let migrated = try payloads.openLocal(oldSealed)
      _ = try payloads.sealLocal(migrated)
      unicodeHealthy += 1
      let root = try JSONSerialization.jsonObject(with: Data(migrated.utf8)) as! NSDictionary
      let scopes = wrapper == "direct" ? root : root.object(forKey: wrapper) as! NSDictionary
      check(scopes.count == contexts.count, "Unicode scope identities preserved")
      for (context, credentials) in contexts {
        let raw = scopes.object(forKey: context as NSString)!
        let state = wrapper == "journal" ? ["journal": raw] as NSDictionary : raw as! NSDictionary
        var entries: [(String, Any)] = []
        if location == "outbox" || location == "journal" {
          let operations: NSArray
          if location == "outbox" { operations = state.object(forKey: location) as! NSArray }
          else {
            let batch = (state.object(forKey: location) as! NSArray)[0] as! NSDictionary
            operations = batch.object(forKey: "ops") as! NSArray
          }
          for operation in operations {
            let operation = operation as! NSDictionary
            entries.append((operation.object(forKey: "k") as! String, operation.object(forKey: "v")!))
          }
        } else {
          for (key, stored) in state.object(forKey: location) as! NSDictionary {
            let value: Any
            switch location {
            case "records": value = (stored as! NSDictionary).object(forKey: "v")!
            case "base": value = try JSONSerialization.jsonObject(with: Data((stored as! String).utf8))
            default: value = (stored as! NSArray)[0]
            }
            entries.append((key as! String, value))
          }
        }
        check(entries.count == credentials.count, "Unicode password identities preserved in \(location)")
        for (recordKey, json) in entries {
          let expected = credentials.first { $0.recordKey.utf8.elementsEqual(recordKey.utf8) }!
          let value = try codec.value(from: json, scope: context, recordKey: recordKey)
          let opened = try codec.open(value, scope: context, recordKey: recordKey)
          check(opened == expected, "Unicode credential and origin context retained")
        }
      }
    }
    for rawIndex in 0..<2 {
      for reverse in [false, true] {
        let order = reverse ? [1, 0] : [0, 1]
        for location in locations {
          var values: [(PasswordRecords.Credentials, Any)] = []
          for index in order {
            let credential = unicodeCredentials[index]
            let value = index == rawIndex ? credential.legacyValue : try codec.seal(credential, scope: scope, recordKey: credential.recordKey).json
            values.append((credential, value))
          }
          let state = try unicodeState(values, location: location)
          for wrapper in ["direct", "scopes"] {
            let scopes = [scope: state] as NSDictionary
            try verifyUnicode(wrapper == "direct" ? scopes : [wrapper: scopes] as NSDictionary,
                              contexts: [(scope, unicodeCredentials)], wrapper: wrapper, location: location)
          }
          for wrapper in ["direct", "scopes", "journal"] where wrapper != "journal" || location == "journal" {
            let scopes = NSMutableDictionary()
            for index in order {
              let credential = unicodeCredentials[index]
              let context = unicodeScopes[index]
              let value = index == rawIndex ? credential.legacyValue : try codec.seal(credential, scope: context, recordKey: credential.recordKey).json
              let state = try unicodeState([(credential, value)], location: location)
              scopes.setObject(wrapper == "journal" ? state.object(forKey: "journal")! : state, forKey: context as NSString)
            }
            try verifyUnicode(wrapper == "direct" ? scopes : [wrapper: scopes] as NSDictionary,
                              contexts: [(unicodeScopes[0], [unicodeCredentials[0]]), (unicodeScopes[1], [unicodeCredentials[1]])],
                              wrapper: wrapper, location: location)
          }
        }
      }
    }
    let unicodeValue = try codec.seal(unicodeCredentials[0], scope: scope, recordKey: unicodeCredentials[0].recordKey)
    denied("NFC envelope accepted under NFD record identity") { _ = try codec.open(unicodeValue, scope: scope, recordKey: unicodeCredentials[1].recordKey) }
    denied("Unicode envelope accepted under another scope") { _ = try codec.open(unicodeValue, scope: secondScope, recordKey: unicodeCredentials[0].recordKey) }
    denied("Unicode envelope accepted under another origin") { _ = try codec.open(unicodeValue, scope: scope, recordKey: "pw:https://other.test\n\u{00e9}") }
    print("PASS: \(unicodeMixed) mixed Unicode payloads rejected; \(unicodeHealthy) migrated opaque equivalents accepted with exact identities")

    let base = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: base) }
    let folder = base.appendingPathComponent("sync", isDirectory: true)
    try SyncVault(folder: folder, keys: keys).createChain()
    var generation: UInt64 = 1
    var foreground = true
    var now: TimeInterval = 100
    var invalidations = 0
    let auth = FixtureAuthentication()
    let store = FixturePasswordStore()
    store.logins = [PasswordSyncLogin(origin: "https://example.test", username: "fixture", password: password, created: 0)]
    let coordinator = PasswordSyncCoordinator(store: store, authentication: auth,
      snapshot: { PasswordSyncKeySnapshot(keys: keys, generation: generation) }, foreground: { foreground }, now: { now },
      observeSystem: false, onInvalidate: { invalidations += 1 })
    let profiles = [["scope": scope, "engineProfile": ""], ["scope": secondScope, "engineProfile": "profile-second"]]
    let hiddenAuth = FixtureAuthentication()
    setenv("ARDIA_BACKGROUND", "1", 1)
    let defaultForeground = PasswordSyncCoordinator(store: store, authentication: hiddenAuth,
      snapshot: { PasswordSyncKeySnapshot(keys: keys, generation: generation) }, observeSystem: false, onInvalidate: {})
    let defaultHidden = await defaultForeground.authorize(folder: folder.path, profiles: profiles)
    check(!defaultHidden && hiddenAuth.calls == 0, "production foreground guard denies background before authentication")
    unsetenv("ARDIA_BACKGROUND")
    check(!coordinator.status(folder: folder.path, scope: scope, profile: ""), "startup never inherits persisted authorization")
    let lockedRead = await coordinator.read(folder: folder.path, scope: scope, profile: "")
    check(lockedRead == nil && auth.calls == 0 && store.reads == 0, "sync reads never prompt or read without approval")
    check(store.authorizationDeadlines.isEmpty && !store.nativeAuthorized, "no native lease is minted before device-owner approval")
    foreground = false
    let hidden = await coordinator.authorize(folder: folder.path, profiles: profiles)
    check(!hidden && auth.calls == 0, "only explicit foreground authorization can prompt")
    foreground = true
    let allowed = await coordinator.authorize(folder: folder.path, profiles: profiles)
    check(allowed && auth.calls == 1, "one prompt approves the exact batch")
    check(store.nativeAuthorized && store.authorizedProfiles == ["", "profile-second"], "successful device-owner grant begins exact native profile authorization")
    check(store.authorizationDeadlines == [100 + 24 * 60 * 60], "native lease receives the original immutable device-owner deadline")
    check(store.authorizationGenerations == [generation], "native lease is bound to the exact approved key generation")
    let reordered = await coordinator.authorize(folder: folder.path, profiles: Array(profiles.reversed()))
    check(reordered && auth.calls == 1, "identical sorted binding set reuses current consent")
    check(store.authorizationDeadlines.count == 1, "cached approval does not mint or extend a native lease")
    let duplicate = await coordinator.authorize(folder: folder.path, profiles: [profiles[0], profiles[0]])
    check(!duplicate && auth.calls == 1, "duplicate binding batches rejected before authentication")
    check(coordinator.status(folder: folder.path, scope: scope, profile: ""), "default profile binding authorized")
    check(coordinator.status(folder: folder.path, scope: secondScope, profile: "profile-second"), "second exact binding authorized")
    check(!coordinator.status(folder: folder.path, scope: scope, profile: "profile-second"), "mixed binding denied")
    check(!coordinator.status(folder: base.path, scope: scope, profile: ""), "other folder denied")
    let records = await coordinator.read(folder: folder.path, scope: scope, profile: "")
    check(records?.count == 1, "approved native password read succeeds")
    check(store.cancellations > 0, "completed operations cancel outstanding native request handles")
    let bridgeJSON = try text(records!)
    check(!bridgeJSON.contains(password), "password record bridge never returns plaintext")
    let plaintextApply = await coordinator.apply(folder: folder.path, scope: scope, profile: "", changes: [["key": key, "desired": legacy, "base": NSNull()]])
    check(!plaintextApply && store.writes == 0, "apply rejects plaintext values")
    now += 61
    check(coordinator.status(folder: folder.path, scope: scope, profile: ""), "password grant survives recovery's sixty second timeout")
    let value = records![0]["value"]!
    let applied = await coordinator.apply(folder: folder.path, scope: scope, profile: "", changes: [["key": key, "desired": value, "base": value]])
    check(applied, "authorized opaque apply verifies settled state")
    let updatedPassword = "updated-fixture-password"
    let updatedLogin = PasswordSyncLogin(origin: "https://example.test", username: "fixture", password: updatedPassword, created: 1_234_567_890_123)
    let updateBinding = PasswordSyncBinding(chain: keys.chainTag, folder: folder.path, scope: scope, profile: "")
    let updatedValue = try PasswordSyncRecords(keys: keys).seal(updatedLogin, key: key, binding: updateBinding).json
    let writesBeforeUpdate = store.writes
    let updated = await coordinator.apply(folder: folder.path, scope: scope, profile: "", changes: [["key": key, "desired": updatedValue, "base": value]])
    check(updated && store.writes == writesBeforeUpdate + 1, "opaque password update reaches fixture store")
    check(store.logins.first?.password == updatedPassword, "opaque password update changes the stored secret")
    check(store.logins.first?.created == 0, "opaque password update preserves native epoch creation date")
    for (index, created) in ([nil, 0, 1_234_567_890_123.5] as [Double?]).enumerated() {
      let source = PasswordRecords.Credentials(origin: "https://example.test", username: "date-fixture-\(index)", password: password, created: created)
      let sourceValue = try codec.seal(source, scope: scope, recordKey: source.recordKey)
      let sourceLog: [String: Any] = ["v": 1, "kind": "log", "device": "source-device", "seq": 1, "at": 123,
                                      "ops": [["k": source.recordKey, "h": "1:0:source-device", "v": sourceValue.json]]]
      let wire = try payloads.write(scope: scope, payload: text(sourceLog))
      let received = try payloads.read(scope: scope, payload: wire)
      check(!received.contains(password), "incoming creation metadata stays sealed before JS")
      let receivedLog = try JSONSerialization.jsonObject(with: Data(received.utf8)) as! [String: Any]
      let receivedValue = (receivedLog["ops"] as! [[String: Any]])[0]["v"]!
      let inserted = await coordinator.apply(folder: folder.path, scope: scope, profile: "",
                                             changes: [["key": source.recordKey, "desired": receivedValue, "base": NSNull()]])
      check(inserted, "outgoing/incoming wire reaches fixture native insertion")
      let stored = store.logins.first { $0.key == source.recordKey }
      check(stored?.password == password && stored?.created == created, "fixture insertion preserves authenticated source creation date")
      let reread = await coordinator.read(folder: folder.path, scope: scope, profile: "")
      let rereadRow = reread!.first { $0["key"] as? String == source.recordKey }!
      let reopenedValue = try codec.value(from: rereadRow["value"]!, scope: scope, recordKey: source.recordKey)
      let reopenedCredential = try codec.open(reopenedValue, scope: scope, recordKey: source.recordKey)
      check(reopenedCredential.created == created, "inserted source creation survives native read and seal")
    }
    for profile in ["incognito:window@profile", "../profile", "a/b", "a\\b", ".", ".."] {
      check(!PasswordSyncCoordinator.valid(scope: scope, profile: profile), "invalid engine profile rejected")
    }
    check(!PasswordSyncCoordinator.valid(scope: "app", profile: ""), "passwords require a profile scope")
    check(!PasswordSyncCoordinator.valid(scope: "p:short", profile: ""), "invalid profile scope rejected")
    check(PasswordSyncCoordinator.canonicalFolder("relative/path") == nil, "relative folder rejected")
    check(PasswordSyncCoordinator.canonicalFolder(folder.path + "/../other") == nil, "folder traversal rejected")
    let invalidationsBeforeGenerationChange = invalidations
    generation += 1
    check(!coordinator.status(folder: folder.path, scope: scope, profile: ""), "key generation changes invalidate approval synchronously")
    check(!store.nativeAuthorized && store.revocations > 0, "key invalidation synchronously revokes native authorization")
    check(auth.calls == 1 && invalidations == invalidationsBeforeGenerationChange + 1, "generation revokes once without silently reauthorizing")
    let reauthorized = await coordinator.authorize(folder: folder.path, profiles: profiles)
    check(reauthorized && auth.calls == 2, "explicit reauthorization succeeds")
    check(store.authorizationGenerations.last == generation, "reauthorization binds the new key generation instead of a stale context")
    store.deferRead = true
    let pendingRead = Task { await coordinator.read(folder: folder.path, scope: scope, profile: "") }
    for _ in 0..<100 where store.pending == nil { await Task.yield() }
    check(store.pending != nil, "native read reached injected async boundary")
    coordinator.revoke()
    check(!store.nativeAuthorized, "explicit revocation reaches native lease before late callback")
    store.pending?(store.logins)
    let revokedRead = await pendingRead.value
    check(revokedRead == nil, "late native password callback cannot cross revoked grant")
    auth.answer = nil
    let pendingAuth = Task { await coordinator.authorize(folder: folder.path, profiles: profiles) }
    for _ in 0..<100 where auth.pending == nil { await Task.yield() }
    check(auth.pending != nil, "authentication reached injected async boundary")
    coordinator.revoke()
    auth.pending?(true)
    let revokedAuth = await pendingAuth.value
    check(!revokedAuth && !coordinator.status(folder: folder.path, scope: scope, profile: ""), "late authentication cannot grant after revocation")
    auth.pending = nil
    let replacedAuth = Task { await coordinator.authorize(folder: folder.path, profiles: profiles) }
    for _ in 0..<100 where auth.pending == nil { await Task.yield() }
    check(auth.pending != nil, "key replacement authentication reached async boundary")
    generation += 1
    auth.pending?(true)
    let replacedAllowed = await replacedAuth.value
    check(!replacedAllowed, "pending authentication cannot grant across key replacement")
    auth.answer = true
    let finalAuthorization = await coordinator.authorize(folder: folder.path, profiles: profiles)
    check(finalAuthorization, "final fixture consent succeeds")
    now += 24 * 60 * 60
    check(!coordinator.status(folder: folder.path, scope: scope, profile: ""), "password session has a twenty-four-hour upper bound")
    check(!store.nativeAuthorized, "expiry revokes the native authorization instead of only the JS-facing flag")
    let refusingStore = FixturePasswordStore()
    refusingStore.rejectAuthorization = true
    let refusingCoordinator = PasswordSyncCoordinator(store: refusingStore, authentication: FixtureAuthentication(),
      snapshot: { PasswordSyncKeySnapshot(keys: keys, generation: generation) }, foreground: { true }, now: { now },
      observeSystem: false, onInvalidate: {})
    let refused = await refusingCoordinator.authorize(folder: folder.path, profiles: profiles)
    check(!refused && !refusingStore.nativeAuthorized && !refusingCoordinator.status(folder: folder.path, scope: scope, profile: ""), "rejected native lease cannot leave a live coordinator grant")
    let expiredStore = FixturePasswordStore()
    var clockReads = 0
    let expiredCoordinator = PasswordSyncCoordinator(store: expiredStore, authentication: FixtureAuthentication(),
      snapshot: { PasswordSyncKeySnapshot(keys: keys, generation: generation) }, foreground: { true },
      now: { clockReads += 1; return clockReads == 1 ? 100 : 100 + 24 * 60 * 60 }, observeSystem: false, onInvalidate: {})
    let expired = await expiredCoordinator.authorize(folder: folder.path, profiles: profiles)
    check(!expired && expiredStore.authorizationDeadlines.isEmpty && !expiredStore.nativeAuthorized, "a known-expired device-owner grant never calls native lease construction")
    print("PASS: \(checks) production password bridge/coordinator assertions; hypothetical conditional-mutation store, not Chromium; isolated sync folder only")
  }
}
