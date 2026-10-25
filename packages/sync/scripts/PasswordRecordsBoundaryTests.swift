import Foundation

@main
struct PasswordRecordsBoundaryTests {
  private enum Failure: Error { case assertion(String) }
  private static var checks = 0
  private static let sentinel = "SECRET-673-fake"

  private static func check(_ condition: @autoclosure () throws -> Bool, _ label: String) throws {
    guard try condition() else { throw Failure.assertion(label) }
    checks += 1
  }

  private static func rejects(_ label: String, _ action: () throws -> Void) throws {
    do { try action() }
    catch let error as PasswordRecords.Failure {
      for description in [String(describing: error), error.localizedDescription, String(describing: (error as NSError).userInfo)] {
        try check(!description.contains(sentinel), label + " has sanitized errors")
      }
      checks += 1
      return
    } catch { throw Failure.assertion(label + " has unexpected error type") }
    throw Failure.assertion(label + " accepted invalid data")
  }

  private static func encode(_ value: Any) throws -> Data {
    try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed, .withoutEscapingSlashes])
  }

  private static func object(_ data: Data) throws -> [String: Any] {
    guard let result = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw Failure.assertion("expected JSON object") }
    return result
  }

  private static func noSecret(_ data: Data) throws {
    try check(data.range(of: Data(sentinel.utf8)) == nil, "no plaintext password in boundary JSON")
  }

  private static func passwordFieldPresent(_ data: Data, escaped: Bool) -> Bool {
    String(decoding: data, as: UTF8.self).contains(escaped ? "\\\"p\\\"" : "\"p\"")
  }

  private static func noPasswordFields(_ data: Data) throws {
    try check(!passwordFieldPresent(data, escaped: false), "no raw plaintext password field")
    try check(!passwordFieldPresent(data, escaped: true), "no escaped plaintext password field")
  }

  static func main() {
    do {
      try run()
      print("PasswordRecords boundary: \(checks) checks passed against production Core sources")
    } catch Failure.assertion(let label) {
      FileHandle.standardError.write(Data(("PasswordRecords boundary failed: " + label + "\n").utf8))
      exit(1)
    } catch {
      FileHandle.standardError.write(Data("PasswordRecords boundary failed with an unexpected error.\n".utf8))
      exit(1)
    }
  }

  private static func creationDates(core: PasswordRecords, scope: String, login: PasswordRecords.Credentials) throws {
    let key = login.recordKey
    let original = try core.seal(login, scope: scope, recordKey: key)
    for created: Double? in [nil, 0, 1_234_567_890_123.5, -1, -8_640_000_000_000_000, 8_640_000_000_000_000] {
      let dated = PasswordRecords.Credentials(origin: login.origin, username: login.username, password: login.password, created: created)
      let value = try core.seal(dated, scope: scope, recordKey: key)
      let opened = try core.open(value, scope: scope, recordKey: key)
      try check(opened.created == created, "creation milliseconds survive authenticated envelope")
      try check(opened == dated, "credential equality includes creation metadata")
      try check(value.fingerprint == original.fingerprint, "creation metadata does not change edit identity")
      try check(Set(dated.legacyValue.keys) == (created == nil ? ["o", "u", "p"] : ["o", "u", "p", "c"]), "unknown creation retains three-field legacy shape")
      let wire: [String: Any] = ["v": 1, "kind": "log", "device": "fixture", "seq": 1, "at": 1000,
                                  "ops": [["k": key, "h": "clock", "v": value.json]]]
      let outbound = try core.outboundLegacyWire(scope: scope, payload: encode(wire))
      let inbound = try object(core.transformWire(scope: scope, payload: outbound))
      let restored = (inbound["ops"] as! [[String: Any]])[0]["v"]!
      let restoredValue = try core.value(from: restored, scope: scope, recordKey: key)
      try check(core.open(restoredValue, scope: scope, recordKey: key).created == created, "outgoing and incoming wire preserve source creation")
      try noSecret(encode(inbound))
      try noPasswordFields(encode(inbound))
      let local: [String: Any] = ["records": [key: ["h": "clock", "o": ["fixture", 1], "v": dated.legacyValue]],
                                 "base": [key: String(decoding: try encode(dated.legacyValue), as: UTF8.self)], "outbox": [],
                                 "applyProvenance": [key: [dated.legacyValue]]]
      let migrated = try object(core.transformLocal(scope: scope, payload: encode(local)))
      let record = (migrated["records"] as! [String: [String: Any]])[key]!["v"]!
      let base = try JSONSerialization.jsonObject(with: Data((migrated["base"] as! [String: String])[key]!.utf8))
      let provenance = (migrated["applyProvenance"] as! [String: [Any]])[key]![0]
      for slot in [record, base, provenance] {
        let sealed = try core.value(from: slot, scope: scope, recordKey: key)
        try check(core.open(sealed, scope: scope, recordKey: key).created == created, "creation metadata survives local state slots")
      }
    }
    func incoming(_ created: Any, extra: Bool = false) throws -> Data {
      var raw = login.legacyValue
      raw["c"] = created
      if extra { raw["extra"] = 1 }
      return try encode(["v": 1, "kind": "log", "device": "fixture", "seq": 1, "at": 1000,
                         "ops": [["k": key, "h": "clock", "v": raw]]])
    }
    let nullIncoming = try object(core.transformWire(scope: scope, payload: incoming(NSNull())))
    let nullValue = try core.value(from: (nullIncoming["ops"] as! [[String: Any]])[0]["v"]!, scope: scope, recordKey: key)
    try check(core.open(nullValue, scope: scope, recordKey: key).created == nil, "explicit null creation stays unknown")
    for bad: Any in [true, false, "0", [], ["ms": 0], 8_640_000_000_000_001.0, -8_640_000_000_000_001.0] {
      try rejects("invalid creation metadata") { _ = try core.transformWire(scope: scope, payload: incoming(bad)) }
    }
    try rejects("unknown credential metadata") { _ = try core.transformWire(scope: scope, payload: incoming(0, extra: true)) }
    for bad in [Double.nan, Double.infinity, -Double.infinity, 8_640_000_000_000_001.0, -8_640_000_000_000_001.0] {
      let invalid = PasswordRecords.Credentials(origin: login.origin, username: login.username, password: login.password, created: bad)
      try rejects("invalid native creation time") { _ = try core.seal(invalid, scope: scope, recordKey: key) }
    }
    let dated = PasswordRecords.Credentials(origin: login.origin, username: login.username, password: login.password, created: 1_234_567_890_123)
    let authenticated = try core.seal(dated, scope: scope, recordKey: key)
    let plain = try encode(dated.legacyValue)
    guard let dateBytes = plain.range(of: Data("1234567890123".utf8)), var bytes = Data(base64Encoded: authenticated.sealed) else { throw Failure.assertion("creation tamper fixture") }
    bytes[12 + dateBytes.lowerBound] ^= 1
    try rejects("creation ciphertext tampering despite unchanged edit fingerprint") {
      _ = try core.open(.init(sealed: bytes.base64EncodedString(), fingerprint: authenticated.fingerprint), scope: scope, recordKey: key)
    }
    var untrusted = authenticated.json
    untrusted["c"] = 9
    try rejects("JS cannot override sealed creation time") { _ = try core.value(from: untrusted, scope: scope, recordKey: key) }
  }

  private static func run() throws {
    let keys = SyncKeys(entropy: Data(repeating: 41, count: 32))
    let core = PasswordRecords(keys: keys)
    let login = PasswordRecords.Credentials(origin: "https://fixture.example", username: "fixture-user", password: sentinel)
    let scope = "p:fixture"
    let key = login.recordKey
    let first = try core.seal(login, scope: scope, recordKey: key)
    let second = try core.seal(login, scope: scope, recordKey: key)
    try check(first.sealed != second.sealed, "random nonces")
    try check(first.fingerprint == second.fingerprint, "stable fingerprints")
    try check(core.open(first, scope: scope, recordKey: key) == login, "authenticated roundtrip")
    try creationDates(core: core, scope: scope, login: login)
    try localStateDecodeBounds(keys: keys)
    let plaintext = try encode(["p": "untracked-fixture"])
    let escapedPlaintext = try encode(["base": [key: String(decoding: plaintext, as: UTF8.self)]])
    for (payload, label) in [(plaintext, "no raw plaintext password field"), (escapedPlaintext, "no escaped plaintext password field")] {
      try check(payload.range(of: Data(sentinel.utf8)) == nil, "plaintext regression does not depend on sentinel matching")
      do {
        try noPasswordFields(payload)
        throw Failure.assertion("plaintext field detection accepted a leak")
      } catch Failure.assertion(let actual) {
        try check(actual == label, "secrecy assertion detects intentionally leaked plaintext")
      }
    }
    try noPasswordFields(encode(first.json))
    let other = PasswordRecords(keys: SyncKeys(entropy: Data(repeating: 42, count: 32)))
    try rejects("chain binding") { _ = try other.open(first, scope: scope, recordKey: key) }
    try rejects("scope binding") { _ = try core.open(first, scope: "p:other", recordKey: key) }
    try rejects("key binding") { _ = try core.open(first, scope: scope, recordKey: key + "other") }
    try rejects("identity binding") { _ = try core.seal(login, scope: scope, recordKey: key + "other") }
    let bytes = Data(base64Encoded: first.sealed)!
    for index in [0, 12, bytes.count - 1] {
      var bad = bytes
      bad[index] ^= 1
      try rejects("ciphertext tampering") {
        _ = try core.open(PasswordRecords.Value(sealed: bad.base64EncodedString(), fingerprint: first.fingerprint), scope: scope, recordKey: key)
      }
    }
    let fakeHash = PasswordRecords.Value(sealed: first.sealed, fingerprint: Data(repeating: 0, count: 32).base64EncodedString())
    try rejects("untrusted fingerprint") { _ = try core.value(from: fakeHash.json, scope: scope, recordKey: key) }
    for data in [bytes, SyncKeys.magic + bytes] {
      for context in [(keys.scopeTag(scope), key), ("local", "state"), (scope, key)] {
        do {
          _ = try keys.open(data, scopeTag: context.0, fileId: context.1)
          throw Failure.assertion("generic file confused with password envelope")
        } catch is SyncKeys.Failure { checks += 1 }
      }
    }
    let generic = try keys.seal(encode(login.legacyValue), scopeTag: scope, fileId: key)
    let genericValue = PasswordRecords.Value(sealed: generic.dropFirst(SyncKeys.magic.count).base64EncodedString(), fingerprint: first.fingerprint)
    try rejects("generic file cannot forge password envelope") { _ = try core.open(genericValue, scope: scope, recordKey: key) }
    var fingerprints = [String]()
    for password in ["", "密碼🔑\n\u{0000}", "é", "e\u{0301}"] {
      let item = PasswordRecords.Credentials(origin: login.origin, username: "用戶\nsecond", password: password)
      let value = try core.seal(item, scope: scope, recordKey: item.recordKey)
      let result = try core.open(value, scope: scope, recordKey: item.recordKey)
      try check(Array(result.password.utf8) == Array(password.utf8), "exact Unicode and empty password bytes")
      fingerprints.append(value.fingerprint)
    }
    try check(fingerprints[2] != fingerprints[3], "canonical equivalents remain different passwords")
    let composed = PasswordRecords.Credentials(origin: login.origin, username: "é", password: sentinel)
    let passwordComposed = PasswordRecords.Credentials(origin: login.origin, username: login.username, password: "é")
    let passwordDecomposed = PasswordRecords.Credentials(origin: login.origin, username: login.username, password: "e\u{0301}")
    try check(passwordComposed != passwordDecomposed, "native password equality preserves bytes")
    try rejects("exact Unicode identity") { _ = try core.seal(composed, scope: scope, recordKey: "pw:" + login.origin + "\ne\u{0301}") }

    func log(_ value: Any, _ key: String? = nil) -> [String: Any] {
      ["v": 1, "kind": "log", "device": "fixture", "seq": 7, "at": 1000,
       "ops": [["k": key ?? login.recordKey, "h": "clock", "v": value]]]
    }
    func record(_ value: Any) -> [String: Any] { ["h": "clock", "o": ["fixture", 7], "v": value] }
    func snapshot(_ value: Any) -> [String: Any] {
      ["v": 1, "kind": "snapshot", "device": "fixture", "at": 1000, "vv": ["fixture": 7], "seen": ["fixture": 1000], "records": [key: record(value)]]
    }
    func opValue(_ file: [String: Any]) -> Any { (file["ops"] as! [[String: Any]])[0]["v"]! }
    func snapshotValue(_ file: [String: Any]) -> Any { (file["records"] as! [String: [String: Any]])[key]!["v"]! }
    for file in [log(login.legacyValue), snapshot(login.legacyValue)] {
      let opaque = try core.transformWire(scope: scope, payload: encode(file))
      try noSecret(opaque)
      try noPasswordFields(opaque)
      try check(object(core.outboundLegacyWire(scope: scope, payload: opaque)) as NSDictionary == file as NSDictionary, "wire roundtrip preserves causality")
      try check(core.transformWire(scope: scope, payload: opaque) == opaque, "opaque transformation idempotent")
      let another = try core.transformWire(scope: scope, payload: encode(file))
      let firstObject = try object(opaque)
      let secondObject = try object(another)
      let isLog = file["kind"] as? String == "log"
      let firstValue = try core.value(from: isLog ? opValue(firstObject) : snapshotValue(firstObject), scope: scope, recordKey: key)
      let secondValue = try core.value(from: isLog ? opValue(secondObject) : snapshotValue(secondObject), scope: scope, recordKey: key)
      try check(firstValue.sealed != secondValue.sealed, "legacy conversion randomizes nonce")
      try check(firstValue.fingerprint == secondValue.fingerprint && firstValue.fingerprint == first.fingerprint, "legacy conversion retains stable fingerprint")
      try check(core.transformLocal(scope: scope, payload: opaque) == opaque, "scoped local wire preserves existing opaque bytes")
    }
    let unknownValue: [String: Any] = ["future": ["unknown": ["o": "ordinary", "u": "text", "p": "not-a-password"]], "list": [1, true, NSNull()]]
    for file in [log(NSNull()), snapshot(NSNull()), log(first.json, "tab:other"), log(unknownValue, "tab:other")] {
      let transformed = try core.transformWire(scope: scope, payload: encode(file))
      try check(object(transformed) as NSDictionary == file as NSDictionary, "tombstones and unrelated unknown value properties preserved")
      let outbound = try core.outboundLegacyWire(scope: scope, payload: transformed)
      try check(object(outbound) as NSDictionary == file as NSDictionary, "non-password envelope never decrypted")
      try noSecret(outbound)
    }
    try rejects("outbound legacy injection") { _ = try core.outboundLegacyWire(scope: scope, payload: encode(log(login.legacyValue))) }
    try rejects("outbound forged fingerprint") { _ = try core.outboundLegacyWire(scope: scope, payload: encode(log(fakeHash.json))) }
    let base = String(decoding: try encode(login.legacyValue), as: UTF8.self)
    let state: [String: Any] = ["records": [key: record(login.legacyValue), "tab:other": record(unknownValue)],
                               "base": [key: base, "tab:other": "{ \"text\": \"untouched\" }"],
                               "outbox": [["k": key, "h": "pending-clock", "v": login.legacyValue]], "journal": [log(login.legacyValue)],
                               "vv": ["fixture": 7], "extra": ["second": [9, 11]], "seen": ["fixture": 1000],
                               "files": ["file": ["d": "fixture", "k": "log", "s": 7, "at": 1000],
                                         "snapshot": ["d": "second", "k": "snapshot", "vv": ["second": 11], "at": 999],
                                         "bad": ["d": "", "k": "bad", "at": 990]],
                               "seq": 7, "pending": 1, "joined": true, "awaitRemote": false, "snapshotAt": 999,
                               "unapplied": [key], "applyAs": ["pw:": "joining"], "damaged": ["bad": 990], "pendingSince": ["file": 1000]]
    let transformed = try core.transformLocal(scope: scope, payload: encode(state))
    try noSecret(transformed)
    let converted = try object(transformed)
    let records = converted["records"] as! [String: [String: Any]]
    let convertedBase = converted["base"] as! [String: String]
    let outbox = converted["outbox"] as! [[String: Any]]
    let journal = converted["journal"] as! [[String: Any]]
    let journalOps = journal[0]["ops"] as! [[String: Any]]
    let baseValue = try JSONSerialization.jsonObject(with: Data(convertedBase[key]!.utf8))
    var slotSeals = Set<String>()
    for value in [records[key]!["v"]!, baseValue, outbox[0]["v"]!, journalOps[0]["v"]!] {
      let envelope = try core.value(from: value, scope: scope, recordKey: key)
      try check(core.open(envelope, scope: scope, recordKey: key) == login, "all four state slots converted")
      try check(envelope.fingerprint == first.fingerprint, "all converted slots have stable fingerprint")
      slotSeals.insert(envelope.sealed)
    }
    try check(slotSeals.count == 4, "independent legacy slots have distinct nonces")
    for field in ["vv", "extra", "seen", "files", "seq", "pending", "joined", "awaitRemote", "snapshotAt", "unapplied", "applyAs", "damaged", "pendingSince"] {
      try check(encode(converted[field]!) == encode(state[field]!), "preserve pending and causal metadata")
    }
    try check(records["tab:other"]! as NSDictionary == record(unknownValue) as NSDictionary, "unknown non-password record values preserved")
    try check(convertedBase["tab:other"] == (state["base"] as! [String: String])["tab:other"], "unrelated base string preserved byte for byte")
    for (index, encoded) in ["{broken", "", "undefined", "{\"text\":1} trailing", "[1,]", "{\"text\":1,}", "[1, \n ]"].enumerated() {
      var invalid = state
      invalid["base"] = ["tab:other": encoded]
      try rejects("malformed unrelated base JSON \(index)") { _ = try core.transformLocal(scope: scope, payload: encode(invalid)) }
      try rejects("malformed unrelated base JSON in root \(index)") { _ = try core.transformLocal(payload: encode([scope: invalid])) }
    }
    for encoded in ["null", " true ", "17", "\"quoted \\\"p\\\" ,] \\\\ text\"", "[1, false, { \"text\": \",}\" }]", "{ \"é\": 1, \"e\\u0301\": 2 }"] {
      var valid = state
      valid["base"] = ["tab:other": encoded]
      let result = try object(core.transformLocal(scope: scope, payload: encode(valid)))
      let preserved = (result["base"] as! NSDictionary).object(forKey: "tab:other") as? String
      try check(preserved?.utf8.elementsEqual(encoded.utf8) == true, "valid unrelated JSON fragments and exact bytes preserved")
    }
    try check(core.transformLocal(scope: scope, payload: transformed) == transformed, "state idempotency")
    for root: [String: Any] in [[scope: state], [scope: state, "p:second": state], ["scopes": [scope: state]], ["journal": [scope: [log(login.legacyValue)]]], ["scopes": [scope: state], "journal": [scope: [log(login.legacyValue)]]]] {
      let result = try core.transformLocal(payload: encode(root))
      try noSecret(result)
      try check(core.transformLocal(payload: result) == result, "local root schemas preserve opaque bytes")
    }
    let standaloneJournal = try core.transformLocal(scope: scope, payload: encode([log(login.legacyValue)]))
    try noSecret(standaloneJournal)
    try check(core.transformLocal(scope: scope, payload: standaloneJournal) == standaloneJournal, "standalone journal preserves opaque bytes")
    var initialState = state
    for field in ["journal", "pendingSince", "applyAs"] { initialState.removeValue(forKey: field) }
    var journalEraState = initialState
    journalEraState["journal"] = [log(login.legacyValue)]
    for legacyState in [initialState, journalEraState, state] {
      let result = try core.transformLocal(payload: encode([scope: legacyState]))
      try noSecret(result)
      let restored = (try object(result))[scope] as! [String: Any]
      try check(Set(restored.keys) == Set(legacyState.keys), "released state shape keeps exactly its original fields")
      for field in legacyState.keys where !["records", "base", "outbox", "journal"].contains(field) {
        try check(encode(restored[field]!) == encode(legacyState[field]!), "released state metadata unchanged")
      }
    }
    for empty: [String: Any] in [[:], ["journal": [:]], ["scopes": [:]], [scope: ["records": [:], "base": [:], "outbox": []]]] {
      try check(object(core.transformLocal(payload: encode(empty))) as NSDictionary == empty as NSDictionary, "empty legacy roots preserved")
    }
    var tombstones = initialState
    tombstones["records"] = [key: record(NSNull())]
    tombstones["base"] = [key: "null"]
    tombstones["outbox"] = [["k": key, "h": "clock", "v": NSNull()]]
    tombstones["journal"] = [log(NSNull())]
    try check(object(core.transformLocal(scope: scope, payload: encode(tombstones))) as NSDictionary == tombstones as NSDictionary, "all local tombstones preserved")
    for bad: Any in [sentinel, 4, [], ["o": login.origin, "u": login.username], ["o": login.origin, "u": login.username, "p": 4], ["o": "wrong", "u": login.username, "p": sentinel], ["o": login.origin, "u": login.username, "p": sentinel, "extra": sentinel], ["version": true, "sealed": "bad", "fingerprint": "bad"], fakeHash.json] {
      try rejects("malformed log password") { _ = try core.transformWire(scope: scope, payload: encode(log(bad))) }
      try rejects("malformed snapshot password") { _ = try core.transformWire(scope: scope, payload: encode(snapshot(bad))) }
      var local = state
      local["base"] = [key: String(decoding: try encode(bad), as: UTF8.self)]
      try rejects("malformed base password") { _ = try core.transformLocal(payload: encode([scope: local])) }
      local = state
      local["outbox"] = [["k": key, "h": "clock", "v": bad]]
      try rejects("malformed outbox password") { _ = try core.transformLocal(payload: encode([scope: local])) }
      local = state
      local["records"] = [key: record(bad)]
      try rejects("malformed local record password") { _ = try core.transformLocal(payload: encode([scope: local])) }
      try rejects("malformed journal password") { _ = try core.transformLocal(payload: encode(["journal": [scope: [log(bad)]]])) }
    }
    for (field, value): (String, Any) in [("records", [key: login.legacyValue]), ("base", [key: login.legacyValue]), ("base", ["tab:other": login.legacyValue]), ("base", [key: "{broken"]), ("journal", [scope: login.legacyValue]), ("outbox", ["hidden": login.legacyValue]), ("vv", ["hidden": login.legacyValue]), ("files", ["hidden": login.legacyValue]), ("unknown", login.legacyValue)] {
      var local = state
      local[field] = value
      try rejects("malformed state structure") { _ = try core.transformLocal(payload: encode([scope: local])) }
    }
    var malformedOp = log(login.legacyValue)
    malformedOp["ops"] = [["k": "tab:other", "h": "clock", "v": NSNull(), "hidden": login.legacyValue]]
    try rejects("malformed unrelated op wrapper") { _ = try core.transformWire(scope: scope, payload: encode(malformedOp)) }
    var malformedSnapshot = snapshot(NSNull())
    malformedSnapshot["records"] = ["tab:other": ["h": "clock", "o": ["fixture", 7], "v": NSNull(), "hidden": login.legacyValue]]
    try rejects("malformed unrelated record wrapper") { _ = try core.transformWire(scope: scope, payload: encode(malformedSnapshot)) }
    for root: Any in [[scope: login.legacyValue], ["journal": [scope: snapshot(login.legacyValue)]], ["journal": [scope: [snapshot(login.legacyValue)]]], ["journal": [scope: [log(login.legacyValue)]], "extra": login.legacyValue], [log(login.legacyValue)]] {
      try rejects("malformed local root") { _ = try core.transformLocal(payload: encode(root)) }
    }
    try rejects("wrong scope during wire conversion") { _ = try core.transformWire(scope: "p:other", payload: encode(log(first.json))) }
    try rejects("wrong scope during local conversion") { _ = try core.transformLocal(payload: encode(["p:other": converted])) }
    try rejects("wrong key during wire conversion") { _ = try core.transformWire(scope: scope, payload: encode(log(first.json, key + "other"))) }
    try rejects("invalid tombstone key") { _ = try core.transformWire(scope: scope, payload: encode(log(NSNull(), "pw:malformed"))) }
    var smuggled = first.json
    smuggled["p"] = sentinel
    try rejects("envelope has extra plaintext") { _ = try core.transformWire(scope: scope, payload: encode(log(smuggled))) }
    try rejects("JSON parse error sanitized") { _ = try core.transformLocal(payload: Data(("{\"" + sentinel + "\":").utf8)) }
    let recordJSON = String(decoding: try encode(record(NSNull())), as: UTF8.self)
    let collidingRecords = "{\"tab:é\":" + recordJSON + ",\"tab:e\\u0301\":" + recordJSON + "}"
    let collisionSnapshot = Data(("{\"v\":1,\"kind\":\"snapshot\",\"device\":\"fixture\",\"at\":1000,\"vv\":{},\"seen\":{},\"records\":" + collidingRecords + "}").utf8)
    let collisionRecords = (try object(core.transformWire(scope: scope, payload: collisionSnapshot)))["records"] as! NSDictionary
    try check(collisionRecords.count == 2, "Unicode-equivalent unrelated record keys preserved")
    let collisionBase = Data(("{\"records\":{},\"base\":{\"tab:é\":\"null\",\"tab:e\\u0301\":\"null\"},\"outbox\":[]}").utf8)
    let collisionBases = (try object(core.transformLocal(scope: scope, payload: collisionBase)))["base"] as! NSDictionary
    try check(collisionBases.count == 2, "Unicode-equivalent unrelated base keys preserved")
    let opaqueUnrelatedValue = Data("{\"v\":1,\"kind\":\"log\",\"device\":\"fixture\",\"seq\":7,\"at\":1000,\"ops\":[{\"k\":\"tab:other\",\"h\":\"clock\",\"v\":{\"é\":1,\"e\\u0301\":2}}]}".utf8)
    let preservedValue = opValue(try object(core.transformWire(scope: scope, payload: opaqueUnrelatedValue))) as! NSDictionary
    try check(preservedValue.count == 2, "unrelated opaque value Unicode keys remain distinct")
    try check(preservedValue.object(forKey: "é" as NSString) as? Int == 1, "first unrelated Unicode property preserved")
    try check(preservedValue.object(forKey: "e\u{0301}" as NSString) as? Int == 2, "second unrelated Unicode property preserved")
    try unicodeAccounts(core: core, scope: scope)
    try applyProvenance(core: core, scope: scope)
  }

  private static func localStateDecodeBounds(keys: SyncKeys) throws {
    try check(PasswordRecords.maximumPayloadBytes == 32 * 1024 * 1024, "shared production plaintext cap is 32 MiB")
    for limit in [0, 1, 2, SyncKeys.padding - 5, SyncKeys.padding - 4, SyncKeys.padding - 3, SyncKeys.padding, SyncKeys.padding * 2 - 4, SyncKeys.padding * 2 - 3] {
      let payload = Data(repeating: 65, count: limit)
      let file = try keys.seal(payload, scopeTag: "local", fileId: "state")
      let encoded = file.base64EncodedString()
      let decoded = PasswordRecords.decodeLocalState(encoded, maximumPayloadBytes: limit)
      try check(decoded == file, "maximum local payload includes length header, padding, magic, nonce, tag and base64 rounding")
      try check(keys.open(decoded!, scopeTag: "local", fileId: "state") == payload, "maximum local payload decrypts without truncation")
      for oversized in [String(repeating: "A", count: encoded.utf8.count + 4), String(repeating: "é", count: encoded.utf8.count / 2 + 1)] {
        var decodedOversized = false
        let result = PasswordRecords.decodeLocalState(oversized, maximumPayloadBytes: limit, decode: { _ in
          decodedOversized = true
          return Data()
        })
        try check(result == nil, "oversized encoded local state rejected")
        try check(!decodedOversized, "oversized encoded local state rejected before decoder allocation")
      }
      try check(PasswordRecords.decodeLocalState((file + Data([0])).base64EncodedString(), maximumPayloadBytes: limit) == nil, "decoded local state cannot exceed its exact encrypted byte cap")
    }
    for limit in [-1, Int.max] {
      var decodedInvalidLimit = false
      try check(PasswordRecords.decodeLocalState("", maximumPayloadBytes: limit, decode: { _ in
        decodedInvalidLimit = true
        return Data()
      }) == nil, "invalid helper limits fail closed without integer overflow")
      try check(!decodedInvalidLimit, "invalid helper limits rejected before decoding")
    }
    try check(PasswordRecords.decodeLocalState("%%") == nil, "malformed local base64 rejected")
  }

  private static func unicodeAccounts(core: PasswordRecords, scope: String) throws {
    let accounts = [
      PasswordRecords.Credentials(origin: "https://fixture.example", username: "é", password: sentinel + "-composed"),
      PasswordRecords.Credentials(origin: "https://fixture.example", username: "e\u{0301}", password: sentinel + "-decomposed"),
    ]
    let records = NSMutableDictionary()
    let bases = NSMutableDictionary()
    let vector = NSMutableDictionary()
    var operations = [[String: Any]]()
    for (index, account) in accounts.enumerated() {
      records.setObject(["h": "clock-\(index)", "o": ["fixture", index + 1], "v": account.legacyValue], forKey: account.recordKey as NSString)
      bases.setObject(String(decoding: try encode(account.legacyValue), as: UTF8.self), forKey: account.recordKey as NSString)
      vector.setObject(index + 1, forKey: account.username as NSString)
      operations.append(["k": account.recordKey, "h": "clock-\(index)", "v": account.legacyValue])
    }
    try check(records.count == 2 && bases.count == 2 && vector.count == 2, "Unicode account fixture has distinct exact keys")
    let log: [String: Any] = ["v": 1, "kind": "log", "device": "fixture", "seq": 2, "at": 1000, "ops": operations]
    let snapshot: [String: Any] = ["v": 1, "kind": "snapshot", "device": "fixture", "at": 1000, "vv": vector, "seen": vector, "records": records]

    func verify(_ json: Any, account: PasswordRecords.Credentials, scope: String) throws -> PasswordRecords.Value {
      let envelope = try core.value(from: json, scope: scope, recordKey: account.recordKey)
      let opened = try core.open(envelope, scope: scope, recordKey: account.recordKey)
      try check(Array(opened.username.utf8) == Array(account.username.utf8), "Unicode account username bytes preserved")
      try check(Array(opened.password.utf8) == Array(account.password.utf8), "Unicode account password bytes preserved")
      return envelope
    }

    func verifyLog(_ file: [String: Any], scope: String) throws {
      let ops = file["ops"] as! [[String: Any]]
      try check(ops.count == 2, "both Unicode accounts remain in log")
      for (index, account) in accounts.enumerated() {
        try check(Array((ops[index]["k"] as! String).utf8) == Array(account.recordKey.utf8), "log record key bytes preserved")
        _ = try verify(ops[index]["v"]!, account: account, scope: scope)
      }
    }

    func verifyRecords(_ map: NSDictionary, scope: String) throws {
      try check(map.count == 2, "both Unicode accounts remain in record map")
      for account in accounts {
        let record = map.object(forKey: account.recordKey as NSString) as! [String: Any]
        _ = try verify(record["v"]!, account: account, scope: scope)
      }
    }

    for file in [log, snapshot] {
      let opaque = try core.transformWire(scope: scope, payload: encode(file))
      try noSecret(opaque)
      let transformed = try object(opaque)
      if file["kind"] as? String == "log" { try verifyLog(transformed, scope: scope) }
      else { try verifyRecords(transformed["records"] as! NSDictionary, scope: scope) }
      let restored = try object(core.outboundLegacyWire(scope: scope, payload: opaque))
      try check((restored as NSDictionary).isEqual(file as NSDictionary), "both Unicode accounts restore exact legacy wire values and metadata")
      let repeated = try object(core.transformWire(scope: scope, payload: opaque))
      try check((transformed as NSDictionary).isEqual(repeated as NSDictionary), "both Unicode account envelopes remain unchanged on repeat")
    }

    let state: [String: Any] = ["records": records, "base": bases, "outbox": operations, "journal": [log], "vv": vector, "seen": vector, "unapplied": accounts.map(\.recordKey)]
    let opaqueState = try core.transformLocal(scope: scope, payload: encode(state))
    try noSecret(opaqueState)
    let transformed = try object(opaqueState)
    try verifyRecords(transformed["records"] as! NSDictionary, scope: scope)
    let opaqueBases = transformed["base"] as! NSDictionary
    try check(opaqueBases.count == 2, "both Unicode accounts remain in base")
    for account in accounts {
      let encoded = opaqueBases.object(forKey: account.recordKey as NSString) as! String
      let value = try JSONSerialization.jsonObject(with: Data(encoded.utf8))
      let envelope = try verify(value, account: account, scope: scope)
      let encodedRecord = (transformed["records"] as! NSDictionary).object(forKey: account.recordKey as NSString) as! [String: Any]
      let recordEnvelope = try core.value(from: encodedRecord["v"]!, scope: scope, recordKey: account.recordKey)
      try check(envelope.fingerprint == recordEnvelope.fingerprint, "Unicode account base and record fingerprints agree")
    }
    try verifyLog(["ops": transformed["outbox"]!], scope: scope)
    try verifyLog((transformed["journal"] as! [[String: Any]])[0], scope: scope)
    for field in ["vv", "seen", "unapplied"] {
      try check(encode(transformed[field]!) == encode(state[field]!), "Unicode indexed causal metadata preserved")
    }
    try check((try object(core.transformLocal(scope: scope, payload: opaqueState)) as NSDictionary).isEqual(transformed as NSDictionary), "Unicode local envelopes are stable on repeat")

    let scopes = NSMutableDictionary()
    let journals = NSMutableDictionary()
    for name in ["p:é", "p:e\u{0301}"] {
      scopes.setObject(state, forKey: name as NSString)
      journals.setObject([log], forKey: name as NSString)
    }
    for root: Any in [scopes, ["scopes": scopes], ["journal": journals], ["scopes": scopes, "journal": journals]] {
      let opaque = try core.transformLocal(payload: encode(root))
      try noSecret(opaque)
      let restored = try JSONSerialization.jsonObject(with: opaque) as! NSDictionary
      let wrappedScopes = restored.object(forKey: "scopes") as? NSDictionary
      let wrappedJournal = restored.object(forKey: "journal") as? NSDictionary
      if let journalMap = wrappedJournal {
        try check(journalMap.count == 2, "Unicode scope keys remain distinct in journal wrapper")
        for name in ["p:é", "p:e\u{0301}"] {
          try verifyLog((journalMap.object(forKey: name as NSString) as! [[String: Any]])[0], scope: name)
        }
      }
      if wrappedScopes != nil || wrappedJournal == nil {
        let scopeMap = wrappedScopes ?? restored
        try check(scopeMap.count == 2, "Unicode scope keys remain distinct in state root")
        for name in ["p:é", "p:e\u{0301}"] {
          let scoped = scopeMap.object(forKey: name as NSString) as! [String: Any]
          try verifyRecords(scoped["records"] as! NSDictionary, scope: name)
        }
      }
      let repeated = try JSONSerialization.jsonObject(with: core.transformLocal(payload: opaque)) as! NSDictionary
      try check(restored.isEqual(repeated), "Unicode scoped envelopes remain unchanged on repeat")
    }
    let opaqueJournal = try core.transformLocal(scope: scope, payload: encode([log]))
    try noSecret(opaqueJournal)
    try verifyLog((try JSONSerialization.jsonObject(with: opaqueJournal) as! [[String: Any]])[0], scope: scope)
    let tombstones = NSMutableDictionary()
    for account in accounts { tombstones.setObject(["h": "clock", "o": ["fixture", 2], "v": NSNull()], forKey: account.recordKey as NSString) }
    var deleted = snapshot
    deleted["records"] = tombstones
    let restoredTombstones = try object(core.transformWire(scope: scope, payload: encode(deleted)))
    try check((restoredTombstones as NSDictionary).isEqual(deleted as NSDictionary), "both Unicode tombstones and causal vectors preserved")
  }

  private static func applyProvenance(core: PasswordRecords, scope: String) throws {
    let old = ["é", "e\u{0301}"].map { PasswordRecords.Credentials(origin: "https://fixture.example", username: $0, password: sentinel + "-old") }
    let new = old.map { PasswordRecords.Credentials(origin: $0.origin, username: $0.username, password: sentinel + "-new") }
    let existing = try old.map { try core.seal($0, scope: scope, recordKey: $0.recordKey) }
    let provenance = NSMutableDictionary()
    for index in old.indices {
      provenance.setObject([NSNull(), old[index].legacyValue, new[index].legacyValue, existing[index].json], forKey: old[index].recordKey as NSString)
    }
    let state: [String: Any] = ["records": [:], "base": [:], "outbox": [], "applyProvenance": provenance, "seq": 7, "vv": ["fixture": 7], "unapplied": old.map(\.recordKey)]
    let opaque = try core.transformLocal(scope: scope, payload: encode(state))
    try noSecret(opaque)
    let restored = try object(opaque)
    let candidatesByKey = restored["applyProvenance"] as! NSDictionary
    try check(candidatesByKey.count == 2, "provenance preserves both Unicode record keys")
    for index in old.indices {
      let candidates = candidatesByKey.object(forKey: old[index].recordKey as NSString) as! [Any]
      try check(candidates.count == 4 && candidates[0] is NSNull, "provenance preserves candidate order and null tombstones")
      let values = try candidates.dropFirst().map { try core.value(from: $0, scope: scope, recordKey: old[index].recordKey) }
      for (position, expected) in [old[index], new[index], old[index]].enumerated() {
        let actual = try core.open(values[position], scope: scope, recordKey: expected.recordKey)
        try check(Array(actual.username.utf8) == Array(expected.username.utf8), "provenance candidate retains exact username bytes")
        try check(Array(actual.password.utf8) == Array(expected.password.utf8), "provenance candidate retains old and new password bytes")
      }
      try check(values[0].fingerprint == existing[index].fingerprint, "legacy provenance fingerprint matches authenticated existing value")
      try check(values[0].fingerprint != values[1].fingerprint, "old and new provenance candidates remain distinct")
      try check(values[2] == existing[index], "first provenance conversion preserves existing opaque bytes")
    }
    for field in ["seq", "vv", "unapplied", "records", "base", "outbox"] {
      try check(encode(restored[field]!) == encode(state[field]!), "provenance conversion preserves causal and pending state")
    }
    let repeated = try object(core.transformLocal(scope: scope, payload: opaque))
    try check((restored as NSDictionary).isEqual(repeated as NSDictionary), "repeated provenance transform preserves all opaque bytes")
    for root: [String: Any] in [[scope: state], ["scopes": [scope: state]]] {
      let result = try core.transformLocal(payload: encode(root))
      try noSecret(result)
      let again = try core.transformLocal(payload: result)
      try check((try JSONSerialization.jsonObject(with: result) as! NSDictionary).isEqual(try JSONSerialization.jsonObject(with: again)), "wrapped provenance remains stable")
    }
    for empty: Any in [NSDictionary(), [old[0].recordKey: [Any]()]] {
      var local = state
      local["applyProvenance"] = empty
      let result = try object(core.transformLocal(scope: scope, payload: encode(local)))
      try check((result["applyProvenance"] as! NSDictionary).isEqual(empty), "empty provenance map and candidate arrays preserved")
    }
    let forged = PasswordRecords.Value(sealed: existing[0].sealed, fingerprint: Data(repeating: 0, count: 32).base64EncodedString())
    let invalid: [Any] = [NSNull(), [], sentinel, old[0].legacyValue,
                          [old[0].recordKey: NSNull()], [old[0].recordKey: old[0].legacyValue],
                          [old[0].recordKey: sentinel], [old[0].recordKey: [sentinel]],
                          [old[0].recordKey: [["o": old[0].origin, "u": old[0].username]]],
                          [old[0].recordKey: [old[1].legacyValue]], [old[0].recordKey: [existing[1].json]],
                          [old[0].recordKey: [forged.json]], ["tab:other": [old[0].legacyValue]],
                          ["pw:malformed": [Any]()]]
    for bad in invalid {
      var local = state
      local["applyProvenance"] = bad
      try rejects("malformed or unauthenticated provenance") { _ = try core.transformLocal(scope: scope, payload: encode(local)) }
    }
    try rejects("provenance scope binding") { _ = try core.transformLocal(scope: "p:other", payload: opaque) }
  }
}
