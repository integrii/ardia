import Foundation
import XCTest
@testable import ArdiaSyncCore

final class PasswordRecordsTests: XCTestCase {
  private let keys = SyncKeys(entropy: Data(repeating: 41, count: 32))
  private let scope = "p:fixture"
  private let login = PasswordRecords.Credentials(origin: "https://fixture.example", username: "alice", password: "fixture-secret-never-in-js-673")
  private var passwords: PasswordRecords { PasswordRecords(keys: keys) }

  private func encode(_ object: Any) throws -> Data {
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .fragmentsAllowed])
  }

  private func decode(_ data: Data) throws -> [String: Any] {
    try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
  }

  private func log(_ value: Any, key: String? = nil) -> [String: Any] {
    ["v": 1, "kind": "log", "device": "fixture-device", "seq": 7, "at": 1000,
     "ops": [["k": key ?? login.recordKey, "h": "000000001.0001.fixture", "v": value]]]
  }

  private func record(_ value: Any) -> [String: Any] {
    ["h": "000000001.0001.fixture", "o": ["fixture-device", 7], "v": value]
  }

  private func snapshot(_ value: Any) -> [String: Any] {
    ["v": 1, "kind": "snapshot", "device": "fixture-device", "at": 1000,
     "vv": ["fixture-device": 7], "seen": ["fixture-device": 1000], "records": [login.recordKey: record(value)]]
  }

  private func state() throws -> [String: Any] {
    ["records": [login.recordKey: record(login.legacyValue), "tab:unrelated": record(["title": "untouched"])],
     "base": [login.recordKey: String(decoding: try encode(login.legacyValue), as: UTF8.self), "tab:unrelated": "{ \"title\": \"untouched\" }"],
     "outbox": [["k": login.recordKey, "h": "pending-hlc", "v": login.legacyValue]],
     "journal": [log(login.legacyValue)], "vv": ["fixture-device": 7], "extra": ["other-device": [9, 11]],
     "files": ["file-id": ["d": "fixture-device", "k": "log", "s": 7, "at": 1000]],
     "seen": ["fixture-device": 1000], "damaged": ["bad-file": 10], "pendingSince": [login.recordKey: 1000],
     "seq": 7, "joined": true, "awaitRemote": false, "snapshotAt": 999, "pending": 1,
     "unapplied": [login.recordKey], "applyAs": [login.recordKey: "joining"]]
  }

  private func assertSecretAbsent(_ payload: Data, file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertNil(payload.range(of: Data(login.password.utf8)), file: file, line: line)
    XCTAssertFalse(passwordFieldPresent(payload, escaped: false), file: file, line: line)
    XCTAssertFalse(passwordFieldPresent(payload, escaped: true), file: file, line: line)
  }

  private func passwordFieldPresent(_ payload: Data, escaped: Bool) -> Bool {
    String(decoding: payload, as: UTF8.self).contains(escaped ? "\\\"p\\\"" : "\"p\"")
  }

  func testSecrecyChecksDetectRawAndEscapedPlaintextWithoutMatchingTheSentinel() throws {
    let plaintext = try encode(["p": "untracked-fixture"])
    let escapedPlaintext = try encode(["base": [login.recordKey: String(decoding: plaintext, as: UTF8.self)]])
    for payload in [plaintext, escapedPlaintext] {
      XCTAssertNil(payload.range(of: Data(login.password.utf8)))
    }
    XCTAssertTrue(passwordFieldPresent(plaintext, escaped: false))
    XCTAssertTrue(passwordFieldPresent(escapedPlaintext, escaped: true))
    let sealed = try passwords.seal(login, scope: scope, recordKey: login.recordKey)
    assertSecretAbsent(try encode(sealed.json))
  }

  func testLocalStateBase64IsBoundedBeforeDecodingAndAllowsPaddingAtTheLimit() throws {
    XCTAssertEqual(PasswordRecords.maximumPayloadBytes, 32 * 1024 * 1024)
    for limit in [0, 1, SyncKeys.padding - 4, SyncKeys.padding - 3, SyncKeys.padding] {
      let payload = Data(repeating: 65, count: limit)
      let file = try keys.seal(payload, scopeTag: "local", fileId: "state")
      let encoded = file.base64EncodedString()
      XCTAssertEqual(PasswordRecords.decodeLocalState(encoded, maximumPayloadBytes: limit), file)
      var decodedOversized = false
      XCTAssertNil(PasswordRecords.decodeLocalState(String(repeating: "A", count: encoded.utf8.count + 4), maximumPayloadBytes: limit, decode: { _ in
        decodedOversized = true
        return Data()
      }))
      XCTAssertFalse(decodedOversized)
      XCTAssertNil(PasswordRecords.decodeLocalState((file + Data([0])).base64EncodedString(), maximumPayloadBytes: limit))
    }
  }

  func testNonPasswordBaseJSONIsValidatedOnSealingAndOpeningWithoutRewritingValidStrings() throws {
    let bridge = PasswordBridgePayloads(keys: keys)
    for encoded in ["{broken", "", "undefined", "[1,]", "{\"text\":1,}"] {
      let local: [String: Any] = [scope: ["records": [:], "base": ["tab:unrelated": encoded], "outbox": []]]
      let payload = try encode(local)
      XCTAssertThrowsError(try bridge.sealLocal(String(decoding: payload, as: UTF8.self)))
      let sealed = try keys.seal(payload, scopeTag: "local", fileId: "state").base64EncodedString()
      XCTAssertThrowsError(try bridge.openLocal(sealed))
    }
    for encoded in ["null", " true ", "17", "\"quoted \\\"p\\\" ,] \\\\ text\"", "{ \"é\": 1, \"e\\u0301\": 2 }"] {
      let local: [String: Any] = [scope: ["records": [:], "base": ["tab:unrelated": encoded], "outbox": []]]
      let sealed = try bridge.sealLocal(String(decoding: encode(local), as: UTF8.self))
      let opened = try decode(Data(bridge.openLocal(sealed).utf8))
      let state = try XCTUnwrap(opened[scope] as? [String: Any])
      let base = try XCTUnwrap(state["base"] as? NSDictionary)
      let preserved = try XCTUnwrap(base.object(forKey: "tab:unrelated") as? String)
      XCTAssertEqual(Array(preserved.utf8), Array(encoded.utf8))
    }
  }

  private func assertEnvelope(_ json: Any, scope: String? = nil, key: String? = nil, file: StaticString = #filePath, line: UInt = #line) throws {
    let value = try passwords.value(from: json, scope: scope ?? self.scope, recordKey: key ?? login.recordKey)
    XCTAssertEqual(try passwords.open(value, scope: scope ?? self.scope, recordKey: key ?? login.recordKey), login, file: file, line: line)
  }

  private func operationValue(_ file: [String: Any]) throws -> Any {
    let ops = try XCTUnwrap(file["ops"] as? [[String: Any]])
    return try XCTUnwrap(ops.first?["v"])
  }

  func testRandomNonceWithStableAuthenticatedFingerprint() throws {
    let first = try passwords.seal(login, scope: scope, recordKey: login.recordKey)
    let second = try passwords.seal(login, scope: scope, recordKey: login.recordKey)
    XCTAssertNotEqual(first.sealed, second.sealed)
    XCTAssertEqual(first.fingerprint, second.fingerprint)
    XCTAssertEqual(try passwords.open(first, scope: scope, recordKey: login.recordKey), login)
    assertSecretAbsent(try encode(first.json))
    let changed = PasswordRecords.Credentials(origin: login.origin, username: login.username, password: "changed")
    XCTAssertNotEqual(first.fingerprint, try passwords.seal(changed, scope: scope, recordKey: login.recordKey).fingerprint)
    XCTAssertNotEqual(first.fingerprint, try passwords.seal(login, scope: "p:other", recordKey: login.recordKey).fingerprint)
  }

  func testCreationMetadataIsAuthenticatedWithoutChangingEditFingerprint() throws {
    let undated = try passwords.seal(login, scope: scope, recordKey: login.recordKey)
    for created: Double? in [nil, 0, 1_234_567_890_123.5, -1] {
      let credential = PasswordRecords.Credentials(origin: login.origin, username: login.username, password: login.password, created: created)
      let value = try passwords.seal(credential, scope: scope, recordKey: login.recordKey)
      XCTAssertEqual(value.fingerprint, undated.fingerprint)
      XCTAssertEqual(try passwords.open(value, scope: scope, recordKey: login.recordKey).created, created)
      for source in [log(credential.legacyValue), snapshot(credential.legacyValue)] {
        let incoming = try passwords.transformWire(scope: scope, payload: encode(source))
        assertSecretAbsent(incoming)
        let restored = try passwords.outboundLegacyWire(scope: scope, payload: incoming)
        XCTAssertEqual(try decode(restored) as NSDictionary, source as NSDictionary)
      }
      var overridden = value.json
      overridden["c"] = 123
      XCTAssertThrowsError(try passwords.value(from: overridden, scope: scope, recordKey: login.recordKey))
      var bytes = try XCTUnwrap(Data(base64Encoded: value.sealed))
      bytes[12] ^= 1
      XCTAssertThrowsError(try passwords.open(.init(sealed: bytes.base64EncodedString(), fingerprint: value.fingerprint), scope: scope, recordKey: login.recordKey))
    }
    XCTAssertEqual(Set(login.legacyValue.keys), ["o", "u", "p"])
  }

  func testCreationMetadataRejectsInvalidTypesNonfiniteAndOutOfRangeTimes() throws {
    for created: Any in [true, false, "0", [], ["ms": 0], 8_640_000_000_000_001.0, -8_640_000_000_000_001.0] {
      var raw = login.legacyValue
      raw["c"] = created
      XCTAssertThrowsError(try passwords.transformWire(scope: scope, payload: encode(log(raw))))
    }
    for created in [Double.nan, Double.infinity, -Double.infinity, 8_640_000_000_000_001.0, -8_640_000_000_000_001.0] {
      let invalid = PasswordRecords.Credentials(origin: login.origin, username: login.username, password: login.password, created: created)
      XCTAssertThrowsError(try passwords.seal(invalid, scope: scope, recordKey: login.recordKey))
    }
    var raw = login.legacyValue
    raw["c"] = NSNull()
    let incoming = try decode(passwords.transformWire(scope: scope, payload: encode(log(raw))))
    let value = try passwords.value(from: operationValue(incoming), scope: scope, recordKey: login.recordKey)
    XCTAssertNil(try passwords.open(value, scope: scope, recordKey: login.recordKey).created)
  }

  func testEmptyAndUnicodePasswordsPreserveExactBytes() throws {
    for secret in ["", "密碼🔑\n\u{0000}résumé", "é", "e\u{0301}"] {
      let credential = PasswordRecords.Credentials(origin: "https://例子.example", username: "用戶\n第二行", password: secret)
      let value = try passwords.seal(credential, scope: scope, recordKey: credential.recordKey)
      let opened = try passwords.open(value, scope: scope, recordKey: credential.recordKey)
      XCTAssertEqual(Array(opened.password.utf8), Array(secret.utf8))
      XCTAssertEqual(Array(opened.username.utf8), Array(credential.username.utf8))
    }
    let composed = PasswordRecords.Credentials(origin: login.origin, username: login.username, password: "é")
    let decomposed = PasswordRecords.Credentials(origin: login.origin, username: login.username, password: "e\u{0301}")
    XCTAssertNotEqual(composed, decomposed)
    XCTAssertNotEqual(try passwords.seal(composed, scope: scope, recordKey: login.recordKey).fingerprint,
                      try passwords.seal(decomposed, scope: scope, recordKey: login.recordKey).fingerprint)
  }

  func testWrongChainScopeRecordKeyAndTamperingFailAuthentication() throws {
    let value = try passwords.seal(login, scope: scope, recordKey: login.recordKey)
    let other = PasswordRecords(keys: SyncKeys(entropy: Data(repeating: 42, count: 32)))
    XCTAssertThrowsError(try other.open(value, scope: scope, recordKey: login.recordKey)) { XCTAssertEqual($0 as? PasswordRecords.Failure, .authentication) }
    XCTAssertThrowsError(try passwords.open(value, scope: "p:other", recordKey: login.recordKey)) { XCTAssertEqual($0 as? PasswordRecords.Failure, .authentication) }
    XCTAssertThrowsError(try passwords.open(value, scope: scope, recordKey: login.recordKey + "x")) { XCTAssertEqual($0 as? PasswordRecords.Failure, .authentication) }
    let original = try XCTUnwrap(Data(base64Encoded: value.sealed))
    for index in [0, 12, original.count - 1] {
      var bytes = original
      bytes[index] ^= 1
      let bad = PasswordRecords.Value(sealed: bytes.base64EncodedString(), fingerprint: value.fingerprint)
      XCTAssertThrowsError(try passwords.open(bad, scope: scope, recordKey: login.recordKey)) { XCTAssertEqual($0 as? PasswordRecords.Failure, .authentication) }
    }
    let badFingerprint = PasswordRecords.Value(sealed: value.sealed, fingerprint: Data(repeating: 0, count: 32).base64EncodedString())
    XCTAssertThrowsError(try passwords.open(badFingerprint, scope: scope, recordKey: login.recordKey)) { XCTAssertEqual($0 as? PasswordRecords.Failure, .authentication) }
    XCTAssertThrowsError(try passwords.value(from: badFingerprint.json, scope: scope, recordKey: login.recordKey))
    XCTAssertThrowsError(try passwords.outboundLegacyWire(scope: scope, payload: encode(log(badFingerprint.json))))
  }

  func testEnvelopeCannotBeOpenedAsGenericSyncFileOrLocalState() throws {
    let value = try passwords.seal(login, scope: scope, recordKey: login.recordKey)
    let combined = try XCTUnwrap(Data(base64Encoded: value.sealed))
    for bytes in [combined, SyncKeys.magic + combined] {
      for context in [(keys.scopeTag(scope), login.recordKey), ("local", "state"), (scope, login.recordKey)] {
        XCTAssertThrowsError(try keys.open(bytes, scopeTag: context.0, fileId: context.1))
      }
    }
    let generic = try keys.seal(encode(login.legacyValue), scopeTag: scope, fileId: login.recordKey)
    let forged = PasswordRecords.Value(sealed: generic.dropFirst(SyncKeys.magic.count).base64EncodedString(), fingerprint: value.fingerprint)
    XCTAssertThrowsError(try passwords.open(forged, scope: scope, recordKey: login.recordKey))
  }

  func testLegacyLogAndSnapshotRoundTripWithoutLosingCausality() throws {
    for original in [log(login.legacyValue), snapshot(login.legacyValue)] {
      let opaque = try passwords.transformWire(scope: scope, payload: encode(original))
      assertSecretAbsent(opaque)
      let roundTrip = try passwords.outboundLegacyWire(scope: scope, payload: opaque)
      XCTAssertEqual(try decode(roundTrip) as NSDictionary, original as NSDictionary)
      let again = try passwords.transformWire(scope: scope, payload: opaque)
      XCTAssertEqual(opaque, again)
    }
  }

  func testCopyingEnvelopeToUnrelatedRecordNeverDecryptsIt() throws {
    let value = try passwords.seal(login, scope: scope, recordKey: login.recordKey)
    let original = log(value.json, key: "tab:unrelated")
    let opaque = try passwords.transformWire(scope: scope, payload: encode(original))
    let outbound = try passwords.outboundLegacyWire(scope: scope, payload: opaque)
    XCTAssertEqual(try decode(outbound) as NSDictionary, original as NSDictionary)
    assertSecretAbsent(outbound)
  }

  func testScopeStateConvertsEveryPasswordSlotAndPreservesPendingWork() throws {
    let original = try state()
    let transformed = try passwords.transformLocal(scope: scope, payload: encode(original))
    assertSecretAbsent(transformed)
    let state = try decode(transformed)
    let records = try XCTUnwrap(state["records"] as? [String: [String: Any]])
    try assertEnvelope(XCTUnwrap(records[login.recordKey]?["v"]))
    let base = try XCTUnwrap(state["base"] as? [String: String])
    try assertEnvelope(JSONSerialization.jsonObject(with: Data(XCTUnwrap(base[login.recordKey]).utf8)))
    let outbox = try XCTUnwrap(state["outbox"] as? [[String: Any]])
    try assertEnvelope(XCTUnwrap(outbox.first?["v"]))
    let journal = try XCTUnwrap(state["journal"] as? [[String: Any]])
    try assertEnvelope(operationValue(XCTUnwrap(journal.first)))
    XCTAssertEqual(base["tab:unrelated"], (original["base"] as? [String: String])?["tab:unrelated"])
    XCTAssertEqual(records["tab:unrelated"]! as NSDictionary, (original["records"] as! [String: Any])["tab:unrelated"] as! NSDictionary)
    for field in ["vv", "extra", "files", "seen", "damaged", "pendingSince", "seq", "joined", "awaitRemote", "snapshotAt", "pending", "unapplied", "applyAs"] {
      XCTAssertEqual(try encode(state[field]!), try encode(original[field]!), field)
    }
    XCTAssertEqual(transformed, try passwords.transformLocal(scope: scope, payload: transformed))
  }

  func testRootScopeMapsWrappedScopesAndWrappedJournals() throws {
    let state = try state()
    let otherScope = "p:second"
    for payload: [String: Any] in [[scope: state, otherScope: state], ["scopes": [scope: state]], ["journal": [scope: [log(login.legacyValue)]]], ["scopes": [scope: state], "journal": [scope: [log(login.legacyValue)]]]] {
      let result = try passwords.transformLocal(payload: encode(payload))
      assertSecretAbsent(result)
      XCTAssertEqual(result, try passwords.transformLocal(payload: result))
    }
    let root = try decode(passwords.transformLocal(payload: encode([scope: state, otherScope: state])))
    let first = root[scope] as! [String: Any]
    let second = root[otherScope] as! [String: Any]
    let firstRecord = (first["records"] as! [String: [String: Any]])[login.recordKey]!["v"]!
    let secondRecord = (second["records"] as! [String: [String: Any]])[login.recordKey]!["v"]!
    let firstValue = try passwords.value(from: firstRecord, scope: scope, recordKey: login.recordKey)
    let secondValue = try passwords.value(from: secondRecord, scope: otherScope, recordKey: login.recordKey)
    XCTAssertNotEqual(firstValue.fingerprint, secondValue.fingerprint)
    XCTAssertThrowsError(try passwords.value(from: firstRecord, scope: otherScope, recordKey: login.recordKey))
  }

  func testScopedStandaloneJournalAndWirePayloads() throws {
    let batch = log(login.legacyValue)
    let array = try passwords.transformLocal(scope: scope, payload: encode([batch]))
    assertSecretAbsent(array)
    let files = try XCTUnwrap(JSONSerialization.jsonObject(with: array) as? [[String: Any]])
    try assertEnvelope(operationValue(XCTUnwrap(files.first)))
    for file in [batch, snapshot(login.legacyValue)] {
      assertSecretAbsent(try passwords.transformLocal(scope: scope, payload: encode(file)))
    }
  }

  func testNullTombstonesAndUnrelatedValuesArePreserved() throws {
    for original in [log(NSNull()), snapshot(NSNull()), log(["o": "ordinary", "u": "text", "p": "unrelated"], key: "tab:other")] {
      let result = try passwords.transformWire(scope: scope, payload: encode(original))
      XCTAssertEqual(try decode(result) as NSDictionary, original as NSDictionary)
      XCTAssertEqual(try decode(passwords.outboundLegacyWire(scope: scope, payload: result)) as NSDictionary, original as NSDictionary)
    }
    var local = try state()
    local["records"] = [login.recordKey: record(NSNull())]
    local["base"] = [login.recordKey: "null"]
    local["outbox"] = [["k": login.recordKey, "h": "hlc", "v": NSNull()]]
    local["journal"] = [log(NSNull())]
    XCTAssertEqual(try decode(passwords.transformLocal(scope: scope, payload: encode(local))) as NSDictionary, local as NSDictionary)
  }

  func testMalformedPasswordValuesFailClosedAtEveryLocation() throws {
    let malformed: [Any] = [login.password, 4, [], ["o": login.origin, "u": login.username],
                            ["o": login.origin, "u": login.username, "p": 3],
                            ["o": login.origin, "u": login.username, "p": login.password, "extra": login.password],
                            ["o": "wrong-origin", "u": login.username, "p": login.password],
                            ["version": 2, "sealed": "broken", "fingerprint": "broken"],
                            ["version": true, "sealed": "broken", "fingerprint": "broken"]]
    for bad in malformed {
      XCTAssertThrowsError(try passwords.transformWire(scope: scope, payload: encode(log(bad))))
      XCTAssertThrowsError(try passwords.transformWire(scope: scope, payload: encode(snapshot(bad))))
      var local = try state()
      local["base"] = [login.recordKey: String(decoding: try encode(bad), as: UTF8.self)]
      XCTAssertThrowsError(try passwords.transformLocal(payload: encode([scope: local])))
      local = try state()
      local["outbox"] = [["k": login.recordKey, "h": "hlc", "v": bad]]
      XCTAssertThrowsError(try passwords.transformLocal(payload: encode([scope: local])))
      XCTAssertThrowsError(try passwords.transformLocal(payload: encode(["journal": [scope: [log(bad)]]])))
    }
  }

  func testMalformedContainersNeverPassThrough() throws {
    var badLog = log(login.legacyValue)
    badLog["ops"] = ["hidden": login.legacyValue]
    var extraLog = log(login.legacyValue)
    extraLog["records"] = [login.recordKey: record(login.legacyValue)]
    var invalidVersion = log(login.legacyValue)
    invalidVersion["v"] = true
    var badSnapshot = snapshot(login.legacyValue)
    badSnapshot["records"] = [login.recordKey: login.legacyValue]
    var badUnrelatedOperation = log(NSNull(), key: "tab:other")
    badUnrelatedOperation["ops"] = [["k": "tab:other", "h": "hlc", "v": NSNull(), "hidden": login.legacyValue]]
    var badUnrelatedRecord = snapshot(NSNull())
    badUnrelatedRecord["records"] = ["tab:other": ["h": "hlc", "o": ["fixture", 7], "v": NSNull(), "hidden": login.legacyValue]]
    for file in [badLog, extraLog, invalidVersion, badSnapshot, badUnrelatedOperation, badUnrelatedRecord] {
      XCTAssertThrowsError(try passwords.transformWire(scope: scope, payload: encode(file)))
    }
    for (field, bad): (String, Any) in [("records", [login.recordKey: login.legacyValue]), ("base", [login.recordKey: login.legacyValue]), ("base", ["tab:other": login.legacyValue]), ("base", [login.recordKey: "{broken"]), ("journal", ["hidden": login.legacyValue]), ("outbox", ["hidden": login.legacyValue]), ("vv", ["hidden": login.legacyValue]), ("files", ["hidden": login.legacyValue]), ("future", login.legacyValue)] {
      var local = try state()
      local[field] = bad
      XCTAssertThrowsError(try passwords.transformLocal(payload: encode([scope: local])))
    }
    for root: Any in [[scope: login.legacyValue], ["journal": [scope: snapshot(login.legacyValue)]], ["journal": [scope: [snapshot(login.legacyValue)]]], ["journal": [scope: [log(login.legacyValue)]], "extra": login.legacyValue], [log(login.legacyValue)]] {
      XCTAssertThrowsError(try passwords.transformLocal(payload: encode(root)))
    }
  }

  func testOutboundRequiresAuthenticatedOpaqueValuesAndIdentity() throws {
    XCTAssertThrowsError(try passwords.outboundLegacyWire(scope: scope, payload: encode(log(login.legacyValue))))
    XCTAssertThrowsError(try passwords.seal(login, scope: scope, recordKey: login.recordKey + "wrong"))
    XCTAssertThrowsError(try passwords.transformWire(scope: scope, payload: encode(log(NSNull(), key: "pw:malformed"))))
    let credential = PasswordRecords.Credentials(origin: login.origin, username: "é", password: login.password)
    XCTAssertThrowsError(try passwords.seal(credential, scope: scope, recordKey: "pw:" + login.origin + "\ne\u{0301}"))
    let ambiguous = PasswordRecords.Credentials(origin: "https://fixture.example\nother", username: "alice", password: login.password)
    XCTAssertThrowsError(try passwords.seal(ambiguous, scope: scope, recordKey: ambiguous.recordKey))
    var envelope = try passwords.seal(login, scope: scope, recordKey: login.recordKey).json
    envelope["p"] = login.password
    XCTAssertThrowsError(try passwords.transformWire(scope: scope, payload: encode(log(envelope))))
    envelope.removeValue(forKey: "p")
    envelope["version"] = 3
    XCTAssertThrowsError(try passwords.transformWire(scope: scope, payload: encode(log(envelope))))
  }

  func testErrorsNeverContainInputOrSecrets() throws {
    let badJSON = Data(("{\"" + login.password + "\":").utf8)
    let actions: [() throws -> Void] = [
      { _ = try self.passwords.transformLocal(payload: badJSON) },
      { _ = try self.passwords.transformWire(scope: self.scope, payload: self.encode(self.log(self.login.password))) },
      { _ = try self.passwords.value(from: ["version": 2, "sealed": self.login.password, "fingerprint": self.login.password], scope: self.scope, recordKey: self.login.recordKey) },
    ]
    for action in actions {
      XCTAssertThrowsError(try action()) {
        XCTAssertNotNil($0 as? PasswordRecords.Failure)
        XCTAssertFalse(String(describing: $0).contains(self.login.password))
        XCTAssertFalse($0.localizedDescription.contains(self.login.password))
        XCTAssertFalse(String(describing: ($0 as NSError).userInfo).contains(self.login.password))
      }
    }
  }

  func testUnicodeEquivalentUsernamesRemainDistinctAcrossEveryBoundary() throws {
    let accounts = [
      PasswordRecords.Credentials(origin: login.origin, username: "é", password: "composed-password"),
      PasswordRecords.Credentials(origin: login.origin, username: "e\u{0301}", password: "decomposed-password"),
    ]
    let records = NSMutableDictionary()
    let bases = NSMutableDictionary()
    var operations = [[String: Any]]()
    for account in accounts {
      records.setObject(record(account.legacyValue), forKey: account.recordKey as NSString)
      bases.setObject(String(decoding: try encode(account.legacyValue), as: UTF8.self), forKey: account.recordKey as NSString)
      operations.append(["k": account.recordKey, "h": "clock", "v": account.legacyValue])
    }
    XCTAssertEqual(records.count, 2)
    var log = self.log(NSNull())
    log["ops"] = operations
    var snapshot = self.snapshot(NSNull())
    snapshot["records"] = records
    for file in [log, snapshot] {
      let opaque = try passwords.transformWire(scope: scope, payload: encode(file))
      let restored = try JSONSerialization.jsonObject(with: passwords.outboundLegacyWire(scope: scope, payload: opaque)) as! NSDictionary
      XCTAssertTrue(restored.isEqual(file as NSDictionary))
      let repeated = try passwords.transformWire(scope: scope, payload: opaque)
      XCTAssertTrue((try JSONSerialization.jsonObject(with: opaque) as! NSDictionary).isEqual(try JSONSerialization.jsonObject(with: repeated)))
    }
    let local: [String: Any] = ["records": records, "base": bases, "outbox": operations, "journal": [log]]
    let opaque = try passwords.transformLocal(scope: scope, payload: encode(local))
    let transformed = try decode(opaque)
    let opaqueRecords = try XCTUnwrap(transformed["records"] as? NSDictionary)
    let opaqueBases = try XCTUnwrap(transformed["base"] as? NSDictionary)
    XCTAssertEqual(opaqueRecords.count, 2)
    XCTAssertEqual(opaqueBases.count, 2)
    for account in accounts {
      let record = try XCTUnwrap(opaqueRecords.object(forKey: account.recordKey as NSString) as? [String: Any])
      let base = try XCTUnwrap(opaqueBases.object(forKey: account.recordKey as NSString) as? String)
      for json in [record["v"]!, try JSONSerialization.jsonObject(with: Data(base.utf8))] {
        let envelope = try passwords.value(from: json, scope: scope, recordKey: account.recordKey)
        let opened = try passwords.open(envelope, scope: scope, recordKey: account.recordKey)
        XCTAssertEqual(Array(opened.username.utf8), Array(account.username.utf8))
        XCTAssertEqual(Array(opened.password.utf8), Array(account.password.utf8))
      }
    }
    for root: [String: Any] in [[scope: local], ["scopes": [scope: local]], ["journal": [scope: [log]]]] {
      let result = try passwords.transformLocal(payload: encode(root))
      for account in accounts { XCTAssertNil(result.range(of: Data(account.password.utf8))) }
      let repeated = try passwords.transformLocal(payload: result)
      XCTAssertTrue((try JSONSerialization.jsonObject(with: result) as! NSDictionary).isEqual(try JSONSerialization.jsonObject(with: repeated)))
    }
    let journal = try passwords.transformLocal(scope: scope, payload: encode([log]))
    let file = try XCTUnwrap((JSONSerialization.jsonObject(with: journal) as? [[String: Any]])?.first)
    let restored = try passwords.outboundLegacyWire(scope: scope, payload: encode(file))
    XCTAssertTrue((try JSONSerialization.jsonObject(with: restored) as! NSDictionary).isEqual(log as NSDictionary))
  }

  func testApplyProvenanceConvertsEveryCandidateAndPreservesExactKeys() throws {
    let accounts = ["é", "e\u{0301}"].map { PasswordRecords.Credentials(origin: login.origin, username: $0, password: login.password) }
    let changed = accounts.map { PasswordRecords.Credentials(origin: $0.origin, username: $0.username, password: "new-password") }
    let existing = try accounts.map { try passwords.seal($0, scope: scope, recordKey: $0.recordKey) }
    let provenance = NSMutableDictionary()
    for index in accounts.indices {
      provenance.setObject([NSNull(), accounts[index].legacyValue, changed[index].legacyValue, existing[index].json], forKey: accounts[index].recordKey as NSString)
    }
    var local = try state()
    local["applyProvenance"] = provenance
    let opaque = try passwords.transformLocal(scope: scope, payload: encode(local))
    assertSecretAbsent(opaque)
    let transformed = try decode(opaque)
    let output = try XCTUnwrap(transformed["applyProvenance"] as? NSDictionary)
    XCTAssertEqual(output.count, 2)
    for index in accounts.indices {
      let candidates = try XCTUnwrap(output.object(forKey: accounts[index].recordKey as NSString) as? [Any])
      XCTAssertEqual(candidates.count, 4)
      XCTAssertTrue(candidates[0] is NSNull)
      let values = try candidates.dropFirst().map { try passwords.value(from: $0, scope: scope, recordKey: accounts[index].recordKey) }
      for (position, expected) in [accounts[index], changed[index], accounts[index]].enumerated() {
        XCTAssertEqual(try passwords.open(values[position], scope: scope, recordKey: expected.recordKey), expected)
      }
      XCTAssertEqual(values[0].fingerprint, existing[index].fingerprint)
      XCTAssertEqual(values[2], existing[index])
    }
    let repeated = try passwords.transformLocal(scope: scope, payload: opaque)
    XCTAssertTrue((try JSONSerialization.jsonObject(with: opaque) as! NSDictionary).isEqual(try JSONSerialization.jsonObject(with: repeated)))
    for bad: Any in [NSNull(), [], [login.recordKey: login.legacyValue], [login.recordKey: [login.password]], ["tab:other": [login.legacyValue]], ["pw:malformed": [Any]()]] {
      local["applyProvenance"] = bad
      XCTAssertThrowsError(try passwords.transformLocal(scope: scope, payload: encode(local))) { XCTAssertEqual($0 as? PasswordRecords.Failure, .format) }
    }
  }
}
