import CoreFoundation
import CryptoKit
import Foundation

public struct PasswordRecords {
  public struct Credentials: Equatable {
    public let origin: String
    public let username: String
    public let password: String

    public init(origin: String, username: String, password: String) {
      self.origin = origin
      self.username = username
      self.password = password
    }

    public var recordKey: String { "pw:" + origin + "\n" + username }
    public var legacyValue: [String: Any] { ["o": origin, "u": username, "p": password] }

    public static func == (lhs: Credentials, rhs: Credentials) -> Bool {
      lhs.origin.utf8.elementsEqual(rhs.origin.utf8) && lhs.username.utf8.elementsEqual(rhs.username.utf8) && lhs.password.utf8.elementsEqual(rhs.password.utf8)
    }
  }

  public struct Value: Equatable {
    public let version: Int
    public let sealed: String
    public let fingerprint: String

    public init(version: Int = 2, sealed: String, fingerprint: String) {
      self.version = version
      self.sealed = sealed
      self.fingerprint = fingerprint
    }

    public var json: [String: Any] { ["version": version, "sealed": sealed, "fingerprint": fingerprint] }
  }

  public enum Failure: Error, Equatable, LocalizedError {
    case format
    case authentication

    public var errorDescription: String? {
      switch self {
      case .format: return "Invalid password sync data."
      case .authentication: return "Password sync authentication failed."
      }
    }
  }

  private enum Direction { case opaque, legacy }
  private static let maximumPayloadBytes = 32 * 1024 * 1024
  private static let maximumCredentialBytes = 1024 * 1024
  private let encryptionKey: SymmetricKey
  private let fingerprintKey: SymmetricKey
  private let chain: String

  public init(keys: SyncKeys) {
    let salt = Data("ardia.sync.password.v2".utf8)
    encryptionKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: keys.fileKey, salt: salt, info: Data("encryption".utf8), outputByteCount: 32)
    fingerprintKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: keys.fileKey, salt: salt, info: Data("fingerprint".utf8), outputByteCount: 32)
    chain = keys.chainTag
  }

  public func seal(_ credentials: Credentials, scope: String, recordKey: String) throws -> Value {
    try validate(credentials, recordKey: recordKey)
    let context = try associatedData(scope: scope, recordKey: recordKey)
    let plain = try Self.encode(credentials.legacyValue)
    do {
      let box = try AES.GCM.seal(plain, using: encryptionKey, authenticating: context)
      guard let combined = box.combined else { throw Failure.format }
      return Value(sealed: combined.base64EncodedString(), fingerprint: fingerprint(credentials, context: context).base64EncodedString())
    } catch {
      throw Failure.authentication
    }
  }

  public func open(_ value: Value, scope: String, recordKey: String) throws -> Credentials {
    let context = try associatedData(scope: scope, recordKey: recordKey)
    guard value.version == 2, value.sealed.utf8.count <= Self.maximumCredentialBytes * 8 + 4096, value.fingerprint.utf8.count == 44,
          let combined = Data(base64Encoded: value.sealed), combined.count >= 28,
          let suppliedFingerprint = Data(base64Encoded: value.fingerprint), suppliedFingerprint.count == 32 else { throw Failure.format }
    let plain: Data
    do {
      plain = try AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: encryptionKey, authenticating: context)
    } catch {
      throw Failure.authentication
    }
    let credentials = try credentials(Self.decode(plain), recordKey: recordKey)
    guard HMAC<SHA256>.isValidAuthenticationCode(suppliedFingerprint, authenticating: fingerprintInput(credentials, context: context), using: fingerprintKey) else {
      throw Failure.authentication
    }
    return credentials
  }

  public func value(from json: Any, scope: String, recordKey: String) throws -> Value {
    let value = try envelope(json)
    _ = try open(value, scope: scope, recordKey: recordKey)
    return value
  }

  public func transformWire(scope: String, payload: Data) throws -> Data {
    try Self.encode(wire(Self.decode(payload), scope: scope, direction: .opaque))
  }

  public func outboundLegacyWire(scope: String, payload: Data) throws -> Data {
    try Self.encode(wire(Self.decode(payload), scope: scope, direction: .legacy))
  }

  public func transformLocal(payload: Data) throws -> Data {
    let indexed = try Self.indexed(Self.decode(payload))
    if indexed.count > 0 && indexed.allKeys.allSatisfy({ ($0 as? String) == "scopes" || ($0 as? String) == "journal" }) {
      var root = try Self.object(indexed)
      if let scopes = root["scopes"] { root["scopes"] = try scopeMap(scopes) }
      if let journal = root["journal"] { root["journal"] = try journalMap(journal) }
      return try Self.encode(root)
    }
    return try Self.encode(scopeMap(indexed))
  }

  public func transformLocal(scope: String, payload: Data) throws -> Data {
    let json = try Self.decode(payload)
    if json is [Any] { return try Self.encode(journal(json, scope: scope)) }
    let object = try Self.object(json)
    if object["kind"] != nil { return try Self.encode(wire(object, scope: scope, direction: .opaque)) }
    return try Self.encode(state(object, scope: scope))
  }

  private func associatedData(scope: String, recordKey: String) throws -> Data {
    guard !scope.isEmpty, scope.utf8.count <= 4096, recordKey.hasPrefix("pw:"), recordKey.utf8.count <= Self.maximumCredentialBytes,
          let newline = recordKey.firstIndex(of: "\n"), recordKey.distance(from: recordKey.startIndex, to: newline) > 3 else { throw Failure.format }
    return Self.framed(["ardia.sync.password.envelope.v2", chain, scope, recordKey])
  }

  private func validate(_ credentials: Credentials, recordKey: String) throws {
    guard !credentials.origin.isEmpty, !credentials.origin.contains("\n"),
          credentials.origin.utf8.count + credentials.username.utf8.count + credentials.password.utf8.count <= Self.maximumCredentialBytes,
          credentials.recordKey.utf8.elementsEqual(recordKey.utf8) else { throw Failure.format }
  }

  private func fingerprintInput(_ credentials: Credentials, context: Data) -> Data {
    context + Self.framed(["ardia.sync.password.fingerprint.v2", credentials.origin, credentials.username, credentials.password])
  }

  private func fingerprint(_ credentials: Credentials, context: Data) -> Data {
    Data(HMAC<SHA256>.authenticationCode(for: fingerprintInput(credentials, context: context), using: fingerprintKey))
  }

  private static func framed(_ strings: [String]) -> Data {
    var result = Data()
    for string in strings {
      let bytes = Data(string.utf8)
      result.append(withUnsafeBytes(of: UInt64(bytes.count).bigEndian) { Data($0) })
      result.append(bytes)
    }
    return result
  }

  private func credentials(_ json: Any, recordKey: String) throws -> Credentials {
    let object = try Self.object(json)
    guard Set(object.keys) == ["o", "u", "p"], let origin = object["o"] as? String,
          let username = object["u"] as? String, let password = object["p"] as? String else { throw Failure.format }
    let credentials = Credentials(origin: origin, username: username, password: password)
    try validate(credentials, recordKey: recordKey)
    return credentials
  }

  private func envelope(_ json: Any) throws -> Value {
    let object = try Self.object(json)
    guard Set(object.keys) == ["version", "sealed", "fingerprint"], Self.number(object["version"], equals: 2),
          let sealed = object["sealed"] as? String, let fingerprint = object["fingerprint"] as? String else { throw Failure.format }
    return Value(sealed: sealed, fingerprint: fingerprint)
  }

  private func transform(_ json: Any, scope: String, recordKey: String, direction: Direction) throws -> Any {
    _ = try associatedData(scope: scope, recordKey: recordKey)
    if json is NSNull { return json }
    let object = try Self.object(json)
    if object["version"] != nil {
      let value = try envelope(object)
      let credentials = try open(value, scope: scope, recordKey: recordKey)
      return direction == .opaque ? value.json : credentials.legacyValue
    }
    guard direction == .opaque else { throw Failure.format }
    return try seal(credentials(object, recordKey: recordKey), scope: scope, recordKey: recordKey).json
  }

  private func wire(_ json: Any, scope: String, direction: Direction) throws -> [String: Any] {
    var object = try Self.object(json)
    guard Self.number(object["v"], equals: 1), let kind = object["kind"] as? String,
          object["device"] is String, Self.isNumber(object["at"]) else { throw Failure.format }
    switch kind {
    case "log":
      guard Set(object.keys) == ["v", "kind", "device", "seq", "at", "ops"], Self.isNumber(object["seq"]) else { throw Failure.format }
      object["ops"] = try operations(object["ops"], scope: scope, direction: direction)
    case "snapshot":
      guard Set(object.keys) == ["v", "kind", "device", "at", "vv", "seen", "records"] else { throw Failure.format }
      try Self.numberMap(object["vv"])
      try Self.numberMap(object["seen"])
      object["records"] = try records(object["records"], scope: scope, direction: direction)
    default: throw Failure.format
    }
    return object
  }

  private func operations(_ json: Any?, scope: String, direction: Direction) throws -> [[String: Any]] {
    guard let list = json as? [Any] else { throw Failure.format }
    return try list.map { item in
      var operation = try Self.object(item)
      guard Set(operation.keys) == ["k", "h", "v"], let key = operation["k"] as? String, operation["h"] is String else { throw Failure.format }
      if key.hasPrefix("pw:") {
        operation["v"] = try transform(operation["v"]!, scope: scope, recordKey: key, direction: direction)
      }
      return operation
    }
  }

  private func records(_ json: Any?, scope: String, direction: Direction) throws -> NSDictionary {
    try Self.mapIndexed(json) { key, value in
      var record = try Self.object(value)
      guard Set(record.keys) == ["h", "v", "o"], record["h"] is String,
            let origin = record["o"] as? [Any], origin.count == 2, origin[0] is String, Self.isNumber(origin[1]) else { throw Failure.format }
      if key.hasPrefix("pw:") {
        record["v"] = try transform(record["v"]!, scope: scope, recordKey: key, direction: direction)
        return record
      }
      return value
    }
  }

  private func state(_ json: Any, scope: String) throws -> [String: Any] {
    var state = try Self.object(json)
    let allowed: Set<String> = ["records", "base", "unapplied", "vv", "extra", "files", "damaged", "pendingSince", "seq", "outbox", "journal", "seen", "joined", "awaitRemote", "applyAs", "applyProvenance", "snapshotAt", "pending"]
    guard Set(state.keys).isSubset(of: allowed) else { throw Failure.format }
    state["records"] = try records(state["records"], scope: scope, direction: .opaque)
    state["base"] = try Self.mapIndexed(state["base"]) { key, value in
      guard let encoded = value as? String else { throw Failure.format }
      if key.hasPrefix("pw:") {
        return String(decoding: try Self.encode(transform(Self.decode(Data(encoded.utf8)), scope: scope, recordKey: key, direction: .opaque)), as: UTF8.self)
      }
      return encoded
    }
    state["outbox"] = try operations(state["outbox"], scope: scope, direction: .opaque)
    if let batches = state["journal"] { state["journal"] = try journal(batches, scope: scope) }
    if let provenance = state["applyProvenance"] {
      state["applyProvenance"] = try Self.mapIndexed(provenance) { key, value in
        guard key.hasPrefix("pw:"), let candidates = value as? [Any] else { throw Failure.format }
        _ = try associatedData(scope: scope, recordKey: key)
        return try candidates.map { try transform($0, scope: scope, recordKey: key, direction: .opaque) }
      }
    }
    try validateStateMetadata(state)
    return state
  }

  private func validateStateMetadata(_ state: [String: Any]) throws {
    for key in ["vv", "damaged", "pendingSince", "seen"] {
      if let value = state[key] { try Self.numberMap(value) }
    }
    for key in ["seq", "snapshotAt", "pending"] {
      if let value = state[key], !Self.isNumber(value) { throw Failure.format }
    }
    for key in ["joined", "awaitRemote"] {
      if let value = state[key] {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { throw Failure.format }
      }
    }
    if let value = state["unapplied"], !(value is [String]) { throw Failure.format }
    if let value = state["extra"] {
      let map = try Self.indexed(value)
      for list in map.allValues {
        guard let numbers = list as? [Any], numbers.allSatisfy({ Self.isNumber($0) }) else { throw Failure.format }
      }
    }
    if let value = state["applyAs"] {
      let map = try Self.indexed(value)
      guard map.allValues.allSatisfy({ ($0 as? String) == "joined" || ($0 as? String) == "joining" }) else { throw Failure.format }
    }
    if let value = state["files"] {
      let map = try Self.indexed(value)
      for item in map.allValues {
        let file = try Self.object(item)
        guard Set(file.keys).isSubset(of: ["d", "k", "s", "vv", "at"]), file["d"] is String,
              let kind = file["k"] as? String, ["log", "snapshot", "bad"].contains(kind), Self.isNumber(file["at"]) else { throw Failure.format }
        if let sequence = file["s"], !Self.isNumber(sequence) { throw Failure.format }
        if let vector = file["vv"] { try Self.numberMap(vector) }
      }
    }
  }

  private func journal(_ json: Any, scope: String) throws -> [[String: Any]] {
    guard let list = json as? [Any] else { throw Failure.format }
    return try list.map {
      let file = try wire($0, scope: scope, direction: .opaque)
      guard file["kind"] as? String == "log" else { throw Failure.format }
      return file
    }
  }

  private func scopeMap(_ json: Any) throws -> NSDictionary {
    try Self.mapIndexed(json) { scope, value in try state(value, scope: scope) }
  }

  private func journalMap(_ json: Any) throws -> NSDictionary {
    try Self.mapIndexed(json) { scope, value in try journal(value, scope: scope) }
  }

  private static func indexed(_ json: Any?) throws -> NSDictionary {
    guard let dictionary = json as? NSDictionary, dictionary.allKeys.allSatisfy({ $0 is String }) else { throw Failure.format }
    return dictionary
  }

  private static func mapIndexed(_ json: Any?, transform: (String, Any) throws -> Any) throws -> NSDictionary {
    let original = try indexed(json)
    let result = NSMutableDictionary(capacity: original.count)
    for (key, value) in original {
      guard let key = key as? String else { throw Failure.format }
      result.setObject(try transform(key, value), forKey: key as NSString)
    }
    return result
  }

  private static func object(_ json: Any?) throws -> [String: Any] {
    guard let original = json as? NSDictionary, let object = json as? [String: Any], original.count == object.count else { throw Failure.format }
    return object
  }

  private static func isNumber(_ value: Any?) -> Bool {
    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return false }
    return number.doubleValue.isFinite
  }

  private static func number(_ value: Any?, equals expected: Int) -> Bool {
    isNumber(value) && (value as? NSNumber)?.doubleValue == Double(expected)
  }

  private static func numberMap(_ value: Any?) throws {
    let map = try indexed(value)
    guard map.allValues.allSatisfy({ isNumber($0) }) else { throw Failure.format }
  }

  private static func decode(_ data: Data) throws -> Any {
    guard data.count <= maximumPayloadBytes else { throw Failure.format }
    do { return try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) }
    catch { throw Failure.format }
  }

  private static func encode(_ json: Any) throws -> Data {
    do {
      let data = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .fragmentsAllowed, .withoutEscapingSlashes])
      guard data.count <= maximumPayloadBytes else { throw Failure.format }
      return data
    } catch { throw Failure.format }
  }
}
