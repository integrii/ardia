import CoreFoundation
import Foundation

struct PasswordBridgePayloads {
  enum Failure: Error { case invalidLocalState }
  private let keys: SyncKeys
  private let records: PasswordRecords

  init(keys: SyncKeys) {
    self.keys = keys
    records = PasswordRecords(keys: keys)
  }

  func read(scope: String, payload: Data) throws -> String {
    String(decoding: try records.transformWire(scope: scope, payload: payload), as: UTF8.self)
  }

  func write(scope: String, payload: String) throws -> Data {
    try records.outboundLegacyWire(scope: scope, payload: Data(payload.utf8))
  }

  func sealLocal(_ text: String) throws -> String {
    let input = Data(text.utf8)
    let validated = try records.transformLocal(payload: input)
    guard try equivalent(comparableLocal(input), comparableLocal(validated)) else { throw Failure.invalidLocalState }
    return try keys.seal(validated, scopeTag: "local", fileId: "state").base64EncodedString()
  }

  func openLocal(_ sealed: String) throws -> String {
    guard let data = Data(base64Encoded: sealed) else { throw Failure.invalidLocalState }
    let plain = try keys.open(data, scopeTag: "local", fileId: "state")
    return String(decoding: try records.transformLocal(payload: plain), as: UTF8.self)
  }

  private func comparableLocal(_ data: Data) throws -> NSDictionary {
    let root = try indexed(JSONSerialization.jsonObject(with: data))
    if root.count > 0 && root.allKeys.allSatisfy({ ($0 as? String) == "scopes" || ($0 as? String) == "journal" }) {
      return try mapIndexed(root) { key, value in key == "scopes" ? try comparableScopes(value) : value }
    }
    return try comparableScopes(root)
  }

  private func comparableScopes(_ scopes: Any) throws -> NSDictionary {
    try mapIndexed(scopes) { _, state in
      try mapIndexed(state) { field, value in
        guard field == "base" else { return value }
        return try mapIndexed(value) { key, encoded in
          guard key.hasPrefix("pw:") else { return encoded }
          guard let text = encoded as? String else { throw Failure.invalidLocalState }
          return try JSONSerialization.jsonObject(with: Data(text.utf8), options: [.fragmentsAllowed])
        }
      }
    }
  }

  private func indexed(_ value: Any) throws -> NSDictionary {
    guard let dictionary = value as? NSDictionary, dictionary.allKeys.allSatisfy({ $0 is String }) else { throw Failure.invalidLocalState }
    return dictionary
  }

  private func mapIndexed(_ value: Any, transform: (String, Any) throws -> Any) throws -> NSDictionary {
    let original = try indexed(value)
    let result = NSMutableDictionary(capacity: original.count)
    for (key, value) in original {
      guard let key = key as? String else { throw Failure.invalidLocalState }
      result.setObject(try transform(key, value), forKey: key as NSString)
    }
    return result
  }

  private func equivalent(_ left: Any, _ right: Any) -> Bool {
    if let left = left as? NSDictionary {
      guard let right = right as? NSDictionary, left.count == right.count else { return false }
      var rightValues: [Data: Any] = [:]
      for (key, value) in right {
        guard let key = key as? String else { return false }
        rightValues[Data(key.utf8)] = value
      }
      for (key, value) in left {
        guard let key = key as? String, let other = rightValues[Data(key.utf8)], equivalent(value, other) else { return false }
      }
      return true
    }
    if let left = left as? NSArray {
      guard let right = right as? NSArray, left.count == right.count else { return false }
      return (0..<left.count).allSatisfy { equivalent(left[$0], right[$0]) }
    }
    if let left = left as? String {
      guard let right = right as? String else { return false }
      return left.utf8.elementsEqual(right.utf8)
    }
    if let left = left as? NSNumber {
      guard let right = right as? NSNumber,
            (CFGetTypeID(left) == CFBooleanGetTypeID()) == (CFGetTypeID(right) == CFBooleanGetTypeID()) else { return false }
      return left.isEqual(to: right)
    }
    return left is NSNull && right is NSNull
  }
}
