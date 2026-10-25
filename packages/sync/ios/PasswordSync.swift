import Foundation

struct PasswordSyncBinding: Equatable {
  let chain: String
  let folder: String
  let scope: String
  let profile: String

  static func == (lhs: Self, rhs: Self) -> Bool {
    lhs.chain.utf8.elementsEqual(rhs.chain.utf8) && lhs.folder.utf8.elementsEqual(rhs.folder.utf8)
      && lhs.scope.utf8.elementsEqual(rhs.scope.utf8) && lhs.profile.utf8.elementsEqual(rhs.profile.utf8)
  }
}

struct PasswordSyncLogin: Equatable {
  let origin: String
  let username: String
  let password: String
  let created: Double?

  var key: String? {
    let realm = origin.hasSuffix("/") ? String(origin.dropLast()) : origin
    guard realm.range(of: #"^https?://[^/\s]+$"#, options: .regularExpression) != nil else { return nil }
    return "pw:\(realm)\n\(username)"
  }

  static func == (lhs: Self, rhs: Self) -> Bool {
    lhs.origin.utf8.elementsEqual(rhs.origin.utf8) && lhs.username.utf8.elementsEqual(rhs.username.utf8)
      && lhs.password.utf8.elementsEqual(rhs.password.utf8) && lhs.created == rhs.created
  }
}

struct PasswordSyncEnvelope {
  let sealed: String
  let fingerprint: String

  init?(_ value: Any) {
    guard let value = value as? [String: Any], Set(value.keys) == ["version", "sealed", "fingerprint"],
          value["version"] as? Int == 2, let sealed = value["sealed"] as? String, !sealed.isEmpty,
          let fingerprint = value["fingerprint"] as? String, !fingerprint.isEmpty else { return nil }
    self.sealed = sealed
    self.fingerprint = fingerprint
  }

  var json: [String: Any] { ["version": 2, "sealed": sealed, "fingerprint": fingerprint] }
}

@MainActor
protocol PasswordSyncCodec {
  func seal(_ login: PasswordSyncLogin, key: String, binding: PasswordSyncBinding) throws -> PasswordSyncEnvelope
  func open(_ value: PasswordSyncEnvelope, key: String, binding: PasswordSyncBinding) throws -> PasswordSyncLogin
}

@MainActor
struct PasswordSyncAccess {
  let binding: PasswordSyncBinding
  let codec: any PasswordSyncCodec
  let authorized: () -> Bool
}

@MainActor
protocol PasswordSyncStore {
  func read(profile: String, authorized: @escaping () -> Bool, completion: @escaping ([PasswordSyncLogin]?) -> Void)
  func compareAndSet(profile: String, key: String, expected: PasswordSyncLogin?, desired: PasswordSyncLogin?,
                     authorized: @escaping () -> Bool, completion: @escaping (Bool?) -> Void)
}

@MainActor
final class PasswordSync {
  private let store: any PasswordSyncStore
  private let access: (PasswordSyncBinding) -> PasswordSyncAccess?
  private let timeout: TimeInterval
  private let settleChecks: Int
  private let settleNanoseconds: UInt64
  private var busy = false

  init(store: any PasswordSyncStore, timeout: TimeInterval = 10, settleChecks: Int = 20,
       settleNanoseconds: UInt64 = 250_000_000, access: @escaping (PasswordSyncBinding) -> PasswordSyncAccess?) {
    self.store = store
    self.access = access
    self.timeout = timeout
    self.settleChecks = settleChecks
    self.settleNanoseconds = settleNanoseconds
  }

  func read(_ binding: PasswordSyncBinding) async -> [[String: Any]]? {
    guard let operation = begin(binding) else { return nil }
    defer { operation.active = false; busy = false }
    guard let logins = await snapshot(operation), operation.authorized() else { return nil }
    do {
      var records: [[String: Any]] = []
      for login in logins.values.sorted(by: { $0.key!.utf8.lexicographicallyPrecedes($1.key!.utf8) }) {
        let key = login.key!
        let envelope = try operation.access.codec.seal(login, key: key, binding: binding)
        records.append(["key": key, "value": envelope.json, "created": login.created.map { $0 as Any } ?? NSNull()])
      }
      return operation.authorized() ? records : nil
    } catch { return nil }
  }

  func apply(_ binding: PasswordSyncBinding, changes: [[String: Any]]) async -> Bool {
    guard let operation = begin(binding) else { return false }
    defer { operation.active = false; busy = false }
    let decoded: [(key: String, desired: PasswordSyncLogin?, base: PasswordSyncLogin?)]
    do {
      var seen = Set<Data>()
      decoded = try changes.map { change in
        guard Set(change.keys) == ["key", "desired", "base"], let key = change["key"] as? String,
              key.hasPrefix("pw:"), key.contains("\n"), seen.insert(Data(key.utf8)).inserted else { throw Invalid.record }
        return (key, try open(change["desired"]!, key: key, operation: operation), try open(change["base"]!, key: key, operation: operation))
      }
    } catch { return false }
    guard let local = await snapshot(operation), operation.authorized() else { return false }
    guard decoded.allSatisfy({ same(local[Data($0.key.utf8)], $0.desired) || same(local[Data($0.key.utf8)], $0.base) }) else { return false }
    for change in decoded {
      let have = local[Data(change.key.utf8)]
      if same(have, change.desired) { continue }
      guard same(have, change.base), operation.authorized() else { return false }
      let applied: Bool? = await call(operation) { authorized, completion in
        self.store.compareAndSet(profile: binding.profile, key: change.key, expected: have, desired: change.desired,
                                 authorized: authorized, completion: completion)
      }
      guard applied == true, operation.authorized() else { return false }
    }
    for attempt in 0..<settleChecks {
      guard let current = await snapshot(operation), operation.authorized() else { return false }
      if decoded.allSatisfy({ same(current[Data($0.key.utf8)], $0.desired) }) { return true }
      if attempt + 1 < settleChecks {
        do { try await Task.sleep(nanoseconds: settleNanoseconds) } catch { return false }
        guard operation.authorized() else { return false }
      }
    }
    return false
  }

  private enum Invalid: Error { case record }

  private func begin(_ binding: PasswordSyncBinding) -> Operation? {
    guard !busy, !binding.chain.isEmpty, !binding.folder.isEmpty, !binding.scope.isEmpty,
          !binding.profile.contains("/"), !binding.profile.contains("\\"), !binding.profile.hasPrefix("incognito:"),
          let access = access(binding), access.binding == binding, access.authorized() else { return nil }
    busy = true
    return Operation(access: access, deadline: ProcessInfo.processInfo.systemUptime + timeout)
  }

  private func open(_ value: Any, key: String, operation: Operation) throws -> PasswordSyncLogin? {
    if value is NSNull {
      let parts = key.dropFirst(3).split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
      guard parts.count == 2, PasswordSyncLogin(origin: String(parts[0]), username: String(parts[1]), password: "", created: 0).key?.utf8.elementsEqual(key.utf8) == true else { throw Invalid.record }
      return nil
    }
    guard let envelope = PasswordSyncEnvelope(value), operation.authorized() else { throw Invalid.record }
    let login = try operation.access.codec.open(envelope, key: key, binding: operation.access.binding)
    guard login.key?.utf8.elementsEqual(key.utf8) == true else { throw Invalid.record }
    return login
  }

  private func same(_ a: PasswordSyncLogin?, _ b: PasswordSyncLogin?) -> Bool {
    guard let a, let b else { return a == nil && b == nil }
    guard let aKey = a.key, let bKey = b.key else { return false }
    return aKey.utf8.elementsEqual(bKey.utf8) && a.password.utf8.elementsEqual(b.password.utf8)
  }

  private func snapshot(_ operation: Operation) async -> [Data: PasswordSyncLogin]? {
    let rows: [PasswordSyncLogin]? = await call(operation) { authorized, completion in
      self.store.read(profile: operation.access.binding.profile, authorized: authorized, completion: completion)
    }
    guard let rows, operation.authorized() else { return nil }
    var result: [Data: PasswordSyncLogin] = [:]
    for login in rows {
      guard let key = login.key else { continue }
      let identity = Data(key.utf8)
      if result[identity] != nil { return nil }
      result[identity] = login
    }
    return result
  }

  private func call<T>(_ operation: Operation, _ body: (@escaping () -> Bool, @escaping (T?) -> Void) -> Void) async -> T? {
    guard operation.authorized() else { return nil }
    return await withCheckedContinuation { continuation in
      let request = Request(continuation: continuation, operation: operation)
      DispatchQueue.main.asyncAfter(deadline: .now() + max(0, operation.deadline - ProcessInfo.processInfo.systemUptime)) {
        request.finish(nil)
      }
      body({ operation.authorized() && request.pending }, { request.finish($0) })
    }
  }

  @MainActor
  private final class Operation {
    let access: PasswordSyncAccess
    let deadline: TimeInterval
    var active = true

    init(access: PasswordSyncAccess, deadline: TimeInterval) {
      self.access = access
      self.deadline = deadline
    }

    func authorized() -> Bool {
      active && ProcessInfo.processInfo.systemUptime < deadline && access.authorized()
    }
  }

  @MainActor
  private final class Request<T> {
    private var continuation: CheckedContinuation<T?, Never>?
    private let operation: Operation
    var pending: Bool { continuation != nil }

    init(continuation: CheckedContinuation<T?, Never>, operation: Operation) {
      self.continuation = continuation
      self.operation = operation
    }

    func finish(_ value: T?) {
      guard let continuation else { return }
      self.continuation = nil
      continuation.resume(returning: operation.authorized() ? value : nil)
    }
  }
}
