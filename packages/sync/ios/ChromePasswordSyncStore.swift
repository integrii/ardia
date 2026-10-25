import ArdiaCore
import CoreFoundation
import Foundation

@MainActor
final class ChromePasswordSyncStore: PasswordSyncStore, PasswordSyncStoreLifecycle {
  private let keyState: ArdiaCorePasswordSyncKeyState
  private var authorization: ArdiaCorePasswordSyncAuthorization?
  private var requests: [UUID: ArdiaCorePasswordSyncRequest] = [:]

  init(keyState: ArdiaCorePasswordSyncKeyState) {
    self.keyState = keyState
  }

  func beginAuthorization(profiles: [String], expiresAt: TimeInterval, generation: UInt64) -> Bool {
    revokeAuthorization()
    authorization = ArdiaCorePasswordSyncAuthorization(profiles: profiles, expiresAt: expiresAt, keyState: keyState, generation: generation)
    return authorization != nil
  }

  func revokeAuthorization() {
    authorization?.revoke()
    authorization = nil
    cancelPendingRequests()
  }

  func cancelPendingRequests() {
    let pending = requests.values
    requests.removeAll()
    for request in pending { request.cancel() }
  }

  private func beginRequest(profile: String, expiresAt: TimeInterval) -> (UUID, ArdiaCorePasswordSyncRequest)? {
    guard let request = authorization?.request(profile: profile, expiresAt: expiresAt) else { return nil }
    let id = UUID()
    requests[id] = request
    return (id, request)
  }

  private func finishRequest(_ id: UUID) {
    requests.removeValue(forKey: id)?.cancel()
  }

  func read(profile: String, expiresAt: TimeInterval, authorized: @escaping () -> Bool, completion: @escaping ([PasswordSyncLogin]?) -> Void) {
    guard authorized(), let (id, request) = beginRequest(profile: profile, expiresAt: expiresAt) else { return completion(nil) }
    ArdiaCoreServices.passwordsForSync(profile: profile, request: request, authorized: authorized) { rows in
      MainActor.assumeIsolated {
        self.finishRequest(id)
        guard authorized(), let rows else { return completion(nil) }
        var logins: [PasswordSyncLogin] = []
        for row in rows {
          guard let origin = row["origin"] as? String, let username = row["username"] as? String,
                let password = row["password"] as? String else { return completion(nil) }
          let created: Double?
          if row["created"] is NSNull { created = nil }
          else if let value = row["created"] as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(),
                  value.doubleValue.isFinite, abs(value.doubleValue) <= 8_640_000_000_000_000 { created = value.doubleValue }
          else { return completion(nil) }
          logins.append(PasswordSyncLogin(origin: origin, username: username, password: password, created: created))
        }
        completion(authorized() ? logins : nil)
      }
    }
  }

  func compareAndSet(profile: String, key: String, expected: PasswordSyncLogin?, desired: PasswordSyncLogin?,
                     expiresAt: TimeInterval, authorized: @escaping () -> Bool, completion: @escaping (Bool?) -> Void) {
    guard authorized(), key.hasPrefix("pw:"), let newline = key.firstIndex(of: "\n"),
          expected == nil || expected?.key?.utf8.elementsEqual(key.utf8) == true,
          desired == nil || desired?.key?.utf8.elementsEqual(key.utf8) == true,
          desired?.created.map({ $0.isFinite && abs($0) <= 8_640_000_000_000_000 }) ?? true else { return completion(false) }
    let origin = String(key[key.index(key.startIndex, offsetBy: 3)..<newline])
    let username = String(key[key.index(after: newline)...])
    guard let (id, request) = beginRequest(profile: profile, expiresAt: expiresAt) else { return completion(nil) }
    ArdiaCoreServices.compareAndSetPasswordForSync(profile: profile, origin: origin, username: username,
                                                 expectedPassword: expected?.password, desiredPassword: desired?.password,
                                                 desiredCreated: desired?.created.map { NSNumber(value: $0) }, request: request,
                                                 authorized: authorized) { status in
      MainActor.assumeIsolated {
        self.finishRequest(id)
        switch status {
        case .committed: completion(true)
        case .conflict: completion(false)
        default: completion(nil)
        }
      }
    }
  }
}
