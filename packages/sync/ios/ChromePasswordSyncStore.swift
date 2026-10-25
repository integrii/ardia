import ArdiaCore
import Foundation

@MainActor
final class ChromePasswordSyncStore: PasswordSyncStore {
  func read(profile: String, authorized: @escaping () -> Bool, completion: @escaping ([PasswordSyncLogin]?) -> Void) {
    guard authorized() else { return completion(nil) }
    ArdiaCoreServices.passwordsForSync(profile: profile, authorized: authorized) { rows in
      guard authorized(), let rows else { return completion(nil) }
      var logins: [PasswordSyncLogin] = []
      for row in rows {
        guard let origin = row["origin"] as? String, let username = row["username"] as? String,
              let password = row["password"] as? String else { return completion(nil) }
        let created: Double?
        if row["created"] is NSNull { created = nil }
        else if let value = row["created"] as? Double, value.isFinite { created = value }
        else { return completion(nil) }
        logins.append(PasswordSyncLogin(origin: origin, username: username, password: password, created: created))
      }
      completion(authorized() ? logins : nil)
    }
  }

  func compareAndSet(profile: String, key: String, expected: PasswordSyncLogin?, desired: PasswordSyncLogin?,
                     authorized: @escaping () -> Bool, completion: @escaping (Bool?) -> Void) {
    guard authorized(), key.hasPrefix("pw:"), let newline = key.firstIndex(of: "\n"),
          expected == nil || expected?.key?.utf8.elementsEqual(key.utf8) == true,
          desired == nil || desired?.key?.utf8.elementsEqual(key.utf8) == true else { return completion(false) }
    let origin = String(key[key.index(key.startIndex, offsetBy: 3)..<newline])
    let username = String(key[key.index(after: newline)...])
    ArdiaCoreServices.compareAndSetPasswordForSync(profile: profile, origin: origin, username: username,
                                                 expectedPassword: expected?.password, desiredPassword: desired?.password,
                                                 authorized: authorized) { success in
      completion(authorized() && success)
    }
  }
}
