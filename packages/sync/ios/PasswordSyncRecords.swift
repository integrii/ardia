import Foundation

@MainActor
struct PasswordSyncRecords: PasswordSyncCodec {
  private let records: PasswordRecords
  private let chain: String

  init(keys: SyncKeys) {
    records = PasswordRecords(keys: keys)
    chain = keys.chainTag
  }

  func seal(_ login: PasswordSyncLogin, key: String, binding: PasswordSyncBinding) throws -> PasswordSyncEnvelope {
    guard binding.chain == chain, let newline = key.firstIndex(of: "\n") else { throw PasswordRecords.Failure.format }
    let origin = String(key[key.index(key.startIndex, offsetBy: 3)..<newline])
    let credentials = PasswordRecords.Credentials(origin: origin, username: login.username, password: login.password, created: login.created)
    let value = try records.seal(credentials, scope: binding.scope, recordKey: key)
    guard let envelope = PasswordSyncEnvelope(value.json) else { throw PasswordRecords.Failure.format }
    return envelope
  }

  func open(_ value: PasswordSyncEnvelope, key: String, binding: PasswordSyncBinding) throws -> PasswordSyncLogin {
    guard binding.chain == chain else { throw PasswordRecords.Failure.authentication }
    let credentials = try records.open(.init(sealed: value.sealed, fingerprint: value.fingerprint), scope: binding.scope, recordKey: key)
    return PasswordSyncLogin(origin: credentials.origin, username: credentials.username, password: credentials.password, created: credentials.created)
  }
}
