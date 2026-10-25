import Foundation

final class GrantClockAuthentication: DeviceOwnerAuthenticating {
  var grantedAt: TimeInterval?
  var allowed = true
  var calls = 0

  func evaluate(reason: String, completion: @escaping (Bool) -> Void) {
    preconditionFailure("Grant-aware authentication must preserve the native callback timestamp")
  }

  func evaluateGrant(reason: String, completion: @escaping (Bool, TimeInterval?) -> Void) {
    calls += 1
    completion(allowed, grantedAt)
  }

  func cancel() {}
}

@main
struct PasswordSyncGrantExpiryChecks {
  @MainActor
  static func main() {
    let authentication = GrantClockAuthentication()
    authentication.grantedAt = 980
    var now: TimeInterval = 1000
    let authorization = DeviceOwnerAuthorization(authentication: authentication, lifetime: 60, now: { now }, observeSystem: false)
    var first: DeviceOwnerAuthorization.Grant?
    authorization.authorize(binding: "fixture", reason: "fixture", currentBinding: { "fixture" }) { first = $0 }
    precondition(first?.expiresAt == 1040)
    now = 1039.999
    var cached: DeviceOwnerAuthorization.Grant?
    authorization.authorize(binding: "fixture", reason: "fixture", currentBinding: { "fixture" }) { cached = $0 }
    precondition(cached == first && cached?.expiresAt == 1040 && authentication.calls == 1)
    now = 1040
    precondition(!authorization.validate(first!, binding: "fixture"))
    authentication.grantedAt = 1940
    now = 2000
    var expired: DeviceOwnerAuthorization.Grant?
    authorization.authorize(binding: "fixture", reason: "fixture", currentBinding: { "fixture" }) { expired = $0 }
    precondition(expired == nil && authentication.calls == 2)
    authentication.grantedAt = 2000
    authentication.allowed = false
    authorization.authorize(binding: "fixture", reason: "fixture", currentBinding: { "fixture" }) { expired = $0 }
    precondition(expired == nil && authentication.calls == 3)
    precondition(ProcessInfo.processInfo.environment["ARDIA_BACKGROUND"] == "1")
    let background = DeviceOwnerAuthorization(observeSystem: false)
    var backgroundGrant: DeviceOwnerAuthorization.Grant?
    background.authorize(binding: "fixture", reason: "fixture", currentBinding: { "fixture" }) { backgroundGrant = $0 }
    precondition(backgroundGrant == nil)
    print("Production grant expiry: original native callback uptime retained; cached grant cannot extend expiry; exact expiry and delayed-main expired grant denied; authentication failure denied")
  }
}
