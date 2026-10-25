import AppKit
import Foundation

final class FakeAuthentication: DeviceOwnerAuthenticating {
  var callbacks: [(Bool) -> Void] = []
  func evaluate(reason: String, completion: @escaping (Bool) -> Void) { callbacks.append(completion) }
  func cancel() {}
}

var checks = 0
func check(_ condition: @autoclosure () -> Bool, _ message: String) {
  precondition(condition(), message)
  checks += 1
}

let fake = FakeAuthentication()
var now: TimeInterval = 10
var identity: String? = "mock-key-v1"
let access = DeviceOwnerAuthorization(authentication: fake, now: { now }, observeSystem: false)
var grant: DeviceOwnerAuthorization.Grant?
var completions = 0
func authorize() {
  access.authorize(binding: identity!, reason: "mock secrets", currentBinding: { identity }) {
    grant = $0
    completions += 1
  }
}
authorize()
check(grant == nil && fake.callbacks.count == 1, "no grant before authentication")
fake.callbacks[0](false)
check(grant == nil && completions == 1, "cancel is denied")
authorize()
access.revoke()
fake.callbacks[1](true)
check(grant == nil, "late completion after sheet dismissal denied")
authorize()
identity = "mock-key-v2"
fake.callbacks[2](true)
check(grant == nil, "late completion after key change denied")
authorize()
fake.callbacks[3](true)
let issued = grant!
check(access.validate(issued, binding: identity), "fresh grant valid")
authorize()
check(fake.callbacks.count == 4, "bounded session reuses authorization")
let passwordFake = FakeAuthentication()
let passwords = DeviceOwnerAuthorization(authentication: passwordFake, observeSystem: false)
var passwordGrant: DeviceOwnerAuthorization.Grant?
passwords.authorize(binding: identity!, reason: "password mock", currentBinding: { identity }) { passwordGrant = $0 }
passwordFake.callbacks[0](true)
check(!passwords.validate(issued, binding: identity), "recovery grants rejected by password instance")
check(passwords.validate(passwordGrant!, binding: identity), "foreign candidate cannot revoke current grant")
now = 70
check(!access.validate(issued, binding: identity), "grant expires at sixty seconds")
authorize()
access.revoke(.system)
fake.callbacks[4](true)
check(grant == nil, "sleep or lock invalidates pending authentication")
authorize()
fake.callbacks[5](true)
let replaced = grant!
check(!access.validate(issued, binding: identity), "stale grant is rejected")
check(access.validate(replaced, binding: identity), "stale candidate cannot revoke newer grant")
identity = nil
check(!access.validate(replaced, binding: identity), "forget invalidates granted authorization")

setenv("ARDIA_BACKGROUND", "1", 1)
let local = LocalDeviceOwnerAuthentication()
var hiddenAllowed: Bool?
local.evaluate(reason: "must not prompt") { hiddenAllowed = $0 }
check(hiddenAllowed == false, "background denies without native prompt")

let pasteboard = NSPasteboard.withUniqueName()
defer { pasteboard.releaseGlobally() }
let clipboard = RecoveryClipboard(pasteboard: pasteboard, lifetime: 0.03)
var cleaned = 0
clipboard.write("mock recovery phrase" as NSString) { cleaned += 1 }
check(pasteboard.string(forType: .string) == "mock recovery phrase", "private pasteboard receives mock secret")
check(pasteboard.types?.contains(RecoveryClipboard.concealed) == true, "confidential clipboard marker")
check(pasteboard.types?.contains(RecoveryClipboard.transient) == true, "transient clipboard marker")
RunLoop.main.run(until: Date().addingTimeInterval(0.08))
check(pasteboard.string(forType: .string) == nil && cleaned == 1, "clipboard expiry clears owned write")
clipboard.write("second mock" as NSString) { cleaned += 1 }
pasteboard.clearContents()
pasteboard.setString("user replacement", forType: .string)
RunLoop.main.run(until: Date().addingTimeInterval(0.08))
check(pasteboard.string(forType: .string) == "user replacement" && cleaned == 2, "expiry preserves replacement clipboard")
clipboard.write("third mock" as NSString)
clipboard.clear()
check(pasteboard.string(forType: .string) == nil, "lock cleanup clears owned clipboard")

let base = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: base) }
let exports = try RecoveryExports(base: base)
let first = try exports.create(Data("mock kit one".utf8))
let second = try exports.create(Data("mock kit two".utf8))
check(first != second, "export paths unique")
let filePermissions = try FileManager.default.attributesOfItem(atPath: first.path)[.posixPermissions] as? Int
let dirPermissions = try FileManager.default.attributesOfItem(atPath: first.deletingLastPathComponent().path)[.posixPermissions] as? Int
check(filePermissions == 0o600 && dirPermissions == 0o700, "export permissions private")
exports.remove(first)
check(!FileManager.default.fileExists(atPath: first.path) && FileManager.default.fileExists(atPath: second.path), "consumption removes only its export")
let saved = base.appendingPathComponent("intentional.pdf")
try Data("intentional save".utf8).write(to: saved)
exports.remove(saved)
check(FileManager.default.fileExists(atPath: saved.path), "intentional save untouched")
let outside = base.appendingPathComponent("outside", isDirectory: true)
try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
let protected = outside.appendingPathComponent(RecoveryExports.fileName)
try Data("keep outside managed directory".utf8).write(to: protected)
let root = base.appendingPathComponent(RecoveryExports.directoryName, isDirectory: true)
try FileManager.default.createSymbolicLink(at: root.appendingPathComponent(UUID().uuidString), withDestinationURL: outside)
let legacy = base.appendingPathComponent("Ardia Recovery Kit")
try FileManager.default.createSymbolicLink(at: legacy, withDestinationURL: outside)
let restarted = try RecoveryExports(base: base)
restarted.clear()
check(FileManager.default.fileExists(atPath: protected.path), "cleanup never traverses symlink directories")
check(FileManager.default.fileExists(atPath: second.path), "new process cleanup preserves active other export")
try FileManager.default.removeItem(at: legacy)
try FileManager.default.createDirectory(at: legacy, withIntermediateDirectories: false)
let legacyPDF = legacy.appendingPathComponent(RecoveryExports.fileName)
try Data("old mock kit".utf8).write(to: legacyPDF)
let stale = root.appendingPathComponent(UUID().uuidString, isDirectory: true)
try FileManager.default.createDirectory(at: stale, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
try Data("abandoned mock kit".utf8).write(to: stale.appendingPathComponent(RecoveryExports.fileName))
try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(-600)], ofItemAtPath: stale.path)
let recovered = try RecoveryExports(base: base)
check(!FileManager.default.fileExists(atPath: stale.path), "startup cleans expired crashed exports")
check(!FileManager.default.fileExists(atPath: legacyPDF.path), "startup cleans exact legacy kit")
exports.clear()
check(!FileManager.default.fileExists(atPath: second.path), "teardown clears remaining owned exports")
let expiringBase = base.appendingPathComponent("expiry", isDirectory: true)
try FileManager.default.createDirectory(at: expiringBase, withIntermediateDirectories: false)
let expiring = try RecoveryExports(base: expiringBase, lifetime: 0.03)
let expires = try expiring.create(Data("mock expiring kit".utf8))
RunLoop.main.run(until: Date().addingTimeInterval(0.08))
check(!FileManager.default.fileExists(atPath: expires.path), "unconsumed export expires")
let symlinkBase = base.appendingPathComponent("symlink", isDirectory: true)
try FileManager.default.createDirectory(at: symlinkBase, withIntermediateDirectories: false)
try FileManager.default.createSymbolicLink(at: symlinkBase.appendingPathComponent(RecoveryExports.directoryName), withDestinationURL: outside)
do {
  _ = try RecoveryExports(base: symlinkBase)
  preconditionFailure("symlink managed root accepted")
} catch { checks += 1 }
let service = NSSharingService(title: "Mock", image: NSImage(size: NSSize(width: 1, height: 1)), alternateImage: nil) {}
var shareFinishes = 0
var shareAllowed = true
let consuming = RecoveryShare(url: saved, authorized: { shareAllowed }) { shareFinishes += 1 }
consuming.sharingService(service, willShareItems: [])
consuming.cancelUnconsumed()
check(shareFinishes == 0, "chosen share is not cancelled during consumption")
consuming.sharingService(service, didShareItems: [])
check(shareFinishes == 1, "share consumption releases file")
consuming.sharingService(service, didShareItems: [])
check(shareFinishes == 1, "share cleanup exactly once")
let revoked = RecoveryShare(url: saved, authorized: { shareAllowed }) { shareFinishes += 1 }
shareAllowed = false
revoked.sharingService(service, willShareItems: [])
check(shareFinishes == 2, "share generation rechecked before consumption")
let cancelled = RecoveryShare(url: saved, authorized: { true }) { shareFinishes += 1 }
cancelled.cancelUnconsumed()
check(shareFinishes == 3, "unchosen share cleans up on invalidation")
print("PASS: \(checks) production recovery helper assertions; private pasteboard and mock secrets only")
