import AppKit
import XCTest
@testable import ArdiaSyncCore

final class RecoveryProtectionTests: XCTestCase {
  final class Authentication: DeviceOwnerAuthenticating {
    var replies: [(Bool) -> Void] = []
    var cancellations = 0
    func evaluate(reason: String, completion: @escaping (Bool) -> Void) { replies.append(completion) }
    func cancel() { cancellations += 1 }
  }

  func testCancellationRevocationAndKeyReplacementDenyLateAuthentication() {
    let auth = Authentication()
    let access = DeviceOwnerAuthorization(authentication: auth, observeSystem: false)
    var binding: String? = "first-key"
    var grants: [DeviceOwnerAuthorization.Grant?] = []
    access.authorize(binding: "first-key", reason: "test", currentBinding: { binding }) { grants.append($0) }
    auth.replies[0](false)
    XCTAssertNil(grants[0])
    access.authorize(binding: "first-key", reason: "test", currentBinding: { binding }) { grants.append($0) }
    access.revoke()
    auth.replies[1](true)
    XCTAssertNil(grants[1])
    access.authorize(binding: "first-key", reason: "test", currentBinding: { binding }) { grants.append($0) }
    binding = "second-key"
    auth.replies[2](true)
    XCTAssertNil(grants[2])
  }

  func testExpiryAndPurposeIsolation() throws {
    let auth = Authentication()
    var now: TimeInterval = 100
    let access = DeviceOwnerAuthorization(authentication: auth, now: { now }, observeSystem: false)
    var grant: DeviceOwnerAuthorization.Grant?
    access.authorize(binding: "key", reason: "test", currentBinding: { "key" }) { grant = $0 }
    auth.replies[0](true)
    let issued = try XCTUnwrap(grant)
    XCTAssertTrue(access.validate(issued, binding: "key"))
    let otherAuth = Authentication()
    let other = DeviceOwnerAuthorization(authentication: otherAuth, observeSystem: false)
    var otherGrant: DeviceOwnerAuthorization.Grant?
    other.authorize(binding: "key", reason: "test", currentBinding: { "key" }) { otherGrant = $0 }
    otherAuth.replies[0](true)
    XCTAssertFalse(other.validate(issued, binding: "key"))
    XCTAssertTrue(other.validate(try XCTUnwrap(otherGrant), binding: "key"))
    now = 160
    XCTAssertFalse(access.validate(issued, binding: "key"))
    XCTAssertFalse(access.validate(issued, binding: "key"))
  }

  func testStaleGrantCannotRevokeNewGrant() throws {
    let auth = Authentication()
    let access = DeviceOwnerAuthorization(authentication: auth, observeSystem: false)
    var old: DeviceOwnerAuthorization.Grant?
    var fresh: DeviceOwnerAuthorization.Grant?
    access.authorize(binding: "key", reason: "test", currentBinding: { "key" }) { old = $0 }
    auth.replies[0](true)
    access.revoke()
    access.authorize(binding: "key", reason: "test", currentBinding: { "key" }) { fresh = $0 }
    auth.replies[1](true)
    XCTAssertFalse(access.validate(try XCTUnwrap(old), binding: "key"))
    XCTAssertTrue(access.validate(try XCTUnwrap(fresh), binding: "key"))
  }

  func testClipboardCleanupOnlyClearsOurWrite() {
    let pasteboard = NSPasteboard.withUniqueName()
    defer { pasteboard.releaseGlobally() }
    let clipboard = RecoveryClipboard(pasteboard: pasteboard)
    var cleanups = 0
    clipboard.write("mock phrase" as NSString) { cleanups += 1 }
    XCTAssertTrue(pasteboard.types?.contains(RecoveryClipboard.concealed) == true)
    XCTAssertTrue(pasteboard.types?.contains(RecoveryClipboard.transient) == true)
    clipboard.clear()
    XCTAssertNil(pasteboard.string(forType: .string))
    XCTAssertEqual(cleanups, 1)
    clipboard.write("mock phrase" as NSString) { cleanups += 1 }
    pasteboard.clearContents()
    pasteboard.setString("user copied this", forType: .string)
    clipboard.clear()
    XCTAssertEqual(pasteboard.string(forType: .string), "user copied this")
    XCTAssertEqual(cleanups, 2)
  }

  func testScheduledClipboardAndExportExpiry() throws {
    let pasteboard = NSPasteboard.withUniqueName()
    defer { pasteboard.releaseGlobally() }
    let clipboard = RecoveryClipboard(pasteboard: pasteboard, lifetime: 0.01)
    clipboard.write("mock phrase" as NSString)
    let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: base) }
    let exports = try RecoveryExports(base: base, lifetime: 0.01)
    let file = try exports.create(Data("mock kit".utf8))
    RunLoop.main.run(until: Date().addingTimeInterval(0.05))
    XCTAssertNil(pasteboard.string(forType: .string))
    XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
  }

  func testPrivateExportsCleanupAndSymlinkDefense() throws {
    let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: base) }
    let exports = try RecoveryExports(base: base)
    let first = try exports.create(Data("mock kit".utf8))
    let second = try exports.create(Data("another mock kit".utf8))
    XCTAssertNotEqual(first, second)
    XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: first.path)[.posixPermissions] as? Int, 0o600)
    XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: first.deletingLastPathComponent().path)[.posixPermissions] as? Int, 0o700)
    let intentional = base.appendingPathComponent("saved.pdf")
    try Data("keep".utf8).write(to: intentional)
    exports.remove(intentional)
    XCTAssertTrue(FileManager.default.fileExists(atPath: intentional.path))
    exports.remove(first)
    XCTAssertFalse(FileManager.default.fileExists(atPath: first.path))
    XCTAssertTrue(FileManager.default.fileExists(atPath: second.path))
    let outside = base.appendingPathComponent("outside", isDirectory: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
    let protected = outside.appendingPathComponent(RecoveryExports.fileName)
    try Data("keep".utf8).write(to: protected)
    let root = base.appendingPathComponent(RecoveryExports.directoryName, isDirectory: true)
    try FileManager.default.createSymbolicLink(at: root.appendingPathComponent(UUID().uuidString), withDestinationURL: outside)
    let legacy = base.appendingPathComponent("Ardia Recovery Kit")
    try FileManager.default.createSymbolicLink(at: legacy, withDestinationURL: outside)
    let next = try RecoveryExports(base: base)
    XCTAssertTrue(FileManager.default.fileExists(atPath: protected.path))
    next.clear()
    XCTAssertTrue(FileManager.default.fileExists(atPath: second.path))
    exports.clear()
    XCTAssertFalse(FileManager.default.fileExists(atPath: second.path))
  }

  func testSharingKeepsFileUntilConsumptionAndRejectsRevocation() {
    let url = URL(fileURLWithPath: "/mock-kit.pdf")
    let service = NSSharingService(title: "Mock", image: NSImage(size: NSSize(width: 1, height: 1)), alternateImage: nil) {}
    var finished = 0
    var allowed = true
    let consuming = RecoveryShare(url: url, authorized: { allowed }) { finished += 1 }
    consuming.sharingService(service, willShareItems: [])
    consuming.cancelUnconsumed()
    XCTAssertEqual(finished, 0)
    consuming.sharingService(service, didShareItems: [])
    XCTAssertEqual(finished, 1)
    consuming.sharingService(service, didShareItems: [])
    XCTAssertEqual(finished, 1)
    let revoked = RecoveryShare(url: url, authorized: { allowed }) { finished += 1 }
    allowed = false
    revoked.sharingService(service, willShareItems: [])
    XCTAssertEqual(finished, 2)
    let cancelled = RecoveryShare(url: url, authorized: { true }) { finished += 1 }
    cancelled.cancelUnconsumed()
    XCTAssertEqual(finished, 3)
  }
}
