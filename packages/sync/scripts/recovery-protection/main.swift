import AppKit
import Foundation

final class Promise {
  var value: Any?
  var resolutions = 0
  var rejections = 0
  func resolve(_ value: Any?) { self.value = value; resolutions += 1 }
  func reject(_ code: String, _ message: String) { rejections += 1 }
}

enum RecoveryPhrase {
  static func words(for entropy: Data) -> [String] { ["synthetic-word"] }
}

struct RecoveryOperationState {
  var recoveryBinding: String? = "copy"
  func withRecoveryEntropy<T>(binding: String, operation: (Data) throws -> T) throws -> T {
    guard binding == recoveryBinding else { throw CocoaError(.fileReadNoPermission) }
    return try operation(Data("synthetic-entropy".utf8))
  }
}

final class RecoveryOperationFixture {
  var recoveryAuthorization: DeviceOwnerAuthorization?
  var state = RecoveryOperationState()
  var callbacks: [(DeviceOwnerAuthorization.Grant?, String?) -> Void] = []
  func authorizeRecovery(_ completion: @escaping (DeviceOwnerAuthorization.Grant?, String?) -> Void) { callbacks.append(completion) }
}

final class FakeAuthentication: DeviceOwnerAuthenticating {
  var callbacks: [(Bool) -> Void] = []
  var cancellations = 0
  func evaluate(reason: String, completion: @escaping (Bool) -> Void) { callbacks.append(completion) }
  func cancel() { cancellations += 1 }
}

func descriptorPath(_ descriptor: Int32) -> String? {
  var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
  guard fcntl(descriptor, F_GETPATH, &buffer) == 0 else { return nil }
  return String(cString: buffer)
}

if CommandLine.arguments.count == 4, CommandLine.arguments[1] == "--descriptor-child" {
  exit(descriptorPath(Int32(CommandLine.arguments[2])!) == CommandLine.arguments[3] ? 1 : 0)
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
let beforeDismissal = fake.cancellations
access.revoke()
check(fake.cancellations == beforeDismissal + 1, "dismissal cancels in-flight prompt")
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
let beforeSystem = fake.cancellations
access.revoke(.system)
check(fake.cancellations == beforeSystem + 1, "system invalidation cancels in-flight prompt")
fake.callbacks[4](true)
check(grant == nil, "sleep or lock invalidates pending authentication")
authorize()
fake.callbacks[5](true)
let replaced = grant!
check(!access.validate(issued, binding: identity), "stale grant is rejected")
check(access.validate(replaced, binding: identity), "stale candidate cannot revoke newer grant")
identity = nil
check(!access.validate(replaced, binding: identity), "forget invalidates granted authorization")

let copyFake = FakeAuthentication()
let copyAccess = DeviceOwnerAuthorization(authentication: copyFake, observeSystem: false)
var oldCopyGrant: DeviceOwnerAuthorization.Grant?
var lateCopyGrant: DeviceOwnerAuthorization.Grant?
var newCopyGrant: DeviceOwnerAuthorization.Grant?
copyAccess.authorize(binding: "copy", reason: "old copy", currentBinding: { "copy" }) { oldCopyGrant = $0 }
copyFake.callbacks[0](true)
copyAccess.revoke()
copyAccess.authorize(binding: "copy", reason: "invalidated copy", currentBinding: { "copy" }) { lateCopyGrant = $0 }
copyAccess.revoke()
copyAccess.authorize(binding: "copy", reason: "new session", currentBinding: { "copy" }) { newCopyGrant = $0 }
copyFake.callbacks[2](true)
copyFake.callbacks[1](true)
check(lateCopyGrant == nil, "late copy authentication cannot issue old grant")
check(copyAccess.validate(newCopyGrant!, binding: "copy"), "late copy callback preserves newer session")
if copyAccess.validate(oldCopyGrant!, binding: "copy") { copyAccess.revoke() }
check(copyAccess.validate(newCopyGrant!, binding: "copy"), "late copy cleanup cannot revoke newer session")
if copyAccess.validate(newCopyGrant!, binding: "copy") { copyAccess.revoke() }
check(!copyAccess.validate(newCopyGrant!, binding: "copy"), "one-shot copy consumes its own grant")
let bridge = RecoveryOperationFixture()
bridge.recoveryAuthorization = copyAccess
copyAccess.authorize(binding: "copy", reason: "bridge session", currentBinding: { "copy" }) { newCopyGrant = $0 }
copyFake.callbacks[3](true)
let latePromise = Promise()
var bridgeCopies = 0
bridge.recoveryOperation(latePromise, endAuthorization: true) { _ in bridgeCopies += 1; return true }
bridge.callbacks.removeFirst()(oldCopyGrant, "copy")
check(latePromise.resolutions == 1 && latePromise.value == nil && bridgeCopies == 0, "production recovery operation denies late copy before reading words")
check(copyAccess.validate(newCopyGrant!, binding: "copy"), "production late copy leaves newer authorization valid")
let sheetPromise = Promise()
bridge.recoveryOperation(sheetPromise) { _ in true }
bridge.callbacks.removeFirst()(newCopyGrant, "copy")
check(sheetPromise.value as? Bool == true && copyAccess.validate(newCopyGrant!, binding: "copy"), "normal sheet copy preserves reusable grant")
let failedPromise = Promise()
bridge.recoveryOperation(failedPromise, endAuthorization: true) { _ in false }
bridge.callbacks.removeFirst()(newCopyGrant, "copy")
check(failedPromise.value as? Bool == false, "production recovery operation propagates clipboard failure")
check(!copyAccess.validate(newCopyGrant!, binding: "copy"), "one-shot failed copy ends only its captured grant")
copyAccess.authorize(binding: "copy", reason: "throwing bridge copy", currentBinding: { "copy" }) { newCopyGrant = $0 }
copyFake.callbacks[4](true)
let throwingPromise = Promise()
bridge.recoveryOperation(throwingPromise, endAuthorization: true) { _ -> Bool in throw CocoaError(.fileWriteUnknown) }
bridge.callbacks.removeFirst()(newCopyGrant, "copy")
check(throwingPromise.rejections == 1 && throwingPromise.resolutions == 0, "production recovery operation rejects failed generation")
check(!copyAccess.validate(newCopyGrant!, binding: "copy"), "throwing one-shot copy revokes its own grant")
copyAccess.authorize(binding: "copy", reason: "successful bridge copy", currentBinding: { "copy" }) { newCopyGrant = $0 }
copyFake.callbacks[5](true)
let successfulPromise = Promise()
bridge.recoveryOperation(successfulPromise, endAuthorization: true) { _ in true }
bridge.callbacks.removeFirst()(newCopyGrant, "copy")
check(successfulPromise.value as? Bool == true && !copyAccess.validate(newCopyGrant!, binding: "copy"), "successful one-shot copy consumes captured grant")
copyAccess.authorize(binding: "copy", reason: "reentrant bridge copy", currentBinding: { "copy" }) { newCopyGrant = $0 }
copyFake.callbacks[6](true)
let reentrantGrant = newCopyGrant
let reentrantPromise = Promise()
bridge.recoveryOperation(reentrantPromise, endAuthorization: true) { _ in
  copyAccess.revoke()
  copyAccess.authorize(binding: "copy", reason: "newer reentrant session", currentBinding: { "copy" }) { newCopyGrant = $0 }
  copyFake.callbacks[7](true)
  return true
}
bridge.callbacks.removeFirst()(reentrantGrant, "copy")
check(reentrantPromise.value as? Bool == true && copyAccess.validate(newCopyGrant!, binding: "copy"), "production copy completion cannot revoke a newer reentrant grant")

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
var failedCleanup = 0
let failedClipboard = RecoveryClipboard(pasteboard: pasteboard, writeObjects: { _ in false })
check(!failedClipboard.write("uncopied mock" as NSString) { failedCleanup += 1 }, "failed pasteboard write reports false")
check(pasteboard.types?.contains(RecoveryClipboard.concealed) != true, "failed write adds no success markers")
check(failedCleanup == 1, "failed write immediately cleans temporary export")
failedClipboard.clear()
check(failedCleanup == 1, "failed write cleanup runs once")
var replacementFailureCleanup = 0
let replacementFailure = RecoveryClipboard(pasteboard: pasteboard, lifetime: 0.03, writeObjects: { _ in
  pasteboard.clearContents()
  pasteboard.setString("newer-user-copy", forType: .string)
  return false
})
check(!replacementFailure.write("uncopied recovery mock" as NSString) { replacementFailureCleanup += 1 }, "replacement during failed write still reports failure")
check(pasteboard.string(forType: .string) == "newer-user-copy", "failed write preserves newer user clipboard contents")
check(pasteboard.types?.contains(RecoveryClipboard.concealed) != true && pasteboard.types?.contains(RecoveryClipboard.transient) != true, "failed write does not attach advisory markers to newer contents")
check(replacementFailureCleanup == 1, "replacement during failed write immediately cleans export")
replacementFailure.clear()
RunLoop.main.run(until: Date().addingTimeInterval(0.08))
check(pasteboard.string(forType: .string) == "newer-user-copy" && replacementFailureCleanup == 1, "failed write teardown preserves replacement and cleanup runs once")
var foreignOwnerCleanup = 0
let foreignToken = UUID().uuidString
let foreignOwnerFailure = RecoveryClipboard(pasteboard: pasteboard, writeObjects: { _ in
  let newer = NSPasteboardItem()
  newer.setString("newer independently owned copy", forType: .string)
  newer.setString(foreignToken, forType: RecoveryClipboard.ownership)
  pasteboard.clearContents()
  pasteboard.writeObjects([newer])
  return false
})
check(!foreignOwnerFailure.write("failed older recovery copy" as NSString) { foreignOwnerCleanup += 1 }, "foreign owner replacement still reports original failure")
check(pasteboard.string(forType: .string) == "newer independently owned copy" && pasteboard.string(forType: RecoveryClipboard.ownership) == foreignToken, "ownership marker presence cannot authorize clearing another token")
foreignOwnerFailure.clear()
check(foreignOwnerCleanup == 1 && pasteboard.string(forType: .string) == "newer independently owned copy", "foreign owner replacement survives teardown and cleanup runs once")
var partialFailureCleanup = 0
var partialWritten = false
var partialItemTagged = false
let partialFailure = RecoveryClipboard(pasteboard: pasteboard, lifetime: 0.03, writeObjects: { objects in
  if let item = objects.first as? NSPasteboardItem {
    partialItemTagged = objects.count == 1 && item.string(forType: .string) == "partially written recovery mock"
      && item.types.contains(RecoveryClipboard.concealed) && item.types.contains(RecoveryClipboard.transient)
      && item.string(forType: RecoveryClipboard.ownership)?.isEmpty == false
  }
  partialWritten = pasteboard.writeObjects(objects)
  return false
})
check(!partialFailure.write("partially written recovery mock" as NSString) { partialFailureCleanup += 1 }, "partial owned write reports failure")
check(partialWritten && partialItemTagged, "payload and advisory markers are written together in one item")
check(pasteboard.string(forType: .string) == nil, "partial owned failed write is wiped immediately")
check(partialFailureCleanup == 1, "partial owned failed write immediately cleans export")
partialFailure.clear()
RunLoop.main.run(until: Date().addingTimeInterval(0.08))
check(partialFailureCleanup == 1 && pasteboard.string(forType: .string) == nil, "partial failed write leaves no indefinite secret or repeated cleanup")
var replacementSuccessCleanup = 0
let replacementSuccess = RecoveryClipboard(pasteboard: pasteboard, lifetime: 0.03, writeObjects: { objects in
  let written = pasteboard.writeObjects(objects)
  pasteboard.clearContents()
  pasteboard.setString("newer-user-copy-after-success", forType: .string)
  return written
})
check(replacementSuccess.write("successfully written recovery mock" as NSString) { replacementSuccessCleanup += 1 }, "successful superseded write reports successful serialization")
check(pasteboard.string(forType: .string) == "newer-user-copy-after-success", "successful write preserves reentrant user replacement")
check(pasteboard.types?.contains(RecoveryClipboard.concealed) != true && pasteboard.types?.contains(RecoveryClipboard.transient) != true, "successful write does not attach markers to reentrant replacement")
check(replacementSuccessCleanup == 1, "superseded successful write immediately cleans unused export")
replacementSuccess.clear()
RunLoop.main.run(until: Date().addingTimeInterval(0.08))
check(pasteboard.string(forType: .string) == "newer-user-copy-after-success" && replacementSuccessCleanup == 1, "expiry and teardown preserve successful write replacement")
var recopiedCleanup = 0
let recopiedClipboard = RecoveryClipboard(pasteboard: pasteboard, lifetime: 0.03, writeObjects: { objects in
  let written = pasteboard.writeObjects(objects)
  let recopied = NSPasteboardItem()
  if let original = objects.first as? NSPasteboardItem {
    for type in original.types {
      if let data = original.data(forType: type) { recopied.setData(data, forType: type) }
    }
  }
  pasteboard.clearContents()
  pasteboard.writeObjects([recopied])
  return written
})
check(recopiedClipboard.write("explicit newer recopy" as NSString) { recopiedCleanup += 1 }, "successful write can be recopied with its original item token")
check(pasteboard.string(forType: .string) == "explicit newer recopy" && recopiedCleanup == 1, "newer change count is not claimed even when ownership token was copied")
recopiedClipboard.clear()
RunLoop.main.run(until: Date().addingTimeInterval(0.08))
check(pasteboard.string(forType: .string) == "explicit newer recopy" && recopiedCleanup == 1, "teardown and expiry preserve explicitly recopied newer generation")
let emptyAccess = DeviceOwnerAuthorization(authentication: FakeAuthentication(), observeSystem: false)
var emptyInvalidations: [DeviceOwnerAuthorization.Revocation] = []
emptyAccess.onInvalidate = { reason in
  emptyInvalidations.append(reason)
  if reason == .system || reason == .keyChanged { clipboard.clear() }
}
emptyAccess.revoke()
check(emptyInvalidations.isEmpty, "empty session revoke does not invalidate a new UI operation")
clipboard.write("copied without an active grant" as NSString)
emptyAccess.revoke(.system)
check(emptyInvalidations == [.system], "system invalidation notifies without active grant")
check(pasteboard.string(forType: .string) == nil, "system invalidation clears clipboard without active grant")
clipboard.write("copied before key change" as NSString)
emptyAccess.revoke(.keyChanged)
check(emptyInvalidations == [.system, .keyChanged], "key change notifies without active grant")
check(pasteboard.string(forType: .string) == nil, "key change clears clipboard without active grant")

let parent = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
let base = parent.appendingPathComponent("recovery-fixtures-" + UUID().uuidString, isDirectory: true)
try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false)
defer { try? FileManager.default.removeItem(at: base) }
let exports = try RecoveryExports(base: base)
let canonicalPath = realpath(base.appendingPathComponent(RecoveryExports.directoryName).path, nil)!
let managedPath = String(cString: canonicalPath)
free(canonicalPath)
let managedDescriptors = (3..<min(getdtablesize(), 4096)).filter { descriptorPath($0) == managedPath }
if managedDescriptors.count != 1 {
  print("expected managed path: \(managedPath)")
  for descriptor in 3..<min(getdtablesize(), 4096) {
    if let path = descriptorPath(descriptor) { print("descriptor \(descriptor): \(path)") }
  }
  fflush(stdout)
}
check(managedDescriptors.count == 1, "one persistent export directory descriptor")
let managedDescriptor = managedDescriptors[0]
let descriptorFlags = fcntl(managedDescriptor, F_GETFD)
let childArguments = [CommandLine.arguments[0], "--descriptor-child", String(managedDescriptor), managedPath].map { strdup($0) }
defer { childArguments.forEach { free($0) } }
var arguments = childArguments + [nil]
var child: pid_t = 0
let spawned = posix_spawn(&child, CommandLine.arguments[0], nil, nil, &arguments, environ)
check(spawned == 0, "descriptor exec child launched")
var childStatus: Int32 = 0
check(waitpid(child, &childStatus, 0) == child, "descriptor exec child completed")
print("descriptor flags=\(descriptorFlags), exec child status=\(childStatus)")
fflush(stdout)
check(descriptorFlags & FD_CLOEXEC != 0, "export descriptor closes on exec")
check(childStatus == 0, "exec child cannot inherit export descriptor")
let first = try exports.create(Data("mock kit one".utf8))
let second = try exports.create(Data("mock kit two".utf8))
let failedExport = try exports.create(Data("mock kit not copied".utf8))
check(!failedClipboard.write(failedExport as NSURL) { exports.remove(failedExport) }, "failed export pasteboard write reports false")
check(!FileManager.default.fileExists(atPath: failedExport.path), "failed copy removes its temporary PDF immediately")
let formatExport = try exports.create(Data("mock file URL compatibility".utf8))
let originalURL = formatExport as NSURL
let originalURLTypes = originalURL.writableTypes(for: pasteboard)
let fileClipboard = RecoveryClipboard(pasteboard: pasteboard, lifetime: 0.03)
check(fileClipboard.write(originalURL) { exports.remove(formatExport) }, "owned clipboard item accepts exported file URL")
check(originalURLTypes.allSatisfy { type in
  guard let copied = pasteboard.propertyList(forType: type) as? NSObject,
        let original = originalURL.pasteboardPropertyList(forType: type) else { return false }
  return copied.isEqual(original)
}, "owned item preserves every NSURL property-list representation")
let readableURLs = pasteboard.readObjects(forClasses: [NSURL.self], options: nil) as? [NSURL]
check(readableURLs?.first?.isEqual(originalURL) == true, "native NSURL pasteboard reader receives original export URL")
RunLoop.main.run(until: Date().addingTimeInterval(0.08))
check(pasteboard.string(forType: .fileURL) == nil, "owned file URL expires from private clipboard")
check(!FileManager.default.fileExists(atPath: formatExport.path), "owned file URL expiry removes its temporary PDF")
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
} catch {
  let problem = error as NSError
  print("symlink managed root error=\(problem.domain):\(problem.code)")
  fflush(stdout)
  check(problem.domain == NSPOSIXErrorDomain && problem.code == Int(ENOTDIR), "symlink managed root fails with Darwin ENOTDIR")
  let preserved = try Data(contentsOf: protected)
  check(preserved == Data("keep outside managed directory".utf8), "symlink rejection preserves outside target")
}
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
