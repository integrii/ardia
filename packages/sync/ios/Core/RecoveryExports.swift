import AppKit
import Darwin

final class RecoveryExports {
  static let directoryName = "Ardia Recovery Exports"
  static let fileName = "Ardia Recovery Kit.pdf"
  private let root: URL
  private let descriptor: Int32
  private let lifetime: TimeInterval
  private var leases: [String: DispatchWorkItem] = [:]
  private var owned: Set<String> = []

  init(base: URL = FileManager.default.temporaryDirectory, lifetime: TimeInterval = 300) throws {
    self.lifetime = min(300, max(0, lifetime))
    root = base.appendingPathComponent(Self.directoryName, isDirectory: true)
    if mkdir(root.path, 0o700) != 0 && errno != EEXIST { throw Self.error() }
    descriptor = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard descriptor >= 0 else { throw Self.error() }
    var info = stat()
    guard fstat(descriptor, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o777 == 0o700 else {
      close(descriptor)
      throw CocoaError(.fileReadNoPermission)
    }
    for name in (try? FileManager.default.contentsOfDirectory(atPath: root.path)) ?? [] {
      guard UUID(uuidString: name) != nil else { continue }
      var entry = stat()
      guard fstatat(descriptor, name, &entry, AT_SYMLINK_NOFOLLOW) == 0,
            entry.st_mode & S_IFMT == S_IFDIR, entry.st_uid == getuid() else { continue }
      let remaining = self.lifetime - Date().timeIntervalSince1970 + Double(entry.st_mtimespec.tv_sec)
      if remaining <= 0 { remove(name) }
      else { expire(name, after: min(remaining, self.lifetime)) }
    }
    Self.cleanLegacy(base: base)
  }

  deinit {
    clear()
    for expiry in leases.values { expiry.cancel() }
    close(descriptor)
  }

  func create(_ data: Data) throws -> URL {
    let name = UUID().uuidString
    guard mkdirat(descriptor, name, 0o700) == 0 else { throw Self.error() }
    let directory = openat(descriptor, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard directory >= 0 else { remove(name); throw Self.error() }
    defer { close(directory) }
    let file = openat(directory, Self.fileName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    guard file >= 0 else { remove(name); throw Self.error() }
    defer { close(file) }
    do {
      try data.withUnsafeBytes { buffer in
        var written = 0
        while written < buffer.count {
          let count = Darwin.write(file, buffer.baseAddress!.advanced(by: written), buffer.count - written)
          if count < 0 && errno == EINTR { continue }
          guard count > 0 else { throw Self.error() }
          written += count
        }
      }
    } catch {
      remove(name)
      throw error
    }
    owned.insert(name)
    expire(name, after: lifetime)
    return root.appendingPathComponent(name, isDirectory: true).appendingPathComponent(Self.fileName)
  }

  func remove(_ url: URL) {
    guard url.deletingLastPathComponent().deletingLastPathComponent() == root,
          url.lastPathComponent == Self.fileName else { return }
    remove(url.deletingLastPathComponent().lastPathComponent)
  }

  func clear() {
    for name in owned { remove(name) }
  }

  private func expire(_ name: String, after delay: TimeInterval) {
    let expiry = DispatchWorkItem { [weak self] in self?.remove(name) }
    leases[name] = expiry
    DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: expiry)
  }

  private func remove(_ name: String) {
    guard UUID(uuidString: name) != nil else { return }
    owned.remove(name)
    leases.removeValue(forKey: name)?.cancel()
    let directory = openat(descriptor, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard directory >= 0 else { return }
    defer { close(directory) }
    var info = stat()
    guard fstat(directory, &info) == 0, info.st_uid == getuid() else { return }
    unlinkat(directory, Self.fileName, 0)
    unlinkat(descriptor, name, AT_REMOVEDIR)
  }

  private static func cleanLegacy(base: URL) {
    let path = base.appendingPathComponent("Ardia Recovery Kit", isDirectory: true).path
    let directory = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard directory >= 0 else { return }
    defer { close(directory) }
    var info = stat()
    guard fstat(directory, &info) == 0, info.st_uid == getuid() else { return }
    for name in [fileName, "Netnyahoo Recovery Kit.pdf"] {
      guard fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0,
            info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG else { continue }
      unlinkat(directory, name, 0)
    }
    rmdir(path)
  }

  private static func error() -> NSError { NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
}

final class RecoveryShare: NSObject, NSSharingServicePickerDelegate, NSSharingServiceDelegate {
  private let picker: NSSharingServicePicker
  private let authorized: () -> Bool
  private let finished: () -> Void
  private var completed = false
  private var consuming = false

  init(url: URL, authorized: @escaping () -> Bool, finished: @escaping () -> Void) {
    picker = NSSharingServicePicker(items: [url])
    self.authorized = authorized
    self.finished = finished
    super.init()
    picker.delegate = self
  }

  func show(in view: NSView, at point: NSPoint) {
    guard authorized() else { return finish() }
    picker.show(relativeTo: NSRect(origin: point, size: .zero), of: view, preferredEdge: .minY)
  }

  func cancelUnconsumed() {
    guard !consuming, !completed else { return }
    picker.close()
    finish()
  }

  func sharingServicePicker(_ sharingServicePicker: NSSharingServicePicker, didChoose service: NSSharingService?) {
    if service == nil || !authorized() { finish() }
  }

  func sharingServicePicker(_ sharingServicePicker: NSSharingServicePicker, delegateFor sharingService: NSSharingService) -> NSSharingServiceDelegate? { self }

  func sharingService(_ sharingService: NSSharingService, willShareItems items: [Any]) {
    guard !completed, authorized() else { return finish() }
    consuming = true
  }

  func sharingService(_ sharingService: NSSharingService, didShareItems items: [Any]) { finish() }

  func sharingService(_ sharingService: NSSharingService, didFailToShareItems items: [Any], error: Error) { finish() }

  private func finish() {
    guard !completed else { return }
    completed = true
    finished()
  }
}
