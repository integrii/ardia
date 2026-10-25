import AppKit
import ExpoModulesCore
import ArdiaImport
import Security

public class SyncModule: Module {
  private let state = KeyState()
  private static let work = DispatchQueue(label: "ardia.sync", qos: .utility)
  private var recoveryAuthorization: DeviceOwnerAuthorization?
  private var recoveryClipboard: RecoveryClipboard?
  private var recoveryExports: RecoveryExports?
  private var recoveryShares: [UUID: RecoveryShare] = [:]
  private weak var recoverySavePanel: NSSavePanel?
  private var recoveryDestroyed = false

  public func definition() -> ModuleDefinition {
    Name("ArdiaSync")
    Events("onRecoveryInvalidated")

    OnCreate {
      DispatchQueue.main.async { self.recoveryExports = try? RecoveryExports() }
    }

    OnDestroy { [weak self] in
      guard let self else { return }
      DispatchQueue.main.async {
        self.recoveryDestroyed = true
        self.recoveryAuthorization?.revoke()
        self.recoveryClipboard?.clear()
        self.recoveryExports?.clear()
        self.recoveryShares.removeAll()
      }
    }

    AsyncFunction("folderInfo") { (path: String?) -> [String: Any] in
      let url = path.map { URL(fileURLWithPath: $0, isDirectory: true) } ?? Self.defaultFolder
      var isDirectory: ObjCBool = false
      let exists = FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) && isDirectory.boolValue
      return [
        "path": url.path,
        "defaultPath": Self.defaultFolder.path,
        "iCloudAvailable": Self.testFolder != nil || SyncFolder.iCloudDriveAvailable,
        "inICloud": SyncFolder.isInICloudDrive(url),
        "exists": exists,
        "writable": exists && FileManager.default.isWritableFile(atPath: url.path),
        "hasSyncData": exists && SyncFolder.hasSyncData(url),
      ]
    }.runOnQueue(Self.work)

    AsyncFunction("chooseFolder") { (current: String?, promise: Promise) in
      let panel = NSOpenPanel()
      panel.canChooseFiles = false
      panel.canChooseDirectories = true
      panel.canCreateDirectories = true
      panel.allowsMultipleSelection = false
      panel.prompt = "Use Folder"
      panel.message = "Choose a folder that syncs between your Macs, like one in iCloud Drive or Dropbox, or on a NAS or USB drive."
      if let current { panel.directoryURL = URL(fileURLWithPath: current, isDirectory: true) }
      panel.begin { response in promise.resolve(response == .OK ? panel.url?.path : nil) }
    }.runOnQueue(.main)

    Function("newDeviceId") { SyncKeys.newFileId() }

    Function("deviceName") { Host.current().localizedName ?? "This Mac" }

    AsyncFunction("createPhrase") { (account: String) -> Bool in
      let entropy = RecoveryPhrase.generateEntropy()
      guard Self.keyStore.save(entropy, account: account) else { return false }
      self.state.set(entropy)
      self.revokeRecoveryAuthorizationAfterKeyChange()
      return true
    }.runOnQueue(Self.work)

    AsyncFunction("enterPhrase") { (account: String, text: String, folder: String) -> [String: Any] in
      let entropy: Data
      do {
        entropy = try RecoveryPhrase.entropy(from: text)
      } catch let problem as RecoveryPhrase.Problem {
        switch problem {
        case .wordCount(let n): return ["error": "wordCount", "count": n]
        case .unknownWord(let word): return ["error": "unknownWord", "word": word]
        case .checksum: return ["error": "checksum"]
        }
      }
      let folderURL = URL(fileURLWithPath: folder, isDirectory: true)
      if !SyncVault(folder: folderURL, keys: SyncKeys(entropy: entropy)).chainExists() {
        return ["error": SyncFolder.hasSyncData(folderURL) ? "mismatch" : "noData"]
      }
      guard Self.keyStore.save(entropy, account: account) else { return ["error": "keychain"] }
      self.state.set(entropy)
      self.revokeRecoveryAuthorizationAfterKeyChange()
      return ["ok": true]
    }.runOnQueue(Self.work)

    AsyncFunction("unlock") { (account: String) -> Bool in
      guard let entropy = Self.keyStore.load(account: account), entropy.count == 32 else { return false }
      self.state.set(entropy)
      self.revokeRecoveryAuthorizationAfterKeyChange()
      return true
    }.runOnQueue(Self.work)

    AsyncFunction("forget") { (account: String) in
      Self.keyStore.delete(account: account)
      self.state.set(nil)
      self.revokeRecoveryAuthorizationAfterKeyChange()
    }.runOnQueue(Self.work)

    AsyncFunction("chainStatus") { (folder: String) throws -> String in
      let vault = try self.vault(folder)
      var isDirectory: ObjCBool = false
      guard FileManager.default.fileExists(atPath: folder, isDirectory: &isDirectory), isDirectory.boolValue else { return "unavailable" }
      return vault.chainExists() ? "ok" : "missing"
    }.runOnQueue(Self.work)

    AsyncFunction("createChain") { (folder: String) throws in
      try FileManager.default.createDirectory(at: URL(fileURLWithPath: folder, isDirectory: true), withIntermediateDirectories: true)
      try self.vault(folder).createChain()
    }.runOnQueue(Self.work)

    AsyncFunction("write") { (folder: String, scope: String, payload: String) throws -> String in
      try self.vault(folder).write(scope: scope, payload: Data(payload.utf8))
    }.runOnQueue(Self.work)

    AsyncFunction("read") { (folder: String, scope: String, known: [String]) throws -> [String: Any] in
      let listing = try self.vault(folder).read(scope: scope, skipping: Set(known))
      return [
        "files": listing.files.map { ["id": $0.id, "payload": String(decoding: $0.payload, as: UTF8.self)] },
        "pending": listing.pending,
        "damaged": listing.damaged.map { ["id": $0.id, "age": $0.age * 1000] },
        "present": listing.present,
      ]
    }.runOnQueue(Self.work)

    AsyncFunction("remove") { (folder: String, scope: String, ids: [String]) throws in
      try self.vault(folder).remove(scope: scope, ids: ids)
    }.runOnQueue(Self.work)

    AsyncFunction("deleteChain") { (folder: String) throws in
      try self.vault(folder).deleteChain()
    }.runOnQueue(Self.work)

    AsyncFunction("sealLocal") { (text: String) throws -> String in
      guard let keys = self.state.keys else { throw Exception(name: "locked", description: "Sync isn't set up on this Mac.") }
      return try keys.seal(Data(text.utf8), scopeTag: "local", fileId: "state").base64EncodedString()
    }.runOnQueue(Self.work)

    AsyncFunction("openLocal") { (sealed: String) -> String? in
      guard let keys = self.state.keys, let data = Data(base64Encoded: sealed),
            let plain = try? keys.open(data, scopeTag: "local", fileId: "state") else { return nil }
      return String(decoding: plain, as: UTF8.self)
    }.runOnQueue(Self.work)

    AsyncFunction("authorizeRecovery") { (promise: Promise) in
      self.authorizeRecovery { grant, _ in promise.resolve(grant != nil) }
    }.runOnQueue(.main)

    Function("revokeRecoveryAuthorization") {
      DispatchQueue.main.async { self.recoveryAuthorization?.revoke() }
    }

    AsyncFunction("recoveryWords") { (promise: Promise) in
      self.recoveryOperation(promise) { $0 }
    }.runOnQueue(.main)

    AsyncFunction("qrCode") { (promise: Promise) in
      self.recoveryOperation(promise) { words -> String? in
        guard let image = RecoveryKit.qrCode(words: words), let png = RecoveryKit.png(image) else { return nil }
        return "data:image/png;base64," + png.base64EncodedString()
      }
    }.runOnQueue(.main)

    AsyncFunction("recoveryKitPreview") { (width: Double, promise: Promise) in
      self.recoveryOperation(promise) { words in self.preview(words: words, width: CGFloat(width)) }
    }.runOnQueue(.main)

    AsyncFunction("saveRecoveryKit") { (format: String, promise: Promise) in
      self.authorizeRecovery { grant, binding in
        guard let grant, let binding, Self.environment["ARDIA_BACKGROUND"] != "1" else { return promise.resolve(nil) }
        let panel = NSSavePanel()
        let text = format == "text"
        panel.nameFieldStringValue = text ? RecoveryKit.textName : RecoveryKit.pdfName
        panel.allowedContentTypes = [text ? .plainText : .pdf]
        panel.message = "This file contains your unencrypted recovery phrase. Anyone with it can read your synced data."
        panel.canCreateDirectories = true
        self.recoverySavePanel = panel
        panel.begin { response in
          if self.recoverySavePanel === panel { self.recoverySavePanel = nil }
          guard response == .OK, let url = panel.url,
                self.recoveryAuthorization?.validate(grant, binding: self.state.recoveryBinding) == true else { return promise.resolve(nil) }
          do {
            let path = try self.state.withRecoveryEntropy(binding: binding) { entropy -> String in
              try Self.kit(RecoveryPhrase.words(for: entropy), text: text).write(to: url, options: [.atomic])
              return url.path
            }
            promise.resolve(path)
          } catch {
            promise.reject("save", "Couldn’t save the recovery kit. Try unlocking it again.")
          }
        }
      }
    }.runOnQueue(.main)

    AsyncFunction("copyRecoveryKit") { (promise: Promise) in
      self.recoveryOperation(promise) { words in
        let exports = try self.exports()
        let url = try exports.create(Self.kit(words, text: false))
        return self.clipboard().write(url as NSURL) { exports.remove(url) }
      }
    }.runOnQueue(.main)

    AsyncFunction("shareRecoveryKit") { (promise: Promise) in
      self.authorizeRecovery { grant, binding in
        guard let grant, let binding,
              self.recoveryAuthorization?.validate(grant, binding: self.state.recoveryBinding) == true,
              Self.environment["ARDIA_BACKGROUND"] != "1",
              let window = NSApp.keyWindow ?? NSApp.windows.first(where: \.isVisible), let view = window.contentView else { return promise.resolve(nil) }
        do {
          let exports = try self.exports()
          let url = try self.state.withRecoveryEntropy(binding: binding) { entropy in
            try exports.create(Self.kit(RecoveryPhrase.words(for: entropy), text: false))
          }
          let id = UUID()
          let share = RecoveryShare(url: url, authorized: { [weak self] in
            guard let self else { return false }
            return self.recoveryAuthorization?.validate(grant, binding: self.state.recoveryBinding) == true
          }) { [weak self] in
            exports.remove(url)
            self?.recoveryShares.removeValue(forKey: id)
          }
          self.recoveryShares[id] = share
          DispatchQueue.main.asyncAfter(deadline: .now() + 300) { [weak self] in
            self?.recoveryShares[id]?.cancelUnconsumed()
            self?.recoveryShares.removeValue(forKey: id)
          }
          share.show(in: view, at: view.convert(window.mouseLocationOutsideOfEventStream, from: nil))
          promise.resolve(true)
        } catch {
          promise.reject("recovery", "Couldn’t share the recovery kit. Try unlocking it again.")
        }
      }
    }.runOnQueue(.main)

    AsyncFunction("copyRecoveryPhrase") { (endAuthorization: Bool?, promise: Promise) in
      self.recoveryOperation(promise, endAuthorization: endAuthorization == true) { words in
        self.clipboard().write(words.joined(separator: " ") as NSString)
      }
    }.runOnQueue(.main)

    AsyncFunction("revealFolder") { (path: String) in
      NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path, isDirectory: true)])
    }.runOnQueue(.main)

    AsyncFunction("readPasswords") { (engineProfile: String) -> [[String: Any]]? in
      do {
        let key = ChromiumCrypto.deriveKey(secret: try Self.safeStorageSecret())
        let result = try ChromiumSecrets.logins(profile: Self.profileDirectory(engineProfile), key: key)
        if result.undecryptable > 0 {
          NSLog("[sync] \(result.undecryptable) saved passwords didn't decrypt; not syncing passwords now")
          return nil
        }
        return result.items.map { c in
          ["origin": c.realm ?? c.url, "url": c.url, "username": c.username, "password": c.password, "created": c.created ?? 0]
        }
      } catch ImportError.notFound(_) {
        return []
      } catch {
        NSLog("[sync] reading passwords: \(error)")
        return nil
      }
    }.runOnQueue(Self.work)
  }

  private func vault(_ folder: String) throws -> SyncVault {
    guard let keys = state.keys else { throw Exception(name: "locked", description: "Sync isn't set up on this Mac.") }
    return SyncVault(folder: URL(fileURLWithPath: folder, isDirectory: true), keys: keys)
  }

  private func revokeRecoveryAuthorizationAfterKeyChange() {
    DispatchQueue.main.async {
      self.recoveryAuthorization?.revoke(.keyChanged)
    }
  }

  private func authorizeRecovery(_ completion: @escaping (DeviceOwnerAuthorization.Grant?, String?) -> Void) {
    guard !recoveryDestroyed else { return completion(nil, nil) }
    if recoveryAuthorization == nil {
      let authorization = DeviceOwnerAuthorization()
      authorization.onInvalidate = { [weak self] reason in
        guard let self else { return }
        if reason == .system || reason == .keyChanged { self.recoveryClipboard?.clear() }
        self.recoverySavePanel?.cancel(nil)
        for share in Array(self.recoveryShares.values) { share.cancelUnconsumed() }
        self.sendEvent("onRecoveryInvalidated", [:])
      }
      recoveryAuthorization = authorization
    }
    guard let binding = state.recoveryBinding else { return completion(nil, nil) }
    recoveryAuthorization?.authorize(binding: binding, reason: "Unlock your Ardia recovery phrase.", currentBinding: { [weak self] in
      self?.state.recoveryBinding
    }) { grant in completion(grant, binding) }
  }

  private func recoveryOperation<T>(_ promise: Promise, endAuthorization: Bool = false, operation: @escaping ([String]) throws -> T) {
    authorizeRecovery { grant, binding in
      guard let grant, let binding,
            self.recoveryAuthorization?.validate(grant, binding: self.state.recoveryBinding) == true else { return promise.resolve(nil) }
      defer {
        if endAuthorization,
           self.recoveryAuthorization?.validate(grant, binding: self.state.recoveryBinding) == true {
          self.recoveryAuthorization?.revoke()
        }
      }
      do {
        let result = try self.state.withRecoveryEntropy(binding: binding) { entropy in
          try operation(RecoveryPhrase.words(for: entropy))
        }
        promise.resolve(result)
      } catch {
        promise.reject("recovery", "Couldn’t open the recovery kit. Try unlocking it again.")
      }
    }
  }

  private func clipboard() -> RecoveryClipboard {
    if let recoveryClipboard { return recoveryClipboard }
    let clipboard = RecoveryClipboard(pasteboard: .general)
    recoveryClipboard = clipboard
    return clipboard
  }

  private func exports() throws -> RecoveryExports {
    if let recoveryExports { return recoveryExports }
    let exports = try RecoveryExports()
    recoveryExports = exports
    return exports
  }

  private static func kit(_ words: [String], text: Bool) -> Data {
    let device = Host.current().localizedName ?? "this Mac"
    return text ? Data(RecoveryKit.text(words: words, created: Date(), device: device).utf8)
      : RecoveryKit.pdf(words: words, created: Date(), device: device)
  }

  private func preview(words: [String], width: CGFloat) -> String? {
    guard width.isFinite, width >= 1, width <= 2048 else { return nil }
    let pdf = Self.kit(words, text: false)
    guard let page = NSImage(data: pdf) else { return nil }
    let scale = (NSScreen.main?.backingScaleFactor ?? 2)
    let size = NSSize(width: width, height: width * page.size.height / page.size.width)
    guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width * scale), pixelsHigh: Int(size.height * scale),
                                     bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                     colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0) else { return nil }
    rep.size = size
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    NSColor.white.setFill()
    NSRect(origin: .zero, size: size).fill()
    page.draw(in: NSRect(origin: .zero, size: size))
    NSGraphicsContext.restoreGraphicsState()
    guard let png = rep.representation(using: .png, properties: [:]) else { return nil }
    return "data:image/png;base64," + png.base64EncodedString()
  }

  private static let environment = ProcessInfo.processInfo.environment
  private static let dataDirectory = environment["ARDIA_DATA_DIR"].map { URL(fileURLWithPath: $0, isDirectory: true) }
  private static let testFolder = environment["ARDIA_SYNC_DEFAULT_FOLDER"].map { URL(fileURLWithPath: $0, isDirectory: true) }

  static var defaultFolder: URL {
    if let testFolder { return testFolder }
    if let dataDirectory { return dataDirectory.appendingPathComponent("Ardia Sync", isDirectory: true) }
    let folder = SyncFolder.iCloudDrive.appendingPathComponent("Ardia Sync", isDirectory: true)
    let legacy = SyncFolder.iCloudDrive.appendingPathComponent(LegacyName.syncFolderName, isDirectory: true)
    if !FileManager.default.fileExists(atPath: folder.path), SyncFolder.hasSyncData(legacy) { return legacy }
    return folder
  }

  static let keyStore: SyncKeyStore = dataDirectory.map { FileKeyStore(directory: $0) } ?? KeychainKeyStore()

  static func profileDirectory(_ engineProfile: String) -> URL {
    let root = dataDirectory?.appendingPathComponent("Chromium", isDirectory: true)
      ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
      .appendingPathComponent(Bundle.main.bundleIdentifier ?? "com.ardia.browser", isDirectory: true)
      .appendingPathComponent("Chromium", isDirectory: true)
    return root.appendingPathComponent(engineProfile.isEmpty ? "Default" : "Profile \(engineProfile)", isDirectory: true)
  }

  static func safeStorageSecret() throws -> Data {
    if dataDirectory != nil || !isTeamSigned { return Data("mock_password".utf8) }
    return try SafeStorageKeychain.secret(service: "Ardia Safe Storage", account: "Ardia")
  }

  static let isTeamSigned: Bool = {
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return false }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return false }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let dict = info as? [String: Any] else { return false }
    return dict[kSecCodeInfoTeamIdentifier as String] != nil
  }()
}

private final class KeyState {
  private let lock = NSLock()
  private var _entropy: Data?
  private var _keys: SyncKeys?
  private var recoveryGeneration: UInt64 = 0

  func set(_ entropy: Data?) {
    lock.lock()
    defer { lock.unlock() }
    _entropy = entropy
    _keys = entropy.map(SyncKeys.init(entropy:))
    recoveryGeneration &+= 1
  }

  var recoveryBinding: String? {
    lock.lock()
    defer { lock.unlock() }
    return _entropy == nil ? nil : String(recoveryGeneration)
  }

  func withRecoveryEntropy<T>(binding: String, operation: (Data) throws -> T) throws -> T {
    lock.lock()
    defer { lock.unlock() }
    guard binding == String(recoveryGeneration), let entropy = _entropy else {
      throw Exception(name: "locked", description: "Unlock your recovery kit again.")
    }
    return try operation(entropy)
  }

  var entropy: Data? {
    lock.lock()
    defer { lock.unlock() }
    return _entropy
  }

  var keys: SyncKeys? {
    lock.lock()
    defer { lock.unlock() }
    return _keys
  }
}
