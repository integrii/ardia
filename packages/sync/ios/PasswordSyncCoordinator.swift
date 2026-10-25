import AppKit

struct PasswordSyncKeySnapshot {
  let keys: SyncKeys
  let generation: UInt64
}

@MainActor
final class PasswordSyncCoordinator {
  private struct Approval {
    let id = UUID()
    let snapshot: PasswordSyncKeySnapshot
    let folder: String
    let bindings: [PasswordSyncBinding]
    let identity: String
  }

  private let snapshot: () -> PasswordSyncKeySnapshot?
  private let foreground: @MainActor () -> Bool
  private let authorization: DeviceOwnerAuthorization
  private let store: any PasswordSyncStore
  private let onInvalidate: () -> Void
  private var approval: Approval?
  private var grant: DeviceOwnerAuthorization.Grant?
  private var observers: [(NotificationCenter, NSObjectProtocol)] = []
  private lazy var sync = PasswordSync(store: store) { [weak self] binding in self?.access(binding) }

  init(store: any PasswordSyncStore, authentication: DeviceOwnerAuthenticating = LocalDeviceOwnerAuthentication(),
       snapshot: @escaping () -> PasswordSyncKeySnapshot?,
       foreground: @escaping @MainActor () -> Bool = { ProcessInfo.processInfo.environment["ARDIA_BACKGROUND"] != "1" && NSApp.isActive },
       now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
       observeSystem: Bool = true, onInvalidate: @escaping () -> Void) {
    self.store = store
    self.snapshot = snapshot
    self.foreground = foreground
    self.onInvalidate = onInvalidate
    authorization = DeviceOwnerAuthorization(authentication: authentication, lifetime: 24 * 60 * 60, now: now, observeSystem: false)
    authorization.onInvalidate = { [weak self] _ in
      guard let self else { return }
      self.approval = nil
      self.grant = nil
      self.onInvalidate()
    }
    if observeSystem {
      observe(NSWorkspace.shared.notificationCenter, NSWorkspace.willSleepNotification)
      observe(NSWorkspace.shared.notificationCenter, NSWorkspace.sessionDidResignActiveNotification)
      observe(DistributedNotificationCenter.default(), Notification.Name("com.apple.screenIsLocked"))
      observe(NotificationCenter.default, NSApplication.willTerminateNotification)
    }
  }

  deinit {
    for (center, token) in observers { center.removeObserver(token) }
  }

  private func observe(_ center: NotificationCenter, _ name: Notification.Name) {
    let token = center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
      MainActor.assumeIsolated { self?.revoke() }
    }
    observers.append((center, token))
  }

  func authorize(folder: String, profiles: [[String: String]]) async -> Bool {
    guard foreground(), let snapshot = snapshot(), let folder = Self.canonicalFolder(folder),
          !profiles.isEmpty, profiles.count <= 128,
          SyncVault(folder: URL(fileURLWithPath: folder), keys: snapshot.keys).chainExists() else { return false }
    var bindings: [PasswordSyncBinding] = []
    for profile in profiles {
      guard Set(profile.keys) == ["scope", "engineProfile"], let scope = profile["scope"], let engineProfile = profile["engineProfile"],
            Self.valid(scope: scope, profile: engineProfile) else { return false }
      let binding = PasswordSyncBinding(chain: snapshot.keys.chainTag, folder: folder, scope: scope, profile: engineProfile)
      guard !bindings.contains(binding) else { return false }
      bindings.append(binding)
    }
    bindings.sort { ($0.scope, $0.profile) < ($1.scope, $1.profile) }
    guard let data = try? JSONSerialization.data(withJSONObject: [String(snapshot.generation), snapshot.keys.chainTag, folder, bindings.map { [$0.scope, $0.profile] }]) else { return false }
    let request = Approval(snapshot: snapshot, folder: folder, bindings: bindings, identity: data.base64EncodedString())
    if approval?.identity == request.identity, let binding = bindings.first, authorized(binding) { return true }
    revoke()
    return await withCheckedContinuation { continuation in
      authorization.authorize(binding: request.identity, reason: "Allow Ardia to sync passwords for your selected profiles.", currentBinding: { [weak self] in
        guard let self, self.current(request) else { return nil }
        return request.identity
      }) { [weak self] grant in
        guard let self, let grant, self.current(request) else { return continuation.resume(returning: false) }
        self.approval = request
        self.grant = grant
        continuation.resume(returning: true)
      }
    }
  }

  func revoke() { authorization.revoke() }

  func status(folder: String, scope: String, profile: String) -> Bool {
    guard let binding = binding(folder: folder, scope: scope, profile: profile) else { return false }
    return authorized(binding)
  }

  func read(folder: String, scope: String, profile: String) async -> [[String: Any]]? {
    guard let binding = binding(folder: folder, scope: scope, profile: profile) else { return nil }
    return await sync.read(binding)
  }

  func apply(folder: String, scope: String, profile: String, changes: [[String: Any]]) async -> Bool {
    guard let binding = binding(folder: folder, scope: scope, profile: profile) else { return false }
    return await sync.apply(binding, changes: changes)
  }

  private func binding(folder: String, scope: String, profile: String) -> PasswordSyncBinding? {
    guard let snapshot = snapshot(), let folder = Self.canonicalFolder(folder), Self.valid(scope: scope, profile: profile) else { return nil }
    return PasswordSyncBinding(chain: snapshot.keys.chainTag, folder: folder, scope: scope, profile: profile)
  }

  private func authorized(_ binding: PasswordSyncBinding) -> Bool {
    guard let approval, let grant else { return false }
    guard current(approval) else { revoke(); return false }
    return approval.bindings.contains(binding) && authorization.validate(grant, binding: approval.identity)
  }

  private func access(_ binding: PasswordSyncBinding) -> PasswordSyncAccess? {
    guard authorized(binding), let approval else { return nil }
    return PasswordSyncAccess(binding: binding, codec: PasswordSyncRecords(keys: approval.snapshot.keys), authorized: { [weak self] in
      guard let self, self.approval?.id == approval.id else { return false }
      return self.authorized(binding)
    })
  }

  private func current(_ approval: Approval) -> Bool {
    guard let snapshot = snapshot(), snapshot.generation == approval.snapshot.generation,
          snapshot.keys.chainTag == approval.snapshot.keys.chainTag,
          Self.canonicalFolder(approval.folder) == approval.folder else { return false }
    return true
  }

  static func canonicalFolder(_ path: String) -> String? {
    guard !path.isEmpty, path.utf8.count <= 4096, path.hasPrefix("/"), !path.contains("\0"),
          !(path as NSString).pathComponents.contains("..") else { return nil }
    return URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL.resolvingSymlinksInPath().path
  }

  static func valid(scope: String, profile: String) -> Bool {
    guard scope.hasPrefix("p:"), Base32.isTag(String(scope.dropFirst(2))), profile.utf8.count <= 128 else { return false }
    return profile.isEmpty || profile.range(of: #"^[A-Za-z0-9_-]+$"#, options: .regularExpression) != nil
  }
}
