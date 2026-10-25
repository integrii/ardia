import AppKit
import LocalAuthentication

protocol DeviceOwnerAuthenticating: AnyObject {
  func evaluate(reason: String, completion: @escaping (Bool) -> Void)
  func cancel()
}

final class LocalDeviceOwnerAuthentication: DeviceOwnerAuthenticating {
  private var context: LAContext?

  func evaluate(reason: String, completion: @escaping (Bool) -> Void) {
    guard ProcessInfo.processInfo.environment["ARDIA_BACKGROUND"] != "1" else { return completion(false) }
    let context = LAContext()
    self.context = context
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return completion(false) }
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { allowed, _ in
      DispatchQueue.main.async { completion(allowed) }
    }
  }

  func cancel() {
    context?.invalidate()
    context = nil
  }
}

final class DeviceOwnerAuthorization {
  enum Revocation { case session, system, expired, keyChanged }
  struct Grant: Equatable {
    fileprivate let owner: UUID
    fileprivate let generation: UInt64
    fileprivate let binding: String
  }

  private let authentication: DeviceOwnerAuthenticating
  private let owner = UUID()
  private let now: () -> TimeInterval
  private let lifetime: TimeInterval
  private var generation: UInt64 = 0
  private var grant: Grant?
  private var deadline: TimeInterval = 0
  private var pending = false
  private var expiry: DispatchWorkItem?
  private var observers: [(NotificationCenter, NSObjectProtocol)] = []
  var onInvalidate: ((Revocation) -> Void)?

  init(authentication: DeviceOwnerAuthenticating = LocalDeviceOwnerAuthentication(),
       lifetime: TimeInterval = 60, now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
       observeSystem: Bool = true) {
    self.authentication = authentication
    self.lifetime = lifetime
    self.now = now
    if observeSystem {
      observe(NSWorkspace.shared.notificationCenter, NSWorkspace.willSleepNotification)
      observe(NSWorkspace.shared.notificationCenter, NSWorkspace.sessionDidResignActiveNotification)
      observe(DistributedNotificationCenter.default(), Notification.Name("com.apple.screenIsLocked"))
      observe(NotificationCenter.default, NSApplication.willTerminateNotification)
      let center = NotificationCenter.default
      let token = center.addObserver(forName: NSWindow.willCloseNotification, object: nil, queue: .main) { [weak self] notification in
        guard let window = notification.object as? NSWindow, !(window is NSPanel) else { return }
        self?.revoke()
      }
      observers.append((center, token))
    }
  }

  deinit {
    authentication.cancel()
    expiry?.cancel()
    for (center, token) in observers { center.removeObserver(token) }
  }

  private func observe(_ center: NotificationCenter, _ name: Notification.Name) {
    let token = center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in self?.revoke(.system) }
    observers.append((center, token))
  }

  func authorize(binding: String, reason: String, currentBinding: @escaping () -> String?, completion: @escaping (Grant?) -> Void) {
    dispatchPrecondition(condition: .onQueue(.main))
    if let grant, validate(grant, binding: currentBinding()), grant.binding == binding { return completion(grant) }
    guard !pending, currentBinding() == binding else { return completion(nil) }
    let request = generation
    pending = true
    authentication.evaluate(reason: reason) { [weak self] allowed in
      guard let self else { return completion(nil) }
      guard self.generation == request else { return completion(nil) }
      self.pending = false
      guard allowed, currentBinding() == binding else { return completion(nil) }
      let grant = Grant(owner: self.owner, generation: request, binding: binding)
      self.grant = grant
      self.deadline = self.now() + self.lifetime
      let expiry = DispatchWorkItem { [weak self] in self?.revoke(.expired) }
      self.expiry = expiry
      DispatchQueue.main.asyncAfter(deadline: .now() + self.lifetime, execute: expiry)
      completion(grant)
    }
  }

  func validate(_ candidate: Grant, binding: String?) -> Bool {
    dispatchPrecondition(condition: .onQueue(.main))
    guard candidate == grant, candidate.generation == generation else { return false }
    guard candidate.binding == binding else {
      revoke(.keyChanged)
      return false
    }
    guard now() < deadline else {
      revoke(.expired)
      return false
    }
    return true
  }

  func revoke(_ reason: Revocation = .session) {
    dispatchPrecondition(condition: .onQueue(.main))
    let notify = grant != nil || pending || reason == .system || reason == .keyChanged
    generation &+= 1
    grant = nil
    pending = false
    deadline = 0
    expiry?.cancel()
    expiry = nil
    authentication.cancel()
    if notify { onInvalidate?(reason) }
  }
}
