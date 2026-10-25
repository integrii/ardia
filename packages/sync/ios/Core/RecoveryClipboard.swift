import AppKit

final class RecoveryClipboard {
  static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
  static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
  private let pasteboard: NSPasteboard
  private let lifetime: TimeInterval
  private var changeCount: Int?
  private var expiry: DispatchWorkItem?
  private var cleanup: (() -> Void)?

  init(pasteboard: NSPasteboard, lifetime: TimeInterval = 60) {
    self.pasteboard = pasteboard
    self.lifetime = min(60, max(0, lifetime))
  }

  deinit { clear() }

  func write(_ object: NSPasteboardWriting, cleanup: (() -> Void)? = nil) {
    clear()
    pasteboard.prepareForNewContents(with: .currentHostOnly)
    pasteboard.writeObjects([object])
    pasteboard.addTypes([Self.concealed, Self.transient], owner: nil)
    pasteboard.setString("", forType: Self.concealed)
    pasteboard.setString("", forType: Self.transient)
    changeCount = pasteboard.changeCount
    self.cleanup = cleanup
    let expiry = DispatchWorkItem { [weak self] in self?.clear() }
    self.expiry = expiry
    DispatchQueue.main.asyncAfter(deadline: .now() + lifetime, execute: expiry)
  }

  func clear() {
    expiry?.cancel()
    expiry = nil
    if let changeCount, pasteboard.changeCount == changeCount { pasteboard.clearContents() }
    changeCount = nil
    cleanup?()
    cleanup = nil
  }
}
