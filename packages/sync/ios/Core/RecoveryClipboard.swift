import AppKit

final class RecoveryClipboard {
  static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
  static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
  static let ownership = NSPasteboard.PasteboardType("com.ardia.recovery-clipboard-owner")
  private let pasteboard: NSPasteboard
  private let lifetime: TimeInterval
  private let writeObjects: ([NSPasteboardWriting]) -> Bool
  private var changeCount: Int?
  private var ownerToken: String?
  private var expiry: DispatchWorkItem?
  private var cleanup: (() -> Void)?

  init(pasteboard: NSPasteboard, lifetime: TimeInterval = 60, writeObjects: (([NSPasteboardWriting]) -> Bool)? = nil) {
    self.pasteboard = pasteboard
    self.lifetime = min(60, max(0, lifetime))
    self.writeObjects = writeObjects ?? { pasteboard.writeObjects($0) }
  }

  deinit { clear() }

  @discardableResult
  func write(_ object: NSPasteboardWriting, cleanup: (() -> Void)? = nil) -> Bool {
    clear()
    let item = NSPasteboardItem()
    let types = object.writableTypes(for: pasteboard)
    guard !types.isEmpty else { cleanup?(); return false }
    for type in types {
      guard let value = object.pasteboardPropertyList(forType: type) else { cleanup?(); return false }
      let copied: Bool
      if let string = value as? String { copied = item.setString(string, forType: type) }
      else if let data = value as? Data { copied = item.setData(data, forType: type) }
      else { copied = item.setPropertyList(value, forType: type) }
      guard copied else {
        cleanup?()
        return false
      }
    }
    let token = UUID().uuidString
    guard item.setString(token, forType: Self.ownership),
          item.setString("", forType: Self.concealed), item.setString("", forType: Self.transient) else {
      cleanup?()
      return false
    }
    let count = pasteboard.prepareForNewContents(with: .currentHostOnly)
    let written = writeObjects([item])
    guard owns(token, changeCount: count) else {
      cleanup?()
      return written
    }
    ownerToken = token
    changeCount = count
    self.cleanup = cleanup
    guard written else { clear(); return false }
    let expiry = DispatchWorkItem { [weak self] in self?.clear() }
    self.expiry = expiry
    DispatchQueue.main.asyncAfter(deadline: .now() + lifetime, execute: expiry)
    return true
  }

  func clear() {
    expiry?.cancel()
    expiry = nil
    let token = ownerToken
    let count = changeCount
    let cleanup = self.cleanup
    ownerToken = nil
    changeCount = nil
    self.cleanup = nil
    if let token, let count, owns(token, changeCount: count) { pasteboard.clearContents() }
    cleanup?()
  }

  private func owns(_ token: String, changeCount: Int) -> Bool {
    guard pasteboard.changeCount == changeCount,
          let items = pasteboard.pasteboardItems, items.count == 1,
          items[0].string(forType: Self.ownership) == token else { return false }
    return pasteboard.changeCount == changeCount
  }
}
