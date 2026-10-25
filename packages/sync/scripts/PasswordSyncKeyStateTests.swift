import Foundation

struct SyncKeys {
  let entropy: Data
}

struct PasswordSyncKeySnapshot {
  let keys: SyncKeys
  let generation: UInt64
}

final class ObservedNativeKeyState: ArdiaCorePasswordSyncKeyState {
  var beforeReplace: (() -> Void)?
  var afterReplace: (() -> Void)?

  override func replaceGeneration(_ generation: UInt64) {
    beforeReplace?()
    super.replaceGeneration(generation)
    afterReplace?()
  }
}

private func wait(_ event: DispatchSemaphore) {
  precondition(event.wait(timeout: .now() + 3) == .success)
}

@main
struct PasswordSyncKeyStateChecks {
  static func main() {
    let native = ObservedNativeKeyState()
    let state = KeyState(passwordAuthorizationState: native)
    let first = Data(repeating: 1, count: 32)
    let second = Data(repeating: 2, count: 32)
    state.set(first)
    let authorization = ArdiaCorePasswordSyncAuthorization(profiles: ["fixture"], expiresAt: ProcessInfo.processInfo.systemUptime + 60,
                                                          keyState: native, generation: 1)!
    let request = authorization.request(profile: "fixture", expiresAt: ProcessInfo.processInfo.systemUptime + 10)!
    let committing = DispatchSemaphore(value: 0)
    let releaseCommit = DispatchSemaphore(value: 0)
    let committed = DispatchSemaphore(value: 0)
    let replacing = DispatchSemaphore(value: 0)
    let revoked = DispatchSemaphore(value: 0)
    let releasePublication = DispatchSemaphore(value: 0)
    let changed = DispatchSemaphore(value: 0)
    native.beforeReplace = { replacing.signal() }
    native.afterReplace = {
      revoked.signal()
      wait(releasePublication)
    }
    DispatchQueue.global().async {
      precondition(ArdiaTestPasswordSyncBeginCommit(request) == 1)
      committing.signal()
      wait(releaseCommit)
      precondition(state.keys?.entropy == first)
      ArdiaTestPasswordSyncEndCommit(request, 1)
      committed.signal()
    }
    wait(committing)
    DispatchQueue.global().async {
      state.set(second)
      changed.signal()
    }
    wait(replacing)
    let readDuringRevocation = DispatchSemaphore(value: 0)
    DispatchQueue.global().async {
      precondition(state.passwordSnapshot?.generation == 1 && state.keys?.entropy == first)
      readDuringRevocation.signal()
    }
    wait(readDuringRevocation)
    precondition(changed.wait(timeout: .now()) == .timedOut)
    releaseCommit.signal()
    wait(committed)
    wait(revoked)
    let stale = state.passwordSnapshot!
    precondition(stale.generation == 1 && stale.keys.entropy == first)
    precondition(ArdiaCorePasswordSyncAuthorization(profiles: ["fixture"], expiresAt: ProcessInfo.processInfo.systemUptime + 60,
                                                   keyState: native, generation: stale.generation) == nil)
    precondition(ArdiaTestPasswordSyncBeginCommit(request) == 0)
    releasePublication.signal()
    wait(changed)
    precondition(state.passwordSnapshot?.generation == 2 && state.keys?.entropy == second)
    native.beforeReplace = nil
    native.afterReplace = nil
    let nextAuthorization = ArdiaCorePasswordSyncAuthorization(profiles: ["fixture"], expiresAt: ProcessInfo.processInfo.systemUptime + 60,
                                                              keyState: native, generation: 2)!
    let next = nextAuthorization.request(profile: "fixture", expiresAt: ProcessInfo.processInfo.systemUptime + 10)!
    precondition(ArdiaTestPasswordSyncBeginCommit(next) == 1)
    ArdiaTestPasswordSyncEndCommit(next, 0)
    state.set(nil)
    precondition(state.passwordSnapshot == nil && state.entropy == nil && state.keys == nil)
    precondition(nextAuthorization.request(profile: "fixture", expiresAt: ProcessInfo.processInfo.systemUptime + 10) == nil)
    let mutations = DispatchGroup()
    for _ in 0..<100 {
      mutations.enter()
      DispatchQueue.global().async {
        state.set(second)
        mutations.leave()
      }
    }
    precondition(mutations.wait(timeout: .now() + 3) == .success)
    precondition(state.passwordSnapshot?.generation == 103 && state.keys?.entropy == second)
    let detachedNative = ArdiaCorePasswordSyncKeyState()
    var detached: KeyState? = KeyState(passwordAuthorizationState: detachedNative)
    detached!.set(first)
    let detachedAuthorization = ArdiaCorePasswordSyncAuthorization(profiles: ["fixture"], expiresAt: ProcessInfo.processInfo.systemUptime + 60,
                                                                  keyState: detachedNative, generation: 1)!
    detached = nil
    precondition(detachedAuthorization.request(profile: "fixture", expiresAt: ProcessInfo.processInfo.systemUptime + 10) == nil)
    print("Production Swift KeyState + native registry: key reads survive revocation barrier; publication follows commit; stale-generation registration gap denied; forgetting synchronously revokes")
  }
}
