#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
scratch="${1:?Supply an isolated scratch directory}"
mkdir -p "$scratch"
core="$root/packages/sync/ios/Core"
swiftc "$core/SyncCrypto.swift" "$core/RecoveryPhrase.swift" "$core/Wordlist.swift" \
  "$core/LegacyMigration.swift" "$core/LegacyDockTile.swift" "$core/SyncKeyStore.swift" "$core/PasswordRecords.swift" \
  "$root/packages/sync/ios/PasswordSync.swift" "$root/packages/sync/ios/PasswordSyncRecords.swift" \
  "$root/packages/sync/scripts/PasswordSyncBridgeTests.swift" -o "$scratch/password-sync-tests"
"$scratch/password-sync-tests"
swiftc -typecheck -I "$root/packages/sync/scripts/password-bridge-module" \
  "$root/packages/sync/ios/PasswordSync.swift" "$root/packages/sync/ios/ChromePasswordSyncStore.swift"
xcrun clang++ -std=c++20 -fobjc-arc -fblocks -Wno-incomplete-implementation -Wno-objc-property-implementation \
  -I "$root/engine/ardiacore/src/ardia/core/public" -I "$root/packages/ardiacore/ios" \
  "$root/packages/ardiacore/ios/ArdiaCoreEngineBridge.mm" "$root/packages/sync/scripts/PasswordSyncNativeBridgeTests.mm" \
  -framework Foundation -framework AppKit -Wl,-export_dynamic -o "$scratch/native-bridge-tests"
"$scratch/native-bridge-tests"
