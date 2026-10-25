#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
scratch="${1:?usage: password-records-test.sh <isolated scratch directory>}"
mkdir -p "$scratch"
core="$root/packages/sync/ios/Core"
if ! swiftc -parse-as-library \
  "$core/SyncCrypto.swift" "$core/RecoveryPhrase.swift" "$core/Wordlist.swift" \
  "$core/LegacyMigration.swift" "$core/LegacyDockTile.swift" "$core/SyncKeyStore.swift" \
  "$core/PasswordRecords.swift" "$root/packages/sync/scripts/PasswordRecordsBoundaryTests.swift" \
  -o "$scratch/password-records-boundary-tests" > "$scratch/password-records-build.log" 2>&1; then
  cat "$scratch/password-records-build.log" >&2
  exit 1
fi
"$scratch/password-records-boundary-tests"
