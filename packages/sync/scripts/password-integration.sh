#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
scratch=${1:-$(mktemp -d "${TMPDIR:-/tmp}/ardia-passwords.XXXXXX")}
mkdir -p "$scratch"
swiftc "$root"/packages/sync/ios/Core/*.swift "$root/packages/sync/ios/PasswordSync.swift" "$root/packages/sync/ios/PasswordSyncRecords.swift" "$root/packages/sync/ios/PasswordSyncCoordinator.swift" "$root/packages/sync/scripts/password-integration.swift" -o "$scratch/password-check"
"$scratch/password-check" "$scratch/password-fixtures"
