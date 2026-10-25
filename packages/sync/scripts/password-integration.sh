#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
if [[ -n "${1:-}" ]]; then
  scratch=$1
else
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/ardia-passwords.XXXXXX")
  trap 'rm -rf -- "$scratch"' EXIT
fi
mkdir -p "$scratch"
swiftc "$root"/packages/sync/ios/Core/*.swift "$root/packages/sync/ios/PasswordSync.swift" "$root/packages/sync/ios/PasswordSyncRecords.swift" "$root/packages/sync/ios/PasswordSyncCoordinator.swift" "$root/packages/sync/scripts/password-integration.swift" -o "$scratch/password-check"
"$scratch/password-check" "$scratch/password-fixtures"
