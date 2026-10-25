#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
scratch=${1:-$(mktemp -d "${TMPDIR:-/tmp}/ardia-password-authorization.XXXXXX")}
if [[ $# -eq 0 ]]; then
  trap 'rm -rf -- "$scratch"' EXIT
fi
mkdir -p "$scratch"
swiftc "$root"/packages/sync/ios/Core/*.swift "$root/packages/sync/ios/PasswordSync.swift" "$root/packages/sync/ios/PasswordSyncRecords.swift" "$root/packages/sync/ios/PasswordSyncCoordinator.swift" "$root/packages/sync/scripts/password-authorization.swift" -o "$scratch/password-authorization-check"
"$scratch/password-authorization-check" "$scratch/fixtures"
