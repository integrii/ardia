#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
scratch=${1:-$(mktemp -d "${TMPDIR:-/tmp}/ardia-recovery.XXXXXX")}
mkdir -p "$scratch"
swiftc "$root/packages/sync/ios/Core/DeviceOwnerAuthorization.swift" "$root/packages/sync/ios/Core/RecoveryClipboard.swift" "$root/packages/sync/ios/Core/RecoveryExports.swift" "$root/packages/sync/scripts/recovery-protection/main.swift" -o "$scratch/recovery-check"
"$scratch/recovery-check" "$scratch/recovery-fixtures"
"${NODE:-node}" "$root/packages/sync/scripts/recovery-protection/ui-check.cjs"
