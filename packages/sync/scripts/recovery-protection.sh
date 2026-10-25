#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
if [[ $# -eq 0 ]]; then
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/ardia-recovery.XXXXXX")
else
  mkdir -p "$1"
  scratch=$(mktemp -d "$1/recovery-check.XXXXXX")
fi
trap 'rm -rf -- "$scratch"' EXIT
python3 - "$root/packages/sync/ios/SyncModule.swift" "$scratch/RecoveryOperationFixture.swift" <<'PY'
import pathlib
import sys
source = pathlib.Path(sys.argv[1]).read_text()
start = source.index("  private func recoveryOperation<")
end = source.index("\n  private func clipboard()", start)
method = source[start:end].replace("private func", "func", 1)
pathlib.Path(sys.argv[2]).write_text("import Foundation\nextension RecoveryOperationFixture {\n" + method + "\n}\n")
PY
swiftc "$root/packages/sync/ios/Core/DeviceOwnerAuthorization.swift" "$root/packages/sync/ios/Core/RecoveryClipboard.swift" "$root/packages/sync/ios/Core/RecoveryExports.swift" "$scratch/RecoveryOperationFixture.swift" "$root/packages/sync/scripts/recovery-protection/main.swift" -o "$scratch/recovery-check"
"$scratch/recovery-check" "$scratch"
"${NODE:-node}" "$root/packages/sync/scripts/recovery-protection/ui-check.cjs"
