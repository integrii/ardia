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
"${NODE:-node}" - "$root/packages/sync/ios/SyncModule.swift" "$scratch/RecoveryOperationFixture.swift" <<'JS'
const fs = require("node:fs");
const [sourcePath, outputPath] = process.argv.slice(2);
const source = fs.readFileSync(sourcePath, "utf8");
const startMarker = "  private func recoveryOperation<";
const endMarker = "\n  private func clipboard()";
const start = source.indexOf(startMarker);
const end = source.indexOf(endMarker, start + startMarker.length);
if (start < 0 || end <= start || source.indexOf(endMarker) !== end || source.indexOf(startMarker, start + startMarker.length) >= 0 || source.indexOf(endMarker, end + endMarker.length) >= 0) {
  throw new Error("Couldn’t locate a unique bounded recoveryOperation fixture body.");
}
const method = source.slice(start, end).replace("private func", "func");
fs.writeFileSync(outputPath, "import Foundation\nextension RecoveryOperationFixture {\n" + method + "\n}\n");
JS
swiftc "$root/packages/sync/ios/Core/DeviceOwnerAuthorization.swift" "$root/packages/sync/ios/Core/RecoveryClipboard.swift" "$root/packages/sync/ios/Core/RecoveryExports.swift" "$scratch/RecoveryOperationFixture.swift" "$root/packages/sync/scripts/recovery-protection/main.swift" -o "$scratch/recovery-check"
"$scratch/recovery-check" "$scratch"
"${NODE:-node}" "$root/packages/sync/scripts/recovery-protection/ui-check.cjs"
