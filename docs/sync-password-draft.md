# Password sync: blocked draft

Scoped proposal for [#241](https://github.com/mantrakp04/ardia/issues/241), based on `69c5405d`.
This draft does not close the umbrella issue and is not ready to ship.

## Blocking P1: cached presenter is not a database CAS

The Chromium endpoint compares expected credentials against the presenter's cached values,
then submits an unconditional password-store mutation. A queued local edit, or a committed
edit whose presenter notification has not arrived, can still be overwritten. The endpoint's
compare-and-set name does not establish atomicity or durability.

Required follow-up: compare database-current values and insert, update or delete in one
transaction on Chromium's backend sequence; report committed/conflict/error only after the
transaction, retain notifications, and honor revocation and shutdown for queued work. Actual
Chromium regressions must cover delayed notifications, local edits and deletion, expected
absence, commit failure, revocation and shutdown. This snapshot intentionally does not attempt
that backend fix.

## Included boundaries

- Password sync defaults off and needs explicit native device-owner authorization bound to
  the folder, chain, profile and scope. Saved preferences never authorize access.
- Typed Chrome services replace the importer's raw database reader. JavaScript sync receives
  native-sealed records and authenticated fingerprints, not plaintext credentials.
- Remote payloads, snapshots, local state and journals preserve legacy password values and
  causal metadata by transforming them before crossing the native bridge. Invalid inputs fail
  closed rather than silently becoming empty replicas. Exact Unicode identities are retained.
- Apply provenance and unapplied keys are checkpointed before native mutation. Retries retain
  earlier candidates; checkpoints carry the observed HLC, and startup recovers a lower bound
  from records and journals. Creation dates survive the typed bridge.
- Denial and unavailable reads never mean an empty password store. Disabling password sync
  does not delete local passwords; other data continues syncing while passwords are paused.

Recovery exports, clipboard lifetime, recovery authorization, standalone autofill changes and
missing-folder retention are deliberately excluded. Their baseline behavior is unchanged.
DeviceOwnerAuthorization and native API version 17 are shared with the independent recovery PR.
The pod replaces the unused ArdiaImport dependency with ArdiaCore and LocalAuthentication.

## Verification and limits

Run from this exact snapshot with root dependencies wired to its own workspace packages:

- `tsc -p apps/browser` and `tsc -p packages/sync`.
- From `apps/browser`: `node --no-warnings --import ./src/test-loader.mjs --test --test-timeout=15000 src/sync/engine.test.mjs src/sync/adapters.test.mjs src/sync/sharedData.test.mjs src/sync/themePairing.test.mjs`.
- `node --test packages/sync/scripts/e2e-api.test.mjs` and `node --test 'packages/sync/src/**/*.test.ts'`.
- `swift test --package-path packages/sync --scratch-path <isolated-directory>`.
- `bash packages/sync/scripts/password-records-test.sh <isolated-directory>`.
- `bash packages/sync/scripts/password-integration.sh <isolated-directory>`.
- `bash packages/sync/scripts/password-bridge-test.sh <isolated-directory>`.

The Swift fixture stores and substituted engine endpoints test helpers, serialization and
bridge contracts, not Chromium's database or transactional behavior. A passing helper compile
is not an Expo module, complete app or Chromium build. Full Xcode and the pinned Chromium
development/test tree are unavailable; no app, OS-authentication, real-password propagation
or native module lifecycle result is claimed. The hidden E2E harness refuses password grants;
its `--non-passwords` and `--denial` modes explicitly limit coverage. No environment bypass
is added. Rendered consent UI still needs a permitted isolated app check.

Fresh checks on this independent snapshot:

| Check | Result |
| --- | --- |
| Browser and sync TypeScript checks | Both passed |
| Focused engine, adapter, sharing and theme tests | 125 passed, one existing skip |
| Sync package and mocked E2E API tests | 40 passed |
| Password record boundary runner | 705 checks passed |
| Password bridge/coordinator fixture runner | 519 assertions passed, including 84 rejected mixed Unicode inputs and 84 accepted opaque equivalents |
| Swift bridge runner, adapter typecheck and substituted ObjC endpoint runner | Passed |
| Reconstructed SyncModule Swift parse and podspec Ruby syntax | Passed; not a module/app build |
| SwiftPM tests | Blocked: `XCTest` cannot be resolved with `/Library/Developer/CommandLineTools` |

Source audit confirmed recovery entrypoints and export helpers exactly match `69c5405d`,
SyncSheets and the page script are unchanged, no new recovery-export helper is present or
referenced, and the missing-chain reset matches the baseline. That baseline reset still
forgets the key and clears sync state: the independent missing-folder PR owns changing it.
Password records and causal metadata are retained by the opaque migration; focused restart,
partial-apply, failed-checkpoint and HLC regressions passed. No real browser profile was used.
