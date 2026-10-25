# Password sync: blocked draft

Scoped proposal for [#241](https://github.com/mantrakp04/ardia/issues/241), based on `69c5405d`.
This draft does not close the umbrella issue and is not ready to ship.

## Blocking P1: incoming password updates are paused

The reviewed Chromium endpoint compared expected credentials against the presenter's cached
values, then submitted an unconditional password-store mutation. A queued local edit, or a
committed edit whose presenter notification had not arrived, could be overwritten. That path
has been removed: `ac_passwords_sync_compare_and_set` now completes with false/unavailable
before profile resolution, argument parsing, authorization callbacks or password-store access.
It refuses inserts, updates, deletes and equal-value/no-op requests. Ordinary user password
manager actions are unchanged. This removes unsafe sync writes; it does not implement CAS,
finish password import/sync or make this PR merge-ready. The existing Boolean ABI cannot
distinguish unavailable from a database conflict; callers must not treat refusal as success.

Required follow-up: compare database-current values and insert, update or delete in one
transaction on Chromium's backend sequence; report committed/conflict/error only after the
transaction, retain notifications, and honor revocation and shutdown for queued work. Actual
Chromium regressions must cover delayed notifications, local edits and deletion, expected
absence, commit failure, revocation and shutdown. This snapshot intentionally does not attempt
that backend fix.

New-source insertion must also carry the source creation timestamp through the authenticated
record, apply change, typed bridge and conditional database insertion. The disabled insertion
path no longer creates a credential with the wrong current-time date, but date-preserving
insertion is still a blocked requirement. Existing read timestamps, including epoch zero and
unknown dates, are preserved; retaining read timestamps alone does not solve insertion.

## Unsupported snapshots pause the whole password collection

Before delivering any login rows, the native read validates every password credential's
origin/username identity. Multiple distinct affiliated origins, unsupported origins or a
duplicate identity make the entire read unavailable, regardless of collection order or whether
duplicates carry equal passwords. It does not skip an ambiguous row or silently choose a
duplicate: an omitted row could otherwise be published as a deletion. Passkeys, blocked-site
entries and federated logins remain outside the password collection.

Supported origins are lowercase HTTP(S), authority-only and ASCII (Chromium normally stores
internationalized hosts as punycode); raw Unicode hosts, other schemes, paths, query strings,
fragments and whitespace fail the whole read rather than reaching Swift's unsupported-key
skip. This is conservative validation of the draft's identity format, not a full URL parser.

The native bridge buffers rows and discards the buffer on failure or revocation, returning
`nil`, never a partial successful snapshot. This deliberately pauses password publication for
affected profiles, including otherwise usable rows in the same collection. Complete grouped
credential identity, mutation and conflict handling remain unimplemented. The Swift holder's
pre-existing duplicate rejection was already fail-closed; this change improves the native
boundary and explicitly accepts reduced availability, not a new confidentiality fix.

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
  from records and journals. Read creation dates survive the typed bridge; incoming mutations
  are disabled and date-preserving insertion is not implemented.
- Denial and unavailable reads never mean an empty password store. Disabling password sync
  does not delete local passwords; other data continues syncing while passwords are paused.

Recovery exports, clipboard lifetime, recovery authorization, standalone autofill changes and
missing-folder retention are deliberately excluded. Their baseline behavior is unchanged.
DeviceOwnerAuthorization is shared with the independent recovery PR. This branch pairs native
API version 17; the recovery branch now pairs version 18 for its request-scoped copy contract.
Reconcile the version pair and overlapping module changes when either branch lands.
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
- `node --test packages/sync/scripts/password-native-policy.test.mjs`.

The Swift fixture stores and substituted engine endpoints test helpers, serialization and
bridge contracts, not Chromium's database or transactional behavior. A passing helper compile
is not an Expo module, complete app or Chromium build. Full Xcode and the pinned Chromium
development/test tree are unavailable; no app, OS-authentication, real-password propagation
or native module lifecycle result is claimed. The hidden E2E harness refuses password grants;
its `--non-passwords` and `--denial` modes explicitly limit coverage. No environment bypass
is added. Rendered consent UI still needs a permitted isolated app check.

The native policy runner compiles the production snapshot-validation header and the exact
mutation entrypoint extracted from `ac_passwords.cc`, with no substituted store/presenter
implementation. Under AddressSanitizer and UndefinedBehaviorSanitizer it tests 22 identity
collections and 10 mutation refusal/null-completion cases, including inaccessible input
pointers that must never be dereferenced. It separately compiles the production reply-buffer
and callback code extracted from `ArdiaCoreEngineBridge.mm` to verify failed and revoked
snapshots discard buffered rows and clear owned argument buffers. A source-wiring check
confirms native collection validation precedes row callbacks. These checks passed; they do
not compile the Chromium-dependent read path, exercise a real store race, or replace the
required pinned-Chromium database regressions. Scratch outputs are removed after each run.

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
