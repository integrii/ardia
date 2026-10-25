# Password storage candidate: not enabled

PR308 still refuses incoming password mutations. The new store patch is an implementation
candidate, not an engine that has passed database tests. Do not enable either mutation endpoint
from helper-test results or source inspection alone.

## Pinned source and application evidence

- Chromium `155.0.8059.84`, as pinned by `engine/patches/build/env.sh`.
- Helium Chromium `0.19.4`, commit `832faa7822566270e10c0d3262f702f9d0fea81f`.
- Helium macOS `0.19.4.1`, commit `d049c7d9c42f2c4d6d039e6bb05f3c67ddf15524`.
- Candidate: `engine/patches/chromium-password-sync-transaction.patch`.

The patch was generated against the exact tagged Chromium files after the applicable Helium
domain substitutions. Fifty-seven original file hashes and both downloaded Helium archives
were checked. An audit of 406 preceding patch entries found no path overlaps with the candidate.
Read-only `git apply --check` and a zero-fuzz application passed against reconstructed baselines.
This checks source provenance and application, not C++ compilation, linking or runtime behavior.

## Checked SQL prerequisite, not integrated

`engine/patches/chromium-password-sync-checked-transactions.patch` adds opt-in
`sql::Transaction::BeginImmediate`, `IsActive`, `CommitChecked` and `RollbackChecked`.
It applies before the separate manager candidate. The manager candidate does not
yet use these APIs; its ordinary mutation fallback remains unsafe as described below.

Immediate mode refuses ambient wrapper or physical transactions, locks before any
comparison read, and checks physical termination on commit, explicit rollback and
destruction. Failed termination or a failed post-termination schema-read health
probe non-destructively poisons the captured connection. Old guards cannot touch a
closed/reopened connection incarnation. Confirmed commit and connection health are
separate sticky results; an unhealthy connection does not erase a confirmed commit.
Ordinary transaction callers keep their existing behavior unless immediate mode is used.

This is not a statement barrier. Staging must check the active guard before each
SQL step, stop after the first failure, and never reuse ordinary multi-statement
mutators. It also needs checked bindings and statement cleanup: ordinary void bind
methods cannot certify success, and a failed SQLite binding can be followed by a
successful execution using NULL instead of the requested value. Strict statement
integration, lossless manager reads, narrow staging and the shared-store coordinator remain unfinished.
Raw rollback/rebegin on the same connection is not detected by an active guard;
the coordinator must exclude that reentrancy rather than claim it is safe.

`engine/patches/chromium-password-sync-checked-statements.patch` follows the immediate
transaction prerequisite and adds a separate, single-use `sql::CheckedStatement`.
It observes actual bind return codes, latches failure, blocks execution after failure
or missing bindings, and owns its noncached statement privately. Run refuses result
columns before stepping; Step refuses non-readonly SQL before stepping and cannot
restart after DONE. Typed copied readers keep NULL, empty values and access errors
distinct, without storage-class coercion or borrowed output memory. Readonly status
is not an arbitrary-SQL sandbox; manager schema and reentrancy restrictions still apply.

Explicit Finish records reset, clear-bindings and finalize results separately. Every
non-OK cleanup result conservatively poisons only the captured live connection,
including a reset that repeats a prior step error. Callback-driven close/reopen cannot
authorize cleanup of the new incarnation. Terminal results stay immutable; destructor
cleanup is not a substitute for an explicitly checked completion before commit.
Ordinary Statement/cache paths and existing test bodies are unchanged.

The checked-statement follow-up has SHA-256
`8b41e211a055a386d3c834f5c5acf05290ff266b6eb5077c84e8f5ef5cc6a7dc`.
Independent six-file source review found no actionable defects. Main verified strict
application, zero-fuzz/no-offset replay, source equality, whitespace, baseline/support
hashes and preservation of all 14 existing Statement test bodies. Eleven pristine
inputs were independently refetched from the exact tag; four modified SQL inputs
were bound to the accepted immediate prerequisite.

All 26 added real checked-statement gtest definitions are **uncompiled and unrun**.
Bind/conversion OOM and VFS fault induction remain unverified. No independent real
reset-only, clear-bindings-only or finalize-only failure inducer is established; those
coverage gaps remain open despite conservative source handling. System SQLite probes
do not execute Chromium CheckedStatement. The manager does not yet use this API;
strict capability/schema/Unicode/Pickle policy, narrow staging, paired-store operation
and actual native verification remain mandatory before enabling incoming writes.

The separate SQL patch has SHA-256
`879ca744208df22d61f55807025a8c458c14b5341b6cb589f96d5ca671ab8065`.
Eighteen new real SQL gtest definitions cover immediate contention, physical commit
failure, automatic rollback, checked cleanup, incarnation changes and quarantine.
They remain **uncompiled and unexecuted**. The four unusable-drive cases use a
specialized VFS that still forwards physical close/unlock while injecting read/write
faults; otherwise the fault fixture would itself leak file resources and locks.
Independent source review found and repaired that fixture defect, with no remaining
actionable findings in the bounded correction.

Main verified exact pinned input hashes, strict patch application, zero-fuzz/no-offset
replay, source equality and whitespace. A read-only audit found no overlapping SQL
paths in 406 preceding patch entries or the manager patch. This is not a full-series
build, C++ compilation, actual VFS behavior, native lifecycle verification or permission
to enable incoming writes. All existing transaction-test bodies remain unchanged.

## Intended transaction contract

`PasswordStoreInterface::CompareAndSetLogin` dispatches to the backend sequence. Unsupported
backends return error. `LoginDatabase::CompareAndSetLogin` rejects an existing transaction,
reads database-current credentials, checks the exact origin and username, rejects ambiguity,
then conditionally inserts, updates or deletes in one outermost transaction. Presenter state
is not the comparison source. Decryption failure cannot trigger ordinary undecryptable-row
cleanup during this conditional read.

The authorization lease guards the final permission check and physical SQL commit. Successful
native Begin must be paired with End on the same backend thread after commit or rollback;
denied Begin is not paired with End. No UI authorization callback runs on that sequence.
Committed status is not changed by a later revocation. An admitted commit may finish after
expiry; synchronous revocation waits for it, and later queued requests cannot obtain permission
after revocation returns. This is a commit-permission boundary, not a disk-write deadline.

Sleep, session and screen-lock notifications currently invalidate authorization when their
main-queue callbacks run. Revocation takes effect when that callback acquires the native
authorization gate; an earlier admitted commit may finish. A blocked main queue can delay
notification delivery. This is not a guarantee that no commit follows the physical instant
of lock or sleep. Independently delivered event-receipt enforcement would require a verified
native event source and separate lifetime/locking tests.

Original monotonic grant expiry and the overall operation deadline constrain native requests.
They are not renewed for each store call. Key replacement synchronously revokes registered
leases before publishing its new generation. An actively tracking Chromium sync-metadata
processor is unsupported, because its ordinary precommit in-memory changes are not reversible
on native revocation.

The source creation field is authenticated inside the opaque credential. Inserts preserve a
representable source date, including Unix epoch zero; updates retain the current database date.
Unknown stays unknown. Receiver wall-clock ordering is not a validity check. Known 1601-01-01
cannot be represented separately from Chromium's null timestamp: the future enabled parser
must reject that exact known value. Older clients may strip optional creation metadata.

## Tests added, not executed

Twenty-four gtest definitions exercise the actual LoginDatabase or built-in backend, not a copied CAS
algorithm. They cover source dates, stale comparisons, absence and deletion, rollback, nested
transactions, outer-commit refusal after a nested rollback marker, native permission denial,
expiry and revocation, identity
ambiguity, presenter notifications, a queued local write and backend shutdown.

The rollback-marker test does not induce a failing SQLite `COMMIT` statement. A separate new
definition uses a deferred foreign-key violation on the actual database connection, requires
the failing statement to be `COMMIT`, and checks rollback before native End. Other definitions
exercise decrypt/encrypt failures with pinned OSCrypt test encryptors and tracked-sync refusal
through the real database helper. A Python SQLite probe confirms only the deferred-constraint
mechanism, not Chromium behavior. None of these definitions have been compiled or run.

Three definitions were corrected for LoginDatabase's default exclusive SQLite locking. Native
End now inspects the live owning connection with checked queries and transaction-state checks.
The owner is destroyed before a separate connection checks durable disk state. The shared
column-query helper also asserts successful query completion, so a query error cannot appear
to be an empty table. Independent source review and fresh pinned-source application checks
passed; a Python locking probe is mechanism evidence only, not execution of these gtests.

Required runtime evidence includes queued
and committed-but-unnotified local edits, conditional insertion/update/deletion, commit failure,
revocation/expiry, shutdown and callback-context survival until every queued borrower drains.

## Unfinished gates

Source review has identified additional defects in this disabled candidate. Ordinary `AddLogin`
may retry using replacement after a statement error automatically rolls back SQLite's
transaction. That retry can write outside the intended transaction before native permission
is checked. Broad `UpdateLogin` and auxiliary notes/issues readers also do not provide strict
failure propagation or preservation of unrelated metadata. Existing transaction wrapper counts
do not prove physical rollback completion. A synthetic SQLite probe demonstrates the automatic
rollback/fallback mechanism only; it is not execution of this candidate. The passing source
checks and unexecuted test definitions do not establish safety against these defects.

A separate checked immediate-transaction SQL slice and narrow fail-fast mutation staging are
required before coordinated profile/account-store integration. Neither is complete here.

1. Wire the versioned engine endpoint to the real backend without a presenter fallback.
2. Define a safe atomic contract for collisions spanning independent profile/account stores.
3. Tie profile teardown and every timeout to cancellation without freeing borrowed contexts.
4. Build the pinned patched Chromium framework and execute the real storage regressions.
5. Build the complete app with full Xcode and exercise native lifecycle behavior in an isolated,
   hidden instance. Helper compilation and substituted engine endpoints do not meet this gate.
6. Obtain normal authorized review of GitGuardian's historical synthetic-fixture findings.

No real browser profile, installed app, Chromium build output or shared checkout index was used
to construct or test this candidate.
