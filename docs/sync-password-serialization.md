# Strict password serialization prerequisite — not enabled

The serialization patch adds three internal password-store helpers and their real
Chromium test definitions. Incoming password mutations remain disabled. The manager
does not yet consume these helpers; this is not working two-way password sync.

## Contract

`password_manager::internal::DecodeSyncAlternativeUsernames`, `DecodeSyncGaiaIdHashes`
and `DecodeSyncFormData` take owned byte vectors and return optional owned values.
An invalid nonempty blob returns no value, never a partial collection or a default
form. Empty legacy BLOBs deliberately decode to empty values. A zero-payload Pickle
is valid for an empty pair/hash stream, but invalid FormData without its version.

The caller must first validate SQLite storage class and permitted NULLs. These
helpers cannot distinguish a SQL NULL from a deliberately supplied empty vector.
The manager must retain raw bytes and storage classes separately for lossless
updates; it must not reserialize legacy data as a newer format.

The helpers validate the fixed Pickle envelope, exact payload extent, complete
record pairs, hash width, string lengths, alignment spans and complete consumption.
Valid nonzero padding is accepted. Counts are bounded by remaining payload rather
than an arbitrary small record limit. Text uses strict UTF conversion and an exact
round trip. Length-delimited text may contain U+0000; URLs, origin spellings and
control-type strings may not.

FormData preflight follows Chromium 155.0.8059.84's form versions 1–8 and field
versions 1–11, including persisted values that the ordinary decoder discards. It
checks full-width boolean slots, known current enum/control/property domains and
canonical URL/origin spellings before invoking the existing boolean deserializer
and checking its complete consumption. Empty URLs and the opaque origin spelling
`null` remain valid. The retired Section6 check-status field is an ignored integer
in this pin, not a current enum; the helper consumes its full integer width without
claiming validation of a historical domain absent from the pinned declarations.

## Evidence and limits

Independent source review found no actionable defects in the three helper/test
files or the separate GN membership changes. Main independently verified candidate
hashes, exact patch application, byte equality and composition with the delivered
execution foundation. All 43 combined exact-tag reference hashes matched fresh
fetches. These are source checks, not compilation or runtime verification.

All **18 real `LoginDatabaseSyncSerializationTest` definitions are uncompiled and
unrun**. They include current serializer-produced populated forms, all 88 supported
form/field version combinations, the public pinned v43 SQL fixture, malformed and
truncated records, and positive control/enum/text cases. Their presence and source
review do not establish that they compile or pass. No portable imitation parser is
offered as Chromium evidence.

The implementation and tests belong to the existing non-Android password-store
targets; the test target is reachable through `//components:components_unittests`.
Actual GN generation/include checks, Chromium compilation and focused gtest
execution remain required.

This prerequisite supplies neither strict live-schema/scalar/crypto/auxiliary
validation nor transaction ownership, database-current manager staging, paired
profile/account coordination, authorization lifecycle or native date-preserving
round trips. Those remain separate gates in [the storage candidate](sync-password-storage.md).
Do not enable writes based on this source review or the passing JS tests.
