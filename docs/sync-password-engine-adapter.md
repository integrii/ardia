# Password engine adapter candidate: still disabled

The source now contains the engine-to-storage handoff for Chromium
155.0.8059.84 plus the conditional-store candidate. It has not been compiled
against Chromium or exercised against SQLite. `ARDIA_PASSWORD_SYNC_CHROMIUM_VERIFIED`
is a source-owned zero in `ac_passwords_sync_adapter.h`. The production v2
export immediately returns error without dereferencing profile or JSON pointers,
calling authorization, or queuing work. There is no environment, JavaScript,
runtime, or command-line override. Do not change the latch based on helper tests.
The five-argument legacy mutation always returns zero; reads retain binary 0/1.

## Input and storage boundary

The internal path bounds the JSON to 64 KiB using `SensitiveArgs`, then applies
shared typed-field validation. Presence booleans distinguish expected absence,
password replacement and deletion. Secret fields must agree with those booleans;
ambiguous plain-plus-hex fields, wrong types and extra fields are rejected.
The Chromium-specific parser validates canonical HTTP(S) origin identity, UTF-8,
UTF-16 lengths, nonempty replacement and the actual mutation's `IsValid()`.

`desiredCreated` is authenticated source creation metadata, not receiver time.
Absent or null is unknown. Known finite Unix milliseconds in the inclusive
JavaScript/Swift range are passed as `double` to the pinned `base::Time` overload,
including fractional milliseconds and Unix zero. Storage representation has
Chromium's microsecond precision; the adapter does not first truncate to integer
milliseconds. The single known
1601-01-01 value `-11644473600000` is rejected before `base::Time` conversion;
its adjacent milliseconds remain permitted. Any known input that converts to
Chromium's null time is also rejected rather than silently becoming unknown.
Storage preserves the current
database creation date on update.

`DispatchSyncMutation` calls the pinned `PasswordStoreInterface::CompareAndSetLogin`
with `ConditionalLoginMutation`, `PasswordStoreAuthorizationLease` and its actual
status callback. Neither presenter data nor cached credential presence is used
for comparison or insertion decisions. Only the storage transaction decides.
Statuses map exactly to committed 1, conflict 0, error -1 and unauthorized -2.
Completion does not recheck authorization and cannot downgrade a committed result.

## Whole-profile account policy

Atomic logical identity across two independent profile/account databases remains
unsupported. Both read and mutation submission query both factories with explicit
access, and reject the entire operation if an account store exists, even if that
store appears empty or signed out. A read returns no rows and binary failure;
it never presents a profile-only snapshot as complete account-inclusive data.

The pinned default desktop account-store factory constructs a store even without
a signed-in account. Consequently ordinary profiles using that factory are
unavailable for password sync under this deliberately conservative policy.
Ardia having no account UI does not prove the underlying account database absent.
Only a configuration where the account factory truly supplies no second store
can use the internal single-store path. No cached emptiness exception is provided.
Full account-store/cross-store CAS is not implemented or claimed.

## Lifetime and ordering

UI authorization runs only at submission. Engine lease construction receives the
absolute engine-operation deadline computed once on entry, never a renewed
deadline. The independently retained native lease still enforces the original
native request and authentication deadlines inside its thread-safe Begin gate.
Neither a delayed engine submission nor another database call renews native grants.

An engine-owned shared commit context forwards backend Begin and End to the
original native context on the same thread and never dispatches to main. It records
successful End as sticky committed, including when a completion closure is later
discarded. The completion closure strongly owns the engine request and its commit
context. The profile registry, main-loop registry and ten-second cancellation
task hold weak references. Timeout only synchronously
revokes the engine lease; it does not invoke C done while backend work is queued.
Native UI timeout independently cancels its lease while retaining its holder until
the eventual engine done callback.

Actual Chromium profile destruction calls `ProfileState::Release()`. This closes
the profile registration gate, synchronously revokes and drains every registered
engine lease, then completes the drained requests exactly once with unauthorized
or their sticky committed result. All leases are drained before any terminal
callback runs. Weak pointers and the delegate are then released. Ardia's regular
public profile-release operation is a no-op and does not invoke this hook; it is
not claimed as an earlier profile-close boundary.

A process-lifetime `NoDestructor<shared_ptr<...>>` in `TrackSyncMutation` independently
owns a `CurrentThread::DestructionObserver`, registered on the actual main execution
environment before backend submission. It has no profile pointer and therefore
does not depend on profiles being destroyed first. If no current execution
environment exists, submission fails closed. Its callback unregisters itself,
keeps its owner alive across reentrant C done, closes the global registration gate,
drains all leases, and directly completes requests on main without posting a task.
The closed process-lifetime owner prevents new registrations during final cleanup.

Pinned `base/task/current_thread.h` lines 104–131 guarantees notification before
`CurrentThread::IsSet()` becomes false and permits removal during the callback.
`SequenceManagerImpl` unregisters queues at lines 200–203 before notifying destruction
observers at lines 214–217. Thus this is synchronous final main-thread cleanup
after queues can already reject posts, not a claim of an earlier notification
before posting fails. It does not require the reply runner to accept a profile
callback or deletion task. The native C done implementation runs directly when
already on main. No ordinary task is posted from this cleanup path.

Cancellation only acquires the engine lease mutex, waits for already admitted
commit/End borrowers, and returns. All terminal callbacks occur after that mutex
is released; no main dispatch, profile lookup or UI authorization runs while it
is held.

Normal backend completion revokes first, then invokes C done outside the gate,
exactly once. A discarded completion closure also revokes synchronously before
its request destructor reports error, or preserves sticky committed after a recorded
successful End: future queued lease holders cannot invoke
Begin/End on the released native context. This drain/cancellation fallback is not
a timer-based completion. Completion destruction is only a fallback: pinned
`base/threading/post_task_and_reply_impl.cc` lines 67–84 intentionally leaks a relay
if both reply posting and origin-sequence deletion fail during shutdown. The
independent profile/main-loop drain paths release the borrowed native context even
if that relay and its C++ request remain alive forever. A retained revoked lease
cannot forward a later Begin or End to the released context. The real built-in
backend handles rejected database
posts with an error reply; rejection of the engine cancellation-task post reports
one error without submitting storage work.

Native event revocation takes effect when the invalidation callback acquires the
native authorization gate. Commits admitted earlier may finish. Main-queue event
delivery can be delayed; neither this candidate nor the fixture tests prove that
no commit follows the physical instant of lock, sleep or another OS event.

## Verification and remaining gates

The underlying disabled storage candidate also has known unresolved SQL safety defects:
ordinary insertion fallback can continue after automatic rollback, broad updates can touch
unrelated metadata, and existing wrappers do not prove physical rollback termination. See
`sync-password-storage.md`. This adapter's ownership/helper results do not repair those defects
or justify enabling the handoff. Checked SQL transactions, narrow staging and paired database
reads remain separate unfinished work.

The focused Node test runner compiles the real adapter/input helper headers under
ASan/UBSan and TSan with a gated fixture backend. It checks fractional creation metadata,
absence/replacement/delete handoff, four status values, queued timeout cancellation,
profile cancellation, committed-before-notification behavior, callback destruction,
post rejection, reentrant completion, replies retained across profile and loop
shutdown, native-context destruction before any late reply, and 300 commit/revoke
races. The loop fixture rejects posts before delivering the destruction observer;
completion still runs synchronously. Retained fixture replies are only released
after these assertions; the tests use no leak suppression or forced process exit.
Its JSON dictionary
fixture uses Foundation; it is not Chromium's JSONReader, a storage implementation,
or an OS-event integration test. The old compatibility test additionally compiles
the exact production legacy/v2 export bodies and passes inaccessible pointers to
prove default-build refusal happens before any dereference or authorization.

The exact read-submission body is also compiled against fixture factories for all
four store topologies: a second store prevents presenter access, rows and successful
completion rather than silently filtering the account side.

`password_sync_adapter_unittests` defines ten unexecuted Chromium gtests against
the real parser, real candidate authorization-lease types, real `LoginDatabase`
creation-date preservation, and real `SingleThreadTaskExecutor` destruction.
The standalone target explicitly owns every reused local header and declares its
storage/OSCrypt test dependencies. The include-graph/source review is not a
successful GN generation or C++ build. The test translation
unit also instantiates the dispatch helper against the actual
`PasswordStoreInterface` signature. These definitions still need a real pinned
Chromium build and execution, as do the storage owner's database regressions.

Required before any enabling change: real framework/compiler/linker evidence,
actual SQL/crypto/active-sync regressions, native invalidation and profile teardown
integration with queued work, lifetime review, full app build and hidden-instance
exercise. No app, real profile, Chromium build output, Git index or ref was used
to develop this adapter.
