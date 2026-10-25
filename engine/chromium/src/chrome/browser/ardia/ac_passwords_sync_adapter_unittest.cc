#include "chrome/browser/ardia/ac_passwords_sync_adapter.h"
#include "chrome/browser/ardia/ac_passwords_sync_mutation.h"
#include "chrome/browser/ardia/ac_passwords_sync_policy.h"

#include <cmath>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "base/files/scoped_temp_dir.h"
#include "base/functional/bind.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/current_thread.h"
#include "base/task/single_thread_task_executor.h"
#include "base/test/task_environment.h"
#include "components/os_crypt/async/browser/test_utils.h"
#include "components/password_manager/core/browser/password_store/login_database.h"
#include "components/password_manager/core/browser/password_store/password_store_interface.h"
#include "components/password_manager/core/browser/password_store/stored_credential.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace ardia {
namespace {

using Status = password_manager::ConditionalLoginMutationStatus;
using Lease = password_manager::PasswordStoreAuthorizationLease;
using Mutation = password_manager::ConditionalLoginMutation;
using Request = SyncMutationRequest<scoped_refptr<Lease>>;

auto BindCompletion(auto completion) {
  return base::BindOnce(
      [](decltype(completion) completion, Status status) { completion(status); },
      std::move(completion));
}

[[maybe_unused]] void CheckPinnedInterface(
    password_manager::PasswordStoreInterface& store,
    Mutation mutation,
    std::shared_ptr<Request> request) {
  DispatchSyncMutation(store, std::move(mutation), std::move(request),
                       [](auto completion) {
                         return BindCompletion(std::move(completion));
                       });
}

std::string Input(std::string created = {}) {
  return "{\"origin\":\"https://adapter.example\",\"username\":\"fixture\","
         "\"expectedPresent\":false,\"desiredPresent\":true,"
         "\"desiredPasswordHex\":\"66697874757265\"" + created + "}";
}

struct Gate {
  int begins = 0;
  int ends = 0;
  int dones = 0;
  int status = 99;
};

int Begin(void* context) {
  ++static_cast<Gate*>(context)->begins;
  return 1;
}

void End(void* context, int) {
  ++static_cast<Gate*>(context)->ends;
}

void Done(void* context, int status) {
  auto& gate = *static_cast<Gate*>(context);
  ++gate.dones;
  gate.status = status;
}

class GatedStore {
 public:
  void CompareAndSetLogin(Mutation mutation,
                           scoped_refptr<Lease> lease,
                           base::OnceCallback<void(Status)> completion) {
    ++submissions;
    mutation_ = std::move(mutation);
    lease_ = std::move(lease);
    completion_ = std::move(completion);
  }

  Status Commit() {
    return lease_->Commit(base::BindOnce([] { return true; }));
  }

  void Reply(Status status) { std::move(completion_).Run(status); }

  int submissions = 0;
  Mutation mutation_;
  scoped_refptr<Lease> lease_;
  base::OnceCallback<void(Status)> completion_;
};

class PasswordSyncAdapterTest : public testing::Test {
 protected:
  base::test::TaskEnvironment environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

TEST_F(PasswordSyncAdapterTest, ParserRejectsKnownChromiumNullBeforeQueue) {
  Gate gate;
  GatedStore store;
  auto mutation = ParseSyncMutation(Input(",\"desiredCreated\":-11644473600000").c_str());
  EXPECT_FALSE(mutation);
  EXPECT_EQ(store.submissions, 0);
  EXPECT_EQ(gate.begins, 0);
  for (int64_t milliseconds : {-11644473600001LL, -11644473599999LL, 0LL}) {
    auto accepted = ParseSyncMutation(
        Input(",\"desiredCreated\":" + std::to_string(milliseconds)).c_str());
    ASSERT_TRUE(accepted);
    EXPECT_FALSE(accepted->date_created.is_null());
    EXPECT_EQ(accepted->date_created.InMillisecondsSinceUnixEpoch(), milliseconds);
  }
  auto absent = ParseSyncMutation(Input().c_str());
  auto unknown = ParseSyncMutation(Input(",\"desiredCreated\":null").c_str());
  ASSERT_TRUE(absent);
  ASSERT_TRUE(unknown);
  EXPECT_TRUE(absent->date_created.is_null());
  EXPECT_TRUE(unknown->date_created.is_null());
}

TEST_F(PasswordSyncAdapterTest, ParserRejectsWrongTypesAndBounds) {
  for (const auto& metadata : {",\"desiredCreated\":true",
                               ",\"desiredCreated\":\"0\"",
                               ",\"desiredCreated\":8640000000000001",
                               ",\"offTheRecord\":true"}) {
    EXPECT_FALSE(ParseSyncMutation(Input(metadata).c_str()));
  }
  EXPECT_FALSE(ParseSyncMutation(std::string(65537, 'x').c_str()));
  EXPECT_FALSE(ParseSyncMutation("[]"));
  EXPECT_FALSE(ParseSyncMutation("{\"origin\":false}"));
  EXPECT_FALSE(ParseSyncMutation(
      "{\"origin\":\"https://adapter.example/path\",\"username\":\"fixture\","
      "\"expectedPresent\":false,\"desiredPresent\":true,\"desiredPassword\":\"fixture\"}"));
  EXPECT_FALSE(ParseSyncMutation(
      "{\"origin\":\"https://adapter.example\",\"username\":\"fixture\","
      "\"expectedPresent\":false,\"desiredPresent\":true,\"desiredPasswordHex\":\"ff\"}"));
}

TEST_F(PasswordSyncAdapterTest, ParserMapsAbsenceReplacementAndDeletion) {
  auto insertion = ParseSyncMutation(Input().c_str());
  ASSERT_TRUE(insertion);
  EXPECT_FALSE(insertion->expected_password);
  ASSERT_TRUE(insertion->replacement_password);
  EXPECT_EQ(*insertion->replacement_password, u"fixture");
  EXPECT_EQ(insertion->origin.spec(), "https://adapter.example/");
  auto deletion = ParseSyncMutation(
      "{\"origin\":\"https://adapter.example\",\"username\":\"fixture\","
      "\"expectedPresent\":true,\"desiredPresent\":false,\"expectedPasswordHex\":\"66697874757265\"}");
  ASSERT_TRUE(deletion);
  EXPECT_TRUE(deletion->expected_password);
  EXPECT_FALSE(deletion->replacement_password);
}

TEST_F(PasswordSyncAdapterTest, ParserPreservesRepresentableFractionalDates) {
  for (double milliseconds : {
       1234567890123.5, -1234567890123.5, 0.5, -0.5, 0.001, -0.001,
       -8640000000000000.0, 8640000000000000.0,
       std::nextafter(8640000000000000.0, 0.0),
       std::nextafter(-8640000000000000.0, 0.0),
       std::nextafter(-11644473600000.0, std::numeric_limits<double>::infinity()),
       std::nextafter(-11644473600000.0, -std::numeric_limits<double>::infinity())}) {
    auto parsed = ParseSyncMutation(
        Input(",\"desiredCreated\":" + base::NumberToString(milliseconds)).c_str());
    const auto converted = base::Time::FromMillisecondsSinceUnixEpoch(milliseconds);
    if (converted.is_null()) {
      EXPECT_FALSE(parsed);
    } else {
      ASSERT_TRUE(parsed);
      EXPECT_EQ(parsed->date_created, converted);
      EXPECT_FALSE(parsed->date_created.is_null());
    }
  }
  for (double milliseconds : {0.5, -0.5, 1234567890123.5}) {
    auto parsed = ParseSyncMutation(
        Input(",\"desiredCreated\":" + base::NumberToString(milliseconds)).c_str());
    ASSERT_TRUE(parsed);
    EXPECT_DOUBLE_EQ((parsed->date_created - base::Time::UnixEpoch()).InMillisecondsF(),
                     milliseconds);
  }
}

TEST_F(PasswordSyncAdapterTest, OutgoingCreationPreservesSelectedRepresentableDate) {
  for (double milliseconds : {1234567890123.5, -1234567890123.5, 0.5, -0.5,
       -1.5, 0.0, -8640000000000000.0, 8640000000000000.0,
       -11644473600001.0, -11644473599999.0}) {
    const auto time = base::Time::FromMillisecondsSinceUnixEpoch(milliseconds);
    ASSERT_FALSE(time.is_null());
    auto metadata = SerializeSyncCreationTime(std::optional(time));
    ASSERT_TRUE(metadata);
    EXPECT_TRUE(metadata->has_created);
    EXPECT_DOUBLE_EQ(metadata->created_ms, milliseconds);
  }
  for (const auto& time : {std::optional<base::Time>{}, std::optional(base::Time())}) {
    auto metadata = SerializeSyncCreationTime(time);
    ASSERT_TRUE(metadata);
    EXPECT_FALSE(metadata->has_created);
    EXPECT_DOUBLE_EQ(metadata->created_ms, 0);
  }
}

TEST_F(PasswordSyncAdapterTest, OutgoingCreationRejectsKnownUnrepresentableDate) {
  for (double milliseconds : {-8640000000000001.0, 8640000000000001.0}) {
    const auto time = base::Time::FromMillisecondsSinceUnixEpoch(milliseconds);
    ASSERT_FALSE(time.is_null());
    EXPECT_FALSE(SerializeSyncCreationTime(std::optional(time)));
  }
  for (const auto time : {base::Time::Min(), base::Time::Max()}) {
    ASSERT_FALSE(time.is_null());
    EXPECT_FALSE(SerializeSyncCreationTime(std::optional(time)));
  }
  for (int microseconds : {-1, 1}) {
    const auto time = base::Time::FromDeltaSinceWindowsEpoch(base::Microseconds(microseconds));
    ASSERT_FALSE(time.is_null());
    EXPECT_DOUBLE_EQ(time.InMillisecondsFSinceUnixEpochIgnoringNull(), -11644473600000.0);
    EXPECT_FALSE(SerializeSyncCreationTime(std::optional(time)));
  }
  for (int milliseconds : {-1, 1}) {
    const auto time = base::Time::FromDeltaSinceWindowsEpoch(base::Milliseconds(milliseconds));
    auto metadata = SerializeSyncCreationTime(std::optional(time));
    ASSERT_TRUE(metadata);
    EXPECT_TRUE(metadata->has_created);
    EXPECT_DOUBLE_EQ(metadata->created_ms, -11644473600000.0 + milliseconds);
  }
}

TEST_F(PasswordSyncAdapterTest, FractionalSourceUpdateKeepsDatabaseCreationDate) {
  base::ScopedTempDir directory;
  ASSERT_TRUE(directory.CreateUniqueTempDir());
  password_manager::LoginDatabase database(
      directory.GetPath().AppendASCII("AdapterCredentials"),
      password_manager::kProfileStore);
  ASSERT_TRUE(database.Init(base::NullCallback(),
                           os_crypt_async::GetTestEncryptorForTesting()));
  const auto make_lease = [] {
    return base::MakeRefCounted<Lease>(base::TimeTicks::Now() + base::Seconds(10));
  };
  auto insertion = ParseSyncMutation(Input(",\"desiredCreated\":1234567890123.5").c_str());
  ASSERT_TRUE(insertion);
  const auto created = insertion->date_created;
  auto inserted = database.CompareAndSetLogin(std::move(*insertion), make_lease());
  ASSERT_EQ(inserted.status, Status::kCommitted);
  auto replacement = ParseSyncMutation(
      "{\"origin\":\"https://adapter.example\",\"username\":\"fixture\","
      "\"expectedPresent\":true,\"desiredPresent\":true,"
      "\"expectedPassword\":\"fixture\",\"desiredPassword\":\"replacement\","
      "\"desiredCreated\":-0.5}");
  ASSERT_TRUE(replacement);
  EXPECT_NE(replacement->date_created, created);
  auto updated = database.CompareAndSetLogin(std::move(*replacement), make_lease());
  ASSERT_EQ(updated.status, Status::kCommitted);
  std::vector<password_manager::StoredCredential> rows;
  ASSERT_EQ(database.GetAllLogins(&rows), password_manager::FormRetrievalResult::kSuccess);
  ASSERT_EQ(rows.size(), 1u);
  EXPECT_EQ(rows[0].date_created, created);
  EXPECT_EQ(rows[0].password_value, u"replacement");
}

TEST_F(PasswordSyncAdapterTest, TimeoutRevokesWithoutTerminalUntilBackendReply) {
  Gate gate;
  auto lease = base::MakeRefCounted<Lease>(
      base::TimeTicks::Now() + base::Seconds(10), Begin, End, &gate);
  auto request = std::make_shared<Request>(lease, Done, &gate);
  SyncMutationRegistry<Request> registry;
  ASSERT_TRUE(registry.Track(request));
  GatedStore store;
  auto mutation = ParseSyncMutation(Input().c_str());
  ASSERT_TRUE(mutation);
  DispatchSyncMutation(store, std::move(*mutation), request,
                       [](auto completion) {
                         return BindCompletion(std::move(completion));
                       });
  request->Cancel();
  EXPECT_EQ(gate.dones, 0);
  EXPECT_EQ(store.Commit(), Status::kUnauthorized);
  store.Reply(Status::kUnauthorized);
  EXPECT_EQ(gate.dones, 1);
  EXPECT_EQ(gate.begins, 0);
  EXPECT_EQ(gate.ends, 0);
  EXPECT_EQ(gate.status, AC_PASSWORDS_SYNC_UNAUTHORIZED);
}

TEST_F(PasswordSyncAdapterTest, CommittedReplySurvivesProfileRevocation) {
  Gate gate;
  auto context = std::make_shared<SyncMutationCommitContext>(Begin, End, &gate);
  auto lease = base::MakeRefCounted<Lease>(
      base::TimeTicks::Now() + base::Seconds(10), SyncMutationCommitContext::Begin,
      SyncMutationCommitContext::End, context.get());
  auto request = std::make_shared<Request>(lease, Done, &gate, std::move(context));
  SyncMutationRegistry<Request> registry;
  ASSERT_TRUE(registry.Track(request));
  GatedStore store;
  auto mutation = ParseSyncMutation(Input().c_str());
  ASSERT_TRUE(mutation);
  DispatchSyncMutation(store, std::move(*mutation), std::move(request),
                       [](auto completion) {
                         return BindCompletion(std::move(completion));
                       });
  auto status = store.Commit();
  registry.Close();
  EXPECT_EQ(gate.dones, 1);
  store.Reply(status);
  EXPECT_EQ(gate.dones, 1);
  EXPECT_EQ(gate.begins, 1);
  EXPECT_EQ(gate.ends, 1);
  EXPECT_EQ(gate.status, AC_PASSWORDS_SYNC_COMMITTED);
  EXPECT_FALSE(SyncStoreTopologySupported(true, true));
}

TEST_F(PasswordSyncAdapterTest, QueuedWorkCannotRenewOriginalLeaseDeadline) {
  Gate gate;
  auto lease = base::MakeRefCounted<Lease>(
      base::TimeTicks::Now() + base::Seconds(1), Begin, End, &gate);
  auto request = std::make_shared<Request>(lease, Done, &gate);
  GatedStore store;
  auto mutation = ParseSyncMutation(Input().c_str());
  ASSERT_TRUE(mutation);
  DispatchSyncMutation(store, std::move(*mutation), std::move(request),
                       [](auto completion) {
                         return BindCompletion(std::move(completion));
                       });
  environment_.FastForwardBy(base::Seconds(2));
  auto status = store.Commit();
  EXPECT_EQ(status, Status::kUnauthorized);
  EXPECT_EQ(gate.begins, 0);
  EXPECT_EQ(gate.dones, 0);
  store.Reply(status);
  EXPECT_EQ(gate.dones, 1);
  EXPECT_EQ(gate.status, AC_PASSWORDS_SYNC_UNAUTHORIZED);
}

TEST_F(PasswordSyncAdapterTest, DiscardedReplyRetainsCommittedStatusAfterDrain) {
  Gate gate;
  auto context = std::make_shared<SyncMutationCommitContext>(Begin, End, &gate);
  auto lease = base::MakeRefCounted<Lease>(
      base::TimeTicks::Now() + base::Seconds(10), SyncMutationCommitContext::Begin,
      SyncMutationCommitContext::End, context.get());
  auto request = std::make_shared<Request>(lease, Done, &gate, std::move(context));
  GatedStore store;
  auto mutation = ParseSyncMutation(Input().c_str());
  ASSERT_TRUE(mutation);
  DispatchSyncMutation(store, std::move(*mutation), std::move(request),
                       [](auto completion) {
                         return BindCompletion(std::move(completion));
                       });
  ASSERT_EQ(store.Commit(), Status::kCommitted);
  store.completion_.Reset();
  EXPECT_EQ(gate.begins, 1);
  EXPECT_EQ(gate.ends, 1);
  EXPECT_EQ(gate.dones, 1);
  EXPECT_EQ(gate.status, AC_PASSWORDS_SYNC_COMMITTED);
  EXPECT_EQ(store.Commit(), Status::kUnauthorized);
}

TEST(PasswordSyncAdapterShutdownTest, ExecutorShutdownCompletesRetainedReply) {
  using Shutdown = SyncMutationLoopShutdown<base::CurrentThread, Request>;
  for (bool committed : {false, true}) {
    Gate gate;
    GatedStore store;
    std::shared_ptr<Shutdown> shutdown;
    std::thread thread([&] {
      {
        base::SingleThreadTaskExecutor executor;
        shutdown = Shutdown::Create();
        ASSERT_TRUE(shutdown);
        auto context = std::make_shared<SyncMutationCommitContext>(Begin, End, &gate);
        auto lease = base::MakeRefCounted<Lease>(
            base::TimeTicks::Now() + base::Seconds(10),
            SyncMutationCommitContext::Begin, SyncMutationCommitContext::End,
            context.get());
        auto request = std::make_shared<Request>(lease, Done, &gate, std::move(context));
        ASSERT_TRUE(shutdown->Track(request));
        auto mutation = ParseSyncMutation(Input().c_str());
        ASSERT_TRUE(mutation);
        DispatchSyncMutation(store, std::move(*mutation), std::move(request),
                             [](auto completion) {
                               return BindCompletion(std::move(completion));
                             });
        if (committed) {
          ASSERT_EQ(store.Commit(), Status::kCommitted);
        }
      }
      EXPECT_FALSE(base::CurrentThread::IsSet());
    });
    thread.join();
    EXPECT_EQ(gate.dones, 1);
    EXPECT_EQ(gate.status, committed ? AC_PASSWORDS_SYNC_COMMITTED
                                   : AC_PASSWORDS_SYNC_UNAUTHORIZED);
    EXPECT_EQ(store.Commit(), Status::kUnauthorized);
    store.Reply(Status::kError);
    EXPECT_EQ(gate.dones, 1);
    shutdown.reset();
  }
}

}
}
