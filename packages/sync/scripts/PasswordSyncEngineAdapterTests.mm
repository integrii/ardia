#import <Foundation/Foundation.h>

#include "chrome/browser/ardia/ac_passwords_sync_adapter.h"
#include "chrome/browser/ardia/ac_passwords_sync_input.h"
#include "chrome/browser/ardia/ac_passwords_sync_policy.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <functional>
#include <limits>
#include <map>
#include <thread>

namespace {

enum class Kind { kNull, kString, kBoolean, kNumber, kOther };

struct Value {
  Kind kind = Kind::kNull;
  std::string text;
  double number = 0;
  bool boolean = false;

  bool is_none() const { return kind == Kind::kNull; }
  bool is_bool() const { return kind == Kind::kBoolean; }
  bool is_string() const { return kind == Kind::kString; }
  bool is_int() const { return false; }
  bool is_double() const { return kind == Kind::kNumber; }
  bool GetBool() const { return boolean; }
  double GetDouble() const { return number; }
  const std::string& GetString() const { return text; }
};

struct Dictionary : std::map<std::string, Value, std::less<>> {
  const Value* Find(std::string_view key) const {
    auto it = find(key);
    return it == end() ? nullptr : &it->second;
  }
  const std::string* FindString(std::string_view key) const {
    const auto* value = Find(key);
    return value && value->is_string() ? &value->text : nullptr;
  }
  std::optional<bool> FindBool(std::string_view key) const {
    const auto* value = Find(key);
    return value && value->is_bool() ? std::optional(value->boolean) : std::nullopt;
  }
};

Dictionary JSON(NSString* source) {
  NSDictionary* json = [NSJSONSerialization JSONObjectWithData:
      [source dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
  assert([json isKindOfClass:NSDictionary.class]);
  Dictionary dictionary;
  for (NSString* key in json) {
    id object = json[key];
    Value value;
    if ([object isKindOfClass:NSString.class]) {
      value.kind = Kind::kString;
      NSData* bytes = [object dataUsingEncoding:NSUTF8StringEncoding];
      value.text.assign(static_cast<const char*>(bytes.bytes), bytes.length);
    } else if (CFGetTypeID((__bridge CFTypeRef)object) == CFBooleanGetTypeID()) {
      value.kind = Kind::kBoolean;
      value.boolean = [object boolValue];
    } else if ([object isKindOfClass:NSNumber.class]) {
      value.kind = Kind::kNumber;
      value.number = [object doubleValue];
    } else if (object != NSNull.null) {
      value.kind = Kind::kOther;
    }
    dictionary.emplace(key.UTF8String, std::move(value));
  }
  return dictionary;
}

Dictionary Input() {
  return JSON(@"{\"origin\":\"https://adapter.example\",\"username\":\"fixture\",\"expectedPresent\":false,\"desiredPresent\":true,\"desiredPasswordHex\":\"66697874757265\"}");
}

void ParserBoundary() {
  auto dictionary = Input();
  auto parsed = ardia::ParseSyncMutationInput(dictionary);
  assert(parsed && !parsed->desired_created_ms && !parsed->expected_present &&
         parsed->desired_present);
  dictionary["desiredCreated"] = Value{};
  assert(!ardia::ParseSyncMutationInput(dictionary)->desired_created_ms);
  for (int64_t milliseconds : {int64_t{0}, int64_t{-1},
       ardia::kSyncCreatedNullSentinel - 1,
       ardia::kSyncCreatedNullSentinel + 1,
       -ardia::kSyncCreatedLimit, ardia::kSyncCreatedLimit}) {
    dictionary["desiredCreated"] = Value{Kind::kNumber, {},
                                         static_cast<double>(milliseconds)};
    parsed = ardia::ParseSyncMutationInput(dictionary);
    assert(parsed && parsed->desired_created_ms == milliseconds);
  }
  for (double milliseconds : {
       0.5, -0.5, 0.001, -0.001, 1234567890123.5, -1234567890123.5,
       std::nextafter(static_cast<double>(ardia::kSyncCreatedNullSentinel),
                      std::numeric_limits<double>::infinity()),
       std::nextafter(static_cast<double>(ardia::kSyncCreatedNullSentinel),
                      -std::numeric_limits<double>::infinity()),
       std::nextafter(static_cast<double>(ardia::kSyncCreatedLimit), 0.0),
       std::nextafter(-static_cast<double>(ardia::kSyncCreatedLimit), 0.0)}) {
    dictionary["desiredCreated"] = Value{Kind::kNumber, {}, milliseconds};
    parsed = ardia::ParseSyncMutationInput(dictionary);
    assert(parsed && parsed->desired_created_ms == milliseconds);
  }
  for (double milliseconds : {
       static_cast<double>(ardia::kSyncCreatedNullSentinel),
       static_cast<double>(ardia::kSyncCreatedLimit) + 1,
       -static_cast<double>(ardia::kSyncCreatedLimit) - 1,
       std::numeric_limits<double>::quiet_NaN(),
       std::numeric_limits<double>::infinity()}) {
    dictionary["desiredCreated"] = Value{Kind::kNumber, {}, milliseconds};
    assert(!ardia::ParseSyncMutationInput(dictionary));
  }
  for (NSString* invalid in @[
      @"{\"origin\":\"https://adapter.example\",\"username\":\"fixture\",\"expectedPresent\":0,\"desiredPresent\":true,\"desiredPassword\":\"fixture\"}",
      @"{\"origin\":\"https://adapter.example\",\"username\":\"fixture\",\"expectedPresent\":false,\"desiredPresent\":false}",
      @"{\"origin\":\"https://adapter.example\",\"username\":\"fixture\",\"expectedPresent\":false,\"desiredPresent\":true,\"desiredPassword\":null}",
      @"{\"origin\":\"https://adapter.example\",\"username\":\"fixture\",\"expectedPresent\":false,\"desiredPresent\":true,\"desiredPassword\":false}",
      @"{\"origin\":\"https://adapter.example\",\"username\":\"fixture\",\"expectedPresent\":false,\"desiredPresent\":true,\"desiredPassword\":\"fixture\",\"desiredPasswordHex\":\"66\"}",
      @"{\"origin\":\"https://adapter.example\",\"username\":\"fixture\",\"expectedPresent\":false,\"desiredPresent\":true,\"desiredPassword\":\"fixture\",\"expectedPassword\":null}",
      @"{\"origin\":\"https://adapter.example\",\"username\":\"fixture\",\"expectedPresent\":true,\"desiredPresent\":false,\"expectedPassword\":\"fixture\",\"desiredCreated\":0}",
      @"{\"origin\":\"https://adapter.example\",\"username\":\"fixture\",\"expectedPresent\":false,\"desiredPresent\":true,\"desiredPassword\":\"fixture\",\"desiredCreated\":false}",
      @"{\"origin\":\"https://adapter.example\",\"username\":\"fixture\",\"expectedPresent\":false,\"desiredPresent\":true,\"desiredPassword\":\"fixture\",\"offTheRecord\":true}",
      @"{\"origin\":\"https://adapter.example\",\"username\":\"fixture\",\"expectedPresent\":false,\"desiredPresent\":true,\"desiredPassword\":\"fixture\",\"extra\":null}"]) {
    assert(!ardia::ParseSyncMutationInput(JSON(invalid)));
  }
  dictionary = Input();
  dictionary["username"].text.assign(4097, 'x');
  assert(!ardia::ParseSyncMutationInput(dictionary));
  dictionary = Input();
  dictionary["desiredPasswordHex"].text.assign(ardia::kSyncMutationMaxJsonBytes + 1, '0');
  assert(!ardia::ParseSyncMutationInput(dictionary));
  dictionary = JSON(@"{\"origin\":\"https://adapter.example\",\"username\":\"fixture\",\"expectedPresent\":true,\"desiredPresent\":false,\"expectedPasswordHex\":\"66\"}");
  parsed = ardia::ParseSyncMutationInput(dictionary);
  assert(parsed && parsed->expected_present && !parsed->desired_present);
  dictionary = JSON(@"{\"origin\":\"https://adapter.example\",\"username\":\"fixture\",\"expectedPresent\":true,\"desiredPresent\":true,\"expectedPassword\":\"old\",\"desiredPassword\":\"new\"}");
  assert(ardia::ParseSyncMutationInput(dictionary));
}

enum class Status { kCommitted, kConflict, kError, kUnauthorized };

struct Observation {
  std::atomic<int> begins = 0;
  std::atomic<int> ends = 0;
  std::atomic<int> dones = 0;
  std::atomic<int> frees = 0;
  std::atomic<int> status = 99;
  std::atomic<bool> denied = false;
};

struct Context {
  std::shared_ptr<Observation> observation;
  std::function<void()> on_done;
  ~Context() { ++observation->frees; }
};

int Begin(void* pointer) {
  auto& observation = *static_cast<Context*>(pointer)->observation;
  ++observation.begins;
  return !observation.denied;
}

void End(void* pointer, int status) {
  auto& observation = *static_cast<Context*>(pointer)->observation;
  assert(status == 0 || status == 1);
  ++observation.ends;
}

void Done(void* pointer, int status) {
  std::unique_ptr<Context> context(static_cast<Context*>(pointer));
  context->observation->status = status;
  ++context->observation->dones;
  if (context->on_done) {
    context->on_done();
  }
}

class FixtureLease {
 public:
  explicit FixtureLease(void* context,
                        std::chrono::steady_clock::time_point deadline,
                        ac_passwords_sync_begin_commit_t begin = Begin,
                        ac_passwords_sync_end_commit_t end = End)
      : context_(context), deadline_(deadline), begin_(begin), end_(end) {}

  void Revoke() {
    std::lock_guard lock(mutex_);
    revoked_ = true;
  }

  Status Commit(const std::function<bool()>& commit) {
    std::lock_guard lock(mutex_);
    if (revoked_ || std::chrono::steady_clock::now() >= deadline_) {
      return Status::kUnauthorized;
    }
    if (!begin_(context_)) {
      return Status::kUnauthorized;
    }
    const bool result = commit();
    end_(context_, result ? 1 : 0);
    return result ? Status::kCommitted : Status::kError;
  }

 private:
  std::mutex mutex_;
  bool revoked_ = false;
  void* context_;
  const std::chrono::steady_clock::time_point deadline_;
  const ac_passwords_sync_begin_commit_t begin_;
  const ac_passwords_sync_end_commit_t end_;
};

using Lease = std::shared_ptr<FixtureLease>;
using Request = ardia::SyncMutationRequest<Lease>;

class FixtureCurrentThread {
 public:
  class DestructionObserver {
   public:
    virtual void WillDestroyCurrentMessageLoop() = 0;
    virtual ~DestructionObserver() = default;
  };

  static bool IsSet() { return set_; }

  static FixtureCurrentThread Get() {
    assert(set_);
    return {};
  }

  void AddDestructionObserver(DestructionObserver* observer) {
    assert(set_ && !rejecting_posts_);
    observers_.push_back(observer);
  }

  void RemoveDestructionObserver(DestructionObserver* observer) {
    assert(set_);
    std::erase(observers_, observer);
  }

  static void Reset() {
    assert(observers_.empty());
    set_ = true;
    rejecting_posts_ = false;
  }

  static void Destroy() {
    rejecting_posts_ = true;
    const auto observers = observers_;
    for (auto* observer : observers) {
      if (std::find(observers_.begin(), observers_.end(), observer) !=
          observers_.end()) {
        observer->WillDestroyCurrentMessageLoop();
      }
    }
    set_ = false;
    assert(observers_.empty());
  }

  inline static bool rejecting_posts_ = false;

 private:
  inline static bool set_ = true;
  inline static std::vector<DestructionObserver*> observers_;
};

using LoopShutdown = ardia::SyncMutationLoopShutdown<FixtureCurrentThread, Request>;

struct Mutation {
  bool expected_present = false;
  bool desired_present = true;
};

struct FixtureStore {
  std::function<void(Status)> reply;
  Lease lease;
  Mutation input;
  bool reject_post = false;
  int submissions = 0;

  void CompareAndSetLogin(Mutation mutation, Lease authorization,
                           std::function<void(Status)> completion) {
    ++submissions;
    input = mutation;
    lease = std::move(authorization);
    if (reject_post) {
      completion(Status::kError);
    } else {
      reply = std::move(completion);
    }
  }

  Status Execute(bool commit = true) {
    return lease->Commit([commit] { return commit; });
  }

  void Reply(Status status) {
    auto completion = std::exchange(reply, {});
    completion(status);
  }
};

struct Fixture {
  std::shared_ptr<Observation> observation = std::make_shared<Observation>();
  Context* context = new Context{observation, {}};
  std::shared_ptr<ardia::SyncMutationCommitContext> commit_context =
      std::make_shared<ardia::SyncMutationCommitContext>(Begin, End, context);
  Lease lease = std::make_shared<FixtureLease>(
      commit_context.get(),
      std::chrono::steady_clock::now() + std::chrono::seconds(10),
      ardia::SyncMutationCommitContext::Begin, ardia::SyncMutationCommitContext::End);
  std::shared_ptr<Request> request = std::make_shared<Request>(
      lease, Done, context, commit_context);
  ardia::SyncMutationRegistry<Request> registry;
  FixtureStore store;

  void Queue(Mutation mutation = {}) {
    assert(registry.Track(request));
    commit_context.reset();
    ardia::DispatchSyncMutation(store, mutation, std::move(request),
                                [](auto callback) { return callback; });
  }
};

void Handoff() {
  assert(ardia::SyncStoreTopologySupported(true, false));
  assert(!ardia::SyncStoreTopologySupported(false, false));
  assert(!ardia::SyncStoreTopologySupported(true, true));
  assert(!ardia::SyncStoreTopologySupported(false, true));
  for (auto [status, expected] : {
       std::pair{Status::kCommitted, 1}, std::pair{Status::kConflict, 0},
       std::pair{Status::kError, -1}, std::pair{Status::kUnauthorized, -2}}) {
    Fixture fixture;
    fixture.Queue();
    fixture.store.Reply(status);
    assert(fixture.observation->status == expected);
    assert(fixture.observation->dones == 1);
    assert(fixture.store.Execute() == Status::kUnauthorized);
    assert(fixture.observation->begins == 0);
  }
  assert(ardia::SyncMutationWireStatus(static_cast<Status>(99)) == -1);
  for (Mutation mutation : {Mutation{false, true}, Mutation{true, true},
                             Mutation{true, false}}) {
    Fixture fixture;
    fixture.Queue(mutation);
    assert(fixture.store.input.expected_present == mutation.expected_present);
    assert(fixture.store.input.desired_present == mutation.desired_present);
    fixture.store.Reply(fixture.store.Execute());
    assert(fixture.observation->status == AC_PASSWORDS_SYNC_COMMITTED);
    assert(fixture.observation->begins == 1 && fixture.observation->ends == 1);
  }
  {
    Fixture fixture;
    fixture.Queue();
    fixture.registry.Close();
    assert(fixture.observation->dones == 1 && fixture.observation->frees == 1);
    fixture.store.Reply(fixture.store.Execute());
    assert(fixture.observation->status == AC_PASSWORDS_SYNC_UNAUTHORIZED);
    assert(fixture.observation->begins == 0);
  }
  {
    Fixture fixture;
    auto timeout = std::weak_ptr<Request>(fixture.request);
    fixture.Queue();
    timeout.lock()->Cancel();
    assert(fixture.observation->dones == 0);
    fixture.store.Reply(fixture.store.Execute());
    assert(fixture.observation->dones == 1 && timeout.expired());
    assert(fixture.observation->status == AC_PASSWORDS_SYNC_UNAUTHORIZED);
  }
  {
    Fixture fixture;
    fixture.Queue();
    auto result = fixture.store.Execute();
    fixture.registry.Close();
    assert(fixture.observation->dones == 1 && fixture.observation->frees == 1);
    fixture.store.Reply(result);
    assert(fixture.observation->status == AC_PASSWORDS_SYNC_COMMITTED);
  }
  {
    Fixture fixture;
    fixture.Queue();
    fixture.store.reply = {};
    assert(fixture.observation->dones == 1);
    assert(fixture.observation->status == AC_PASSWORDS_SYNC_ERROR);
    assert(fixture.store.Execute() == Status::kUnauthorized);
  }
  {
    Fixture fixture;
    fixture.Queue();
    assert(fixture.store.Execute() == Status::kCommitted);
    fixture.registry.Close();
    fixture.store.reply = {};
    assert(fixture.observation->dones == 1);
    assert(fixture.observation->status == AC_PASSWORDS_SYNC_COMMITTED);
    assert(fixture.store.Execute() == Status::kUnauthorized);
  }
  {
    Fixture fixture;
    fixture.store.reject_post = true;
    fixture.Queue();
    assert(fixture.observation->dones == 1);
    assert(fixture.observation->status == AC_PASSWORDS_SYNC_ERROR);
  }
  {
    Fixture fixture;
    fixture.observation->denied = true;
    fixture.Queue();
    fixture.store.Reply(fixture.store.Execute());
    assert(fixture.observation->status == AC_PASSWORDS_SYNC_UNAUTHORIZED);
    assert(fixture.observation->begins == 1 && fixture.observation->ends == 0);
  }
  {
    Fixture fixture;
    fixture.Queue();
    fixture.store.Reply(fixture.store.Execute(false));
    assert(fixture.observation->status == AC_PASSWORDS_SYNC_ERROR);
    assert(fixture.observation->begins == 1 && fixture.observation->ends == 1);
  }
  {
    Fixture fixture;
    fixture.context->on_done = [&] { fixture.registry.Close(); };
    fixture.Queue();
    fixture.store.Reply(fixture.store.Execute());
    assert(fixture.observation->dones == 1);
    assert(fixture.observation->status == AC_PASSWORDS_SYNC_COMMITTED);
  }
  {
    Fixture fixture;
    fixture.registry.Close();
    assert(!fixture.registry.Track(fixture.request));
    assert(fixture.observation->dones == 0);
    fixture.request->Complete(AC_PASSWORDS_SYNC_UNAUTHORIZED);
    assert(fixture.observation->dones == 1);
  }
  {
    Fixture fixture;
    fixture.lease = std::make_shared<FixtureLease>(
        fixture.context, std::chrono::steady_clock::now());
    fixture.request.reset();
    assert(fixture.observation->dones == 1);
    assert(fixture.lease->Commit([] { return true; }) == Status::kUnauthorized);
  }
}

void ConcurrentRevocation() {
  Fixture fixture;
  fixture.Queue();
  std::mutex mutex;
  std::condition_variable condition;
  bool entered = false;
  bool released = false;
  std::atomic<bool> close_started = false;
  std::atomic<bool> close_finished = false;
  Status result = Status::kError;
  std::thread backend([&] {
    result = fixture.lease->Commit([&] {
      std::unique_lock lock(mutex);
      entered = true;
      condition.notify_all();
      assert(condition.wait_for(lock, std::chrono::seconds(5), [&] { return released; }));
      assert(!close_finished);
      return true;
    });
  });
  {
    std::unique_lock lock(mutex);
    assert(condition.wait_for(lock, std::chrono::seconds(5), [&] { return entered; }));
  }
  std::thread closer([&] {
    {
      std::lock_guard lock(mutex);
      close_started = true;
      condition.notify_all();
    }
    fixture.registry.Close();
    close_finished = true;
  });
  {
    std::unique_lock lock(mutex);
    assert(condition.wait_for(lock, std::chrono::seconds(5), [&] { return close_started.load(); }));
    assert(!close_finished);
    released = true;
    condition.notify_all();
  }
  backend.join();
  closer.join();
  assert(close_finished && fixture.observation->dones == 1 &&
         fixture.observation->frees == 1);
  fixture.store.Reply(result);
  assert(fixture.observation->status == AC_PASSWORDS_SYNC_COMMITTED);
  assert(fixture.observation->begins == 1 && fixture.observation->ends == 1);
  assert(fixture.store.Execute() == Status::kUnauthorized);
  for (int i = 0; i < 300; ++i) {
    Fixture racing;
    racing.Queue();
    Status status = Status::kError;
    std::thread commit([&] { status = racing.store.Execute(); });
    racing.registry.Close();
    commit.join();
    racing.store.Reply(status);
    assert(racing.observation->dones == 1);
    assert(racing.observation->begins == racing.observation->ends);
    assert(racing.observation->status == AC_PASSWORDS_SYNC_COMMITTED ||
           racing.observation->status == AC_PASSWORDS_SYNC_UNAUTHORIZED);
  }
}

void LostReplyShutdown() {
  for (bool committed : {false, true}) {
    FixtureCurrentThread::Reset();
    Fixture fixture;
    auto shutdown = LoopShutdown::Create();
    assert(shutdown && shutdown->Track(fixture.request));
    fixture.context->on_done = [&] {
      assert(FixtureCurrentThread::rejecting_posts_);
      shutdown.reset();
    };
    fixture.Queue();
    auto retained_reply = std::exchange(fixture.store.reply, {});
    if (committed) {
      assert(fixture.store.Execute() == Status::kCommitted);
    }
    FixtureCurrentThread::Destroy();
    assert(!shutdown);
    assert(fixture.observation->dones == 1 && fixture.observation->frees == 1);
    const int expected = committed ? AC_PASSWORDS_SYNC_COMMITTED
                                   : AC_PASSWORDS_SYNC_UNAUTHORIZED;
    assert(fixture.observation->status == expected);
    const int begins = fixture.observation->begins;
    assert(fixture.store.Execute() == Status::kUnauthorized);
    assert(fixture.observation->begins == begins);
    retained_reply(Status::kError);
    assert(fixture.observation->dones == 1 && fixture.observation->frees == 1);
    assert(fixture.observation->status == expected);
    retained_reply = {};
  }
  {
    Fixture fixture;
    fixture.Queue();
    auto retained_reply = std::exchange(fixture.store.reply, {});
    fixture.registry.Close();
    assert(fixture.observation->dones == 1 && fixture.observation->frees == 1);
    assert(fixture.store.Execute() == Status::kUnauthorized);
    retained_reply(Status::kError);
    assert(fixture.observation->dones == 1);
  }
  {
    Fixture first;
    Fixture second;
    ardia::SyncMutationRegistry<Request> registry;
    assert(registry.Track(first.request) && registry.Track(second.request));
    first.context->on_done = [&] {
      assert(second.store.Execute() == Status::kUnauthorized);
      assert(second.observation->begins == 0);
    };
    first.Queue();
    second.Queue();
    registry.Close();
    assert(first.observation->dones == 1 && second.observation->dones == 1);
  }
  FixtureCurrentThread::Reset();
}

}

#ifdef ARDIA_TEST_OUTGOING_READ
namespace base {

std::string UTF16ToUTF8(const std::u16string& text) {
  return std::string(text.begin(), text.end());
}

auto BindOnce(auto callback) { return callback; }

}

using Entries = std::vector<int>;

namespace ardia {

struct OutgoingFixtureTime {
  double milliseconds = 0;
  bool null = false;
  bool is_null() const { return null; }
  int64_t InMillisecondsSinceUnixEpoch() const {
    return static_cast<int64_t>(milliseconds);
  }
  double InMillisecondsFSinceUnixEpochIgnoringNull() const {
    return milliseconds;
  }
};

struct OutgoingCredential {
  std::u16string username = u"fixture";
  std::u16string password = u"secret";
  std::optional<OutgoingFixtureTime> creation_time;
  std::set<std::string> origins{"https://adapter.example"};
  bool syncable = true;
};

std::vector<OutgoingCredential> outgoing_credentials;

struct SyncCredentials {
  explicit SyncCredentials(int*) : entries(outgoing_credentials) {}
  std::vector<OutgoingCredential> entries;
};

bool Syncable(const OutgoingCredential& credential) { return credential.syncable; }
auto SyncOrigins(const OutgoingCredential& credential) { return credential.origins; }

class Secret {
 public:
  explicit Secret(std::string text) : text_(std::move(text)) {}
  const std::string& value() const { return text_; }
 private:
  std::string text_;
};

struct OutgoingSession {
  std::shared_ptr<int> delegate = std::make_shared<int>(0);
};

struct SyncRequest {
  std::optional<OutgoingSession> session{std::in_place};
  ac_passwords_sync_login_t login;
  ac_passwords_sync_done_t done;
  void* context;
  bool Allowed() const { return true; }
  void Finish(bool status) { done(context, status ? 1 : 0); }
  bool Send(const ac_passwords_sync_login& row) {
    login(context, &row);
    return true;
  }
};

auto BeginSync(const char*, ac_passwords_sync_authorized_t,
               ac_passwords_sync_login_t login,
               ac_passwords_sync_done_t done, void* context) {
  auto request = std::make_shared<SyncRequest>();
  request->login = login;
  request->done = done;
  request->context = context;
  return request;
}

void WithSyncList(std::shared_ptr<SyncRequest> request, auto callback) {
  callback(std::move(request), Entries{});
}

}

#include "password_sync_read_body.inc"

namespace {

struct OutgoingRows {
  std::vector<std::pair<bool, double>> dates;
  int dones = 0;
  int status = 99;
};

OutgoingRows ReadOutgoing(std::vector<ardia::OutgoingCredential> credentials) {
  ardia::outgoing_credentials = std::move(credentials);
  OutgoingRows rows;
  ac_passwords_sync_read(nullptr, nullptr,
      [](void* context, const ac_passwords_sync_login* row) {
        auto& result = *static_cast<OutgoingRows*>(context);
        result.dates.emplace_back(row->has_created != 0, row->created_ms);
      }, [](void* context, int status) {
        auto& result = *static_cast<OutgoingRows*>(context);
        ++result.dones;
        result.status = status;
      }, &rows);
  assert(rows.dones == 1);
  return rows;
}

ardia::OutgoingCredential OutgoingDate(double milliseconds, bool null = false) {
  ardia::OutgoingCredential credential;
  credential.creation_time = ardia::OutgoingFixtureTime{milliseconds, null};
  return credential;
}

void OutgoingPrecision() {
  const std::vector<double> fractions{1234567890123.5, -1234567890123.5, -1.5, 0.5, -0.5};
  bool exact = true;
  for (double milliseconds : fractions) {
    auto rows = ReadOutgoing({OutgoingDate(milliseconds)});
    assert(rows.status == 1 && rows.dates.size() == 1 && rows.dates[0].first);
    printf("Actual extracted read: %.17g -> %.17g\n", milliseconds, rows.dates[0].second);
    exact &= rows.dates[0].second == milliseconds;
  }
  fflush(stdout);
  assert(exact);
  for (double milliseconds : {0.0, -8640000000000000.0, 8640000000000000.0,
       -11644473600001.0, -11644473599999.0}) {
    auto rows = ReadOutgoing({OutgoingDate(milliseconds)});
    assert(rows.status == 1 && rows.dates.size() == 1 && rows.dates[0].first);
    assert(rows.dates[0].second == milliseconds);
  }
  for (auto credential : {ardia::OutgoingCredential{}, OutgoingDate(0, true),
       OutgoingDate(std::numeric_limits<double>::quiet_NaN(), true)}) {
    auto rows = ReadOutgoing({credential});
    assert(rows.status == 1 && rows.dates.size() == 1);
    assert(!rows.dates[0].first && rows.dates[0].second == 0);
  }
  for (double milliseconds : {-11644473600000.0,
       std::nextafter(8640000000000000.0, std::numeric_limits<double>::infinity()),
       std::nextafter(-8640000000000000.0, -std::numeric_limits<double>::infinity()),
       std::numeric_limits<double>::quiet_NaN(),
       std::numeric_limits<double>::infinity(), -std::numeric_limits<double>::infinity()}) {
    auto invalid = OutgoingDate(milliseconds);
    invalid.username = u"invalid";
    auto rows = ReadOutgoing({OutgoingDate(0.5), invalid});
    assert(rows.status == 0 && rows.dates.empty());
    rows = ReadOutgoing({invalid, OutgoingDate(0.5)});
    assert(rows.status == 0 && rows.dates.empty());
    invalid.syncable = false;
    rows = ReadOutgoing({OutgoingDate(0.5), invalid});
    assert(rows.status == 1 && rows.dates.size() == 1);
  }
  for (int64_t internal_microseconds : {-1, 1}) {
    const double milliseconds =
        static_cast<double>(internal_microseconds - 11644473600000000LL) / 1000.0;
    assert(milliseconds == -11644473600000.0);
    auto known = OutgoingDate(milliseconds);
    const auto metadata = ardia::SerializeSyncCreationTime(known.creation_time);
    assert(!metadata);
    auto rows = ReadOutgoing({known});
    assert(rows.status == 0 && rows.dates.empty());
  }
  puts("Production outgoing read: fractions, unknown/null/Unix zero, bounds and whole-snapshot refusal passed (extracted body, fixture time, not Chromium)");
}

}
#endif

int main() {
  @autoreleasepool {
#ifdef ARDIA_TEST_OUTGOING_READ
    OutgoingPrecision();
#endif
    ParserBoundary();
    Handoff();
    ConcurrentRevocation();
    LostReplyShutdown();
    puts("Production adapter helpers: fractional creation boundary, four-status handoff, whole-profile account refusal, retained-reply profile/loop shutdown, queue/cancel/drain and 300 revoke races passed (fixture backend, not Chromium integration)");
  }
}
