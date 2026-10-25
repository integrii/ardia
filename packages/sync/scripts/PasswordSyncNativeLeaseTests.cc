#include "ArdiaCorePasswordSyncLease.h"

#include <atomic>
#include <cassert>
#include <condition_variable>
#include <cstdio>
#include <future>
#include <thread>

using namespace ardiacore_password_sync;
using namespace std::chrono_literals;

static std::atomic<double> gUptime{0};
static double Uptime() { return gUptime.load(); }

class Event {
 public:
  void Set() {
    std::lock_guard<std::mutex> lock(mutex_);
    set_ = true;
    condition_.notify_all();
  }

  void Wait() {
    std::unique_lock<std::mutex> lock(mutex_);
    assert(condition_.wait_for(lock, 2s, [&] { return set_; }));
  }

 private:
  std::mutex mutex_;
  std::condition_variable condition_;
  bool set_ = false;
};

int main() {
  {
    gUptime = 99.999;
    auto grant = std::make_shared<AuthorizationLease>(200, Uptime);
    RequestLease near_operation_expiry(grant, 100.0);
    assert(near_operation_expiry.Allowed());
    gUptime = 100;
    std::thread backend([&] { assert(!near_operation_expiry.BeginCommit()); });
    backend.join();
  }
  {
    gUptime = 10;
    AuthorizationRegistry registry;
    auto authorization = registry.Authorize(0, 100, Uptime);
    assert(authorization);
    RequestLease request(authorization, 100.0);
    std::thread key_change([&] { registry.ReplaceGeneration(1); });
    key_change.join();
    assert(!request.BeginCommit() && !registry.Authorize(0, 100, Uptime));
    auto next = registry.Authorize(1, 100, Uptime);
    assert(next);
    RequestLease next_request(next, 100.0);
    assert(next_request.BeginCommit());
    next_request.EndCommit(false);
    registry.Invalidate();
    assert(!registry.Authorize(1, 100, Uptime));
  }
  {
    gUptime = 10;
    AuthorizationRegistry registry;
    auto authorization = registry.Authorize(0, 100, Uptime);
    RequestLease request(authorization, 100.0);
    Event committing;
    Event release;
    Event changing;
    std::atomic<bool> replaced{false};
    std::thread backend([&] {
      assert(request.BeginCommit());
      committing.Set();
      release.Wait();
      request.EndCommit(true);
    });
    committing.Wait();
    std::thread work_queue([&] {
      changing.Set();
      registry.ReplaceGeneration(1);
      replaced = true;
    });
    changing.Wait();
    assert(!replaced.load());
    release.Set();
    backend.join();
    work_queue.join();
    assert(replaced && request.Cancel());
    assert(!registry.Authorize(0, 100, Uptime));
  }
  {
    gUptime = 10;
    for (int round = 0; round < 200; ++round) {
      AuthorizationRegistry registry;
      std::shared_ptr<AuthorizationLease> concurrent;
      std::thread register_grant([&] { concurrent = registry.Authorize(0, 100, Uptime); });
      registry.ReplaceGeneration(1);
      register_grant.join();
      if (concurrent) {
        RequestLease stale(concurrent, 100.0);
        assert(!stale.BeginCommit());
      }
      assert(!registry.Authorize(0, 100, Uptime));
    }
  }
  {
    gUptime = 99.999;
    auto cached_grant = std::make_shared<AuthorizationLease>(100, Uptime);
    RequestLease request(cached_grant, 10s);
    assert(request.Allowed());
    gUptime = 100;
    std::thread backend([&] { assert(!request.BeginCommit()); });
    backend.join();
    assert(!request.Allowed());
  }
  {
    gUptime = 101;
    auto delayed_main_expiry = std::make_shared<AuthorizationLease>(100, Uptime);
    RequestLease request(delayed_main_expiry, 10s);
    std::thread backend([&] { assert(!request.BeginCommit()); });
    backend.join();
  }
  {
    auto authorization = std::make_shared<AuthorizationLease>(10s);
    RequestLease request(authorization, 10s);
    Event before_commit;
    Event resume;
    std::thread backend([&] {
      before_commit.Set();
      resume.Wait();
      assert(!request.BeginCommit());
    });
    before_commit.Wait();
    authorization->Revoke();
    resume.Set();
    backend.join();
    assert(!request.Allowed());
    assert(!request.Cancel());
  }
  {
    auto authorization = std::make_shared<AuthorizationLease>(10s);
    RequestLease request(authorization, 10s);
    Event committing;
    Event release;
    Event revoking;
    std::atomic<bool> revoked{false};
    std::atomic<int> writes{0};
    std::thread backend([&] {
      assert(request.BeginCommit());
      committing.Set();
      release.Wait();
      ++writes;
      request.EndCommit(true);
    });
    committing.Wait();
    std::thread main_revoke([&] {
      revoking.Set();
      authorization->Revoke();
      revoked = true;
    });
    revoking.Wait();
    assert(!revoked.load());
    release.Set();
    backend.join();
    main_revoke.join();
    assert(revoked && writes == 1 && request.Cancel());
    assert(!request.BeginCommit());
    RequestLease later(authorization, 10s);
    assert(!later.BeginCommit());
  }
  {
    auto authorization = std::make_shared<AuthorizationLease>(10s);
    RequestLease request(authorization, 10s);
    Event committing;
    Event release;
    Event cancelling;
    std::atomic<bool> cancelled{false};
    std::thread backend([&] {
      assert(request.BeginCommit());
      committing.Set();
      release.Wait();
      request.EndCommit(true);
    });
    committing.Wait();
    std::thread timeout([&] {
      cancelling.Set();
      assert(request.Cancel());
      cancelled = true;
    });
    cancelling.Wait();
    assert(!cancelled.load());
    release.Set();
    backend.join();
    timeout.join();
    assert(cancelled && request.Cancel() && !request.BeginCommit());
  }
  {
    auto authorization = std::make_shared<AuthorizationLease>(10s);
    RequestLease request(authorization, 10s);
    assert(!request.Cancel());
    std::thread backend([&] { assert(!request.BeginCommit()); });
    backend.join();
    RequestLease next(authorization, 10s);
    assert(next.BeginCommit());
    next.EndCommit(false);
    assert(!next.Cancel() && !next.BeginCommit());
  }
  {
    auto authorization = std::make_shared<AuthorizationLease>(10s);
    RequestLease request(authorization, -1s);
    assert(!request.BeginCommit() && !request.Allowed());
  }
  {
    auto authorization = std::make_shared<AuthorizationLease>(-1s);
    RequestLease request(authorization, 10s);
    assert(!request.BeginCommit() && !request.Allowed());
  }
  {
    auto authorization = std::make_shared<AuthorizationLease>(10s);
    auto request = std::make_shared<RequestLease>(authorization, 10s);
    std::weak_ptr<RequestLease> lifetime = request;
    Event queued;
    Event deliver;
    std::thread backend([held = request, &queued, &deliver] {
      queued.Set();
      deliver.Wait();
      assert(!held->BeginCommit());
    });
    queued.Wait();
    authorization->Revoke();
    request.reset();
    authorization.reset();
    assert(!lifetime.expired());
    deliver.Set();
    backend.join();
    assert(lifetime.expired());
  }
  {
    for (int round = 0; round < 200; ++round) {
      auto authorization = std::make_shared<AuthorizationLease>(10s);
      RequestLease request(authorization, 10s);
      std::atomic<int> writes{0};
      std::thread backend([&] {
        if (request.BeginCommit()) {
          ++writes;
          request.EndCommit(true);
        }
      });
      authorization->Revoke();
      int after_revoke = writes.load();
      backend.join();
      assert(writes == after_revoke && writes <= 1);
      assert(request.Cancel() == (writes == 1));
      assert(!request.BeginCommit());
    }
  }
  puts("Production lease: 14 concurrency/deadline/lifetime cases and 400 commit/revoke/registration races passed");
}
