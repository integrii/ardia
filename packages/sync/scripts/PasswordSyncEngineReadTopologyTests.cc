#include "chrome/browser/ardia/ac_passwords_sync_adapter.h"

#include <cassert>
#include <cstdio>
#include <functional>
#include <optional>
#include <utility>

namespace base {

struct TimeTicks {
  double value;
  static TimeTicks Now() { return {0}; }
  TimeTicks operator+(double seconds) const { return {value + seconds}; }
  bool operator<(TimeTicks other) const { return value < other.value; }
};

double Seconds(double value) { return value; }

template <typename Function, typename Argument>
auto BindOnce(Function function, Argument argument) {
  return [function = std::move(function), argument = std::move(argument)]() mutable {
    function(std::move(argument));
  };
}

struct SequencedTaskRunner {
  std::function<void()> timeout;
  int posts = 0;

  static SequencedTaskRunner* GetCurrentDefault() {
    static SequencedTaskRunner runner;
    return &runner;
  }

  bool PostDelayedTask(int, std::function<void()> callback, double) {
    ++posts;
    timeout = std::move(callback);
    return true;
  }
};

}

struct Profile {
  bool IsOffTheRecord() const { return false; }
  bool ShutdownStarted() const { return false; }
};

Profile gProfile;
bool gProfileStore = true;
bool gAccountStore = false;
int gPresenterOpens = 0;

struct Session {
  bool alive() const { return true; }
  Profile* profile() const { return &gProfile; }
};

struct Call {
  Call(const char*, const char*, void*, void*) {}
  explicit operator bool() const { return true; }
  Profile* profile() const { return &gProfile; }
};

enum class ServiceAccessType { EXPLICIT_ACCESS };

struct ProfilePasswordStoreFactory {
  static bool GetForProfile(Profile*, ServiceAccessType) { return gProfileStore; }
};

struct AccountPasswordStoreFactory {
  static bool GetForProfile(Profile*, ServiceAccessType) { return gAccountStore; }
};

std::optional<Session> Open(const Call&) {
  ++gPresenterOpens;
  return Session{};
}

#define DCHECK_CURRENTLY_ON(value) static_cast<void>(0)
#define FROM_HERE 0

using ardia::SyncStoreTopologySupported;

#include "password_sync_read_request.inc"
#include "password_sync_read_begin.inc"

struct Consumer {
  int rows = 0;
  int completions = 0;
  int status = 99;
};

int Authorized(void*) { return 1; }

void Login(void* context, const ac_passwords_sync_login*) {
  ++static_cast<Consumer*>(context)->rows;
}

void Done(void* context, int success) {
  auto& consumer = *static_cast<Consumer*>(context);
  assert(success == 0 || success == 1);
  ++consumer.completions;
  consumer.status = success;
}

int main() {
  for (bool profile : {false, true}) {
    for (bool account : {false, true}) {
      gProfileStore = profile;
      gAccountStore = account;
      gPresenterOpens = 0;
      auto* runner = base::SequencedTaskRunner::GetCurrentDefault();
      runner->posts = 0;
      Consumer consumer;
      auto request = BeginSync("fixture", Authorized, Login, Done, &consumer);
      if (profile && !account) {
        assert(request && gPresenterOpens == 1 && runner->posts == 1);
        assert(request->Send({}));
        request->Finish(true);
        assert(consumer.rows == 1 && consumer.status == 1);
        auto timeout = std::exchange(runner->timeout, {});
        timeout();
      } else {
        assert(!request && gPresenterOpens == 0 && runner->posts == 0);
        assert(consumer.rows == 0 && consumer.status == 0);
      }
      assert(consumer.completions == 1);
    }
  }
  puts("Production read submission: all four profile/account topologies; second store rejects before presenter access or any rows (fixture factories)");
}
