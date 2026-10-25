#include "chrome/browser/ardia/public/ac_engine.h"

#include <cassert>
#include <cstdio>
#include <optional>
#include <type_traits>
#include <utility>

static double gNow = 0;

namespace base {
struct TimeTicks {
  double value;
  static TimeTicks Now() { return {gNow}; }
  TimeTicks operator+(double seconds) const { return {value + seconds}; }
  bool operator<(TimeTicks other) const { return value < other.value; }
};
double Seconds(double seconds) { return seconds; }
}

struct Profile {
  bool shutdown = false;
  bool ShutdownStarted() { return shutdown; }
};

struct Session {
  bool active = true;
  Profile value;
  bool alive() const { return active; }
  Profile* profile() const { return const_cast<Profile*>(&value); }
};

#define DCHECK_CURRENTLY_ON(value) static_cast<void>(0)
#include "password_sync_read_request.inc"

static_assert(std::is_same_v<decltype(&SyncRequest::Finish), void (SyncRequest::*)(bool)>);

struct LegacyConsumer {
  bool authorized = true;
  int buffered = 0;
  int accepted = 0;
  int completions = 0;
  int wire_status = -99;
};

int Authorized(void* context) { return static_cast<LegacyConsumer*>(context)->authorized; }
void Login(void* context, const ac_passwords_sync_login*) { ++static_cast<LegacyConsumer*>(context)->buffered; }
void Done(void* context, int success) {
  auto& consumer = *static_cast<LegacyConsumer*>(context);
  assert(success == 0 || success == 1);
  consumer.wire_status = success;
  consumer.accepted = success != 0 ? consumer.buffered : 0;
  ++consumer.completions;
}

int main() {
  for (int input_status : {AC_PASSWORDS_SYNC_CONFLICT, AC_PASSWORDS_SYNC_COMMITTED,
                           AC_PASSWORDS_SYNC_ERROR, AC_PASSWORDS_SYNC_UNAUTHORIZED}) {
    LegacyConsumer consumer;
    SyncRequest request(Authorized, Login, Done, &consumer);
    request.session = Session{};
    assert(request.Send({}));
    request.Finish(input_status == AC_PASSWORDS_SYNC_COMMITTED);
    assert(consumer.completions == 1);
    assert(consumer.wire_status == (input_status == AC_PASSWORDS_SYNC_COMMITTED ? 1 : 0));
    assert(consumer.accepted == (input_status == AC_PASSWORDS_SYNC_COMMITTED ? 1 : 0));
    request.Finish(true);
    assert(consumer.completions == 1);
  }
  {
    LegacyConsumer consumer;
    SyncRequest request(Authorized, Login, Done, &consumer);
    request.session = Session{};
    assert(request.Send({}));
    consumer.authorized = false;
    request.Finish(true);
    assert(consumer.wire_status == 0 && consumer.accepted == 0);
  }
  {
    LegacyConsumer consumer;
    SyncRequest request(Authorized, Login, Done, &consumer);
    request.session = Session{};
    assert(request.Send({}));
    gNow = 11;
    request.Finish(true);
    assert(consumer.wire_status == 0 && consumer.accepted == 0);
    gNow = 0;
  }
  {
    LegacyConsumer consumer;
    {
      SyncRequest request(Authorized, Login, Done, &consumer);
      request.session = Session{};
      assert(request.Send({}));
      request.session->value.shutdown = true;
      request.Finish(true);
    }
    assert(consumer.wire_status == 0 && consumer.accepted == 0 && consumer.completions == 1);
  }
  {
    LegacyConsumer consumer;
    {
      SyncRequest request(Authorized, Login, Done, &consumer);
      request.session = Session{};
      assert(request.Send({}));
    }
    assert(consumer.wire_status == 0 && consumer.accepted == 0 && consumer.completions == 1);
  }
  puts("Production read request: 8 old-consumer compatibility cases; Boolean wire statuses, partial rows denied, revoke/timeout/shutdown/destructor completion once");
}
