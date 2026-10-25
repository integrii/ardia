#import "ArdiaCorePasswordSyncPrivate.h"

#include <cassert>
#include <thread>

using namespace ardiacore_password_sync;

static PasswordSyncHolder Request() {
  auto request = std::make_shared<PasswordSyncCall>();
  request->lease = std::make_shared<RequestLease>(std::make_shared<AuthorizationLease>(std::chrono::seconds(10)), std::chrono::seconds(10));
  return request;
}

int main() {
  @autoreleasepool {
    auto request = Request();
    __block int completions = 0;
    __block BOOL allowed = YES;
    request->authorized = ^BOOL { return allowed; };
    request->completion = ^(ArdiaCorePasswordSyncStatus status, NSArray* rows) {
      assert(status == ArdiaCorePasswordSyncStatusError && !rows);
      ++completions;
    };
    const unsigned char secret[] = {1, 2, 3, 0};
    NSMutableData* arguments = [NSMutableData dataWithBytes:secret length:sizeof(secret)];
    request->secret = arguments;
    auto holder = new PasswordSyncHolder(request);
    const char origin[] = "https://fixture.example";
    const char username[] = "fixture";
    const char password[] = "fixture-value";
    ac_passwords_sync_login row{origin, sizeof(origin) - 1, username, sizeof(username) - 1,
                               password, sizeof(password) - 1, 1, 1700000000123};
    PasswordSyncLogin(holder, &row);
    assert(request->rows.count == 1);
    PasswordSyncDone(holder, AC_PASSWORDS_SYNC_ERROR);
    assert(completions == 1 && !request->rows && !request->secret);
    const auto* bytes = static_cast<const unsigned char*>(arguments.bytes);
    for (NSUInteger i = 0; i < arguments.length; ++i) assert(bytes[i] == 0);
    request->Finish(AC_PASSWORDS_SYNC_COMMITTED);
    assert(completions == 1);

    auto revoked = Request();
    revoked->authorized = ^BOOL { return allowed; };
    revoked->completion = ^(ArdiaCorePasswordSyncStatus status, NSArray* rows) {
      assert(status == ArdiaCorePasswordSyncStatusUnauthorized && !rows);
      ++completions;
    };
    holder = new PasswordSyncHolder(revoked);
    PasswordSyncLogin(holder, &row);
    assert(revoked->rows.count == 1);
    allowed = NO;
    PasswordSyncDone(holder, 1);
    assert(completions == 2 && !revoked->rows);

    allowed = YES;
    auto timed_out = Request();
    std::weak_ptr<PasswordSyncCall> lifetime = timed_out;
    timed_out->authorized = ^BOOL { return allowed; };
    timed_out->completion = ^(ArdiaCorePasswordSyncStatus status, NSArray* rows) {
      assert(status == ArdiaCorePasswordSyncStatusError && !rows);
      ++completions;
    };
    holder = new PasswordSyncHolder(timed_out);
    PasswordSyncLogin(holder, &row);
    assert(timed_out->rows.count == 1);
    timed_out->Finish(AC_PASSWORDS_SYNC_ERROR);
    timed_out.reset();
    assert(completions == 3 && !lifetime.expired());
    assert(!PasswordSyncAuthorized(holder));
    PasswordSyncLogin(holder, &row);
    PasswordSyncDone(holder, 1);
    assert(completions == 3 && lifetime.expired());

    const int failureStatuses[] = {AC_PASSWORDS_SYNC_ERROR, AC_PASSWORDS_SYNC_UNAUTHORIZED, AC_PASSWORDS_SYNC_CONFLICT, -99};
    for (int status : failureStatuses) {
      auto failed = Request();
      failed->authorized = ^BOOL { return YES; };
      failed->completion = ^(ArdiaCorePasswordSyncStatus result, NSArray* rows) {
        assert(result != ArdiaCorePasswordSyncStatusCommitted && !rows);
        ++completions;
      };
      holder = new PasswordSyncHolder(failed);
      PasswordSyncLogin(holder, &row);
      PasswordSyncDone(holder, status);
    }
    assert(completions == 7);

    auto committed = Request();
    committed->mutation = true;
    committed->authorized = ^BOOL { assert([NSThread isMainThread]); return allowed; };
    committed->completion = ^(ArdiaCorePasswordSyncStatus status, NSArray* rows) {
      assert([NSThread isMainThread]);
      assert(status == ArdiaCorePasswordSyncStatusCommitted && !rows);
      ++completions;
    };
    holder = new PasswordSyncHolder(committed);
    std::thread backend([holder] {
      assert(PasswordSyncBeginCommit(holder));
      PasswordSyncEndCommit(holder, AC_PASSWORDS_SYNC_COMMITTED);
    });
    backend.join();
    allowed = NO;
    committed->Finish(AC_PASSWORDS_SYNC_ERROR);
    assert(completions == 8);
    assert(!PasswordSyncBeginCommit(holder));
    PasswordSyncDone(holder, AC_PASSWORDS_SYNC_COMMITTED);
    assert(completions == 8);

    auto unproven = Request();
    unproven->mutation = true;
    unproven->authorized = ^BOOL { return YES; };
    unproven->completion = ^(ArdiaCorePasswordSyncStatus status, NSArray* rows) {
      assert(status == ArdiaCorePasswordSyncStatusError && !rows);
      ++completions;
    };
    PasswordSyncDone(new PasswordSyncHolder(unproven), AC_PASSWORDS_SYNC_COMMITTED);
    assert(completions == 9);
    puts("Production native reply buffer: 9 completions; negative statuses rejected; secrets cleared; late callbacks retained safely; committed result survives revocation; unproven commit rejected");
  }
}
