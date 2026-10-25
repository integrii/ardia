#import <Foundation/Foundation.h>
#include "chrome/browser/ardia/public/ac_engine.h"

#include <cassert>
#include <cmath>
#include <memory>

#include "password_sync_reply_buffer.inc"

int main() {
  @autoreleasepool {
    auto request = std::make_shared<PasswordSyncCall>();
    __block int completions = 0;
    __block BOOL allowed = YES;
    request->authorized = ^BOOL { return allowed; };
    request->completion = ^(BOOL success, NSArray* rows) {
      assert(!success && !rows);
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
    PasswordSyncDone(holder, 0);
    assert(completions == 1 && !request->rows && !request->secret);
    const auto* bytes = static_cast<const unsigned char*>(arguments.bytes);
    for (NSUInteger i = 0; i < arguments.length; ++i) assert(bytes[i] == 0);
    request->Finish(true);
    assert(completions == 1);

    auto revoked = std::make_shared<PasswordSyncCall>();
    revoked->authorized = ^BOOL { return allowed; };
    revoked->completion = ^(BOOL success, NSArray* rows) {
      assert(!success && !rows);
      ++completions;
    };
    holder = new PasswordSyncHolder(revoked);
    PasswordSyncLogin(holder, &row);
    assert(revoked->rows.count == 1);
    allowed = NO;
    PasswordSyncDone(holder, 1);
    assert(completions == 2 && !revoked->rows);
    puts("Production native reply buffer: failed and revoked snapshots discard all buffered rows; owned argument buffer cleared; completion once");
  }
}
