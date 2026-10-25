#import "ArdiaCoreEngineBridge.h"
#import "ArdiaCoreInternal.h"
#include "../../../engine/chromium/src/chrome/browser/ardia/public/ac_engine.h"

#include <cassert>
#include <cstring>
#include <limits>
#include <vector>

static bool gLoading = false;
static bool gDeferred = false;
static bool gInvalidUTF8 = false;
static int gReads = 0;
static int gWrites = 0;
static bool gHasCreated = true;
static double gCreatedMillis = 1700000000123;
static NSMutableArray *gProfileWaiters = [NSMutableArray array];

@implementation ArdiaCoreHost
+ (BOOL)isStarted { return YES; }
@end

@implementation ArdiaCoreProfile
- (NSString *)path { return @"/fixture/password-sync"; }
- (BOOL)offTheRecord { return NO; }
@end

namespace ardiacore_host {
bool IsIncognito(NSString *profile) { return [profile hasPrefix:@"incognito:"]; }
NSString *OriginalProfileName(NSString *profile) { return profile; }
NSArray<ArdiaCoreProfile *> *LoadedProfiles() { return @[]; }
NSString *ProfileName(ArdiaCoreProfile *) { return @""; }
void WithProfile(NSString *, void (^completion)(ArdiaCoreProfile *)) {
  if (gLoading) [gProfileWaiters addObject:[completion copy]];
  else completion([ArdiaCoreProfile new]);
}
}

struct PendingRead {
  ac_passwords_sync_authorized_t authorized;
  ac_passwords_sync_login_t login;
  ac_passwords_sync_done_t done;
  void *context;
};

static std::vector<PendingRead> gPending;

static void Complete(PendingRead request) {
  if (request.authorized(request.context)) {
    const char origin[] = "https://fixture.example";
    const char username[] = {'a', 0, 'b'};
    const char password[] = {'s', 0, 't'};
    const char invalid[] = {static_cast<char>(0xff)};
    ac_passwords_sync_login row{origin, sizeof(origin) - 1, username, sizeof(username),
                               gInvalidUTF8 ? invalid : password, gInvalidUTF8 ? sizeof(invalid) : sizeof(password),
                               gHasCreated ? 1 : 0, gCreatedMillis};
    request.login(request.context, &row);
  }
  request.done(request.context, request.authorized(request.context));
}

extern "C" AC_ENGINE_EXPORT void ac_passwords_sync_read(const char *, ac_passwords_sync_authorized_t authorized,
                                                       ac_passwords_sync_login_t login, ac_passwords_sync_done_t done, void *context) {
  gReads++;
  PendingRead request{authorized, login, done, context};
  if (gDeferred) gPending.push_back(request);
  else Complete(request);
}

extern "C" AC_ENGINE_EXPORT void ac_passwords_sync_compare_and_set(const char *, const char *json,
                                                                  ac_passwords_sync_authorized_t authorized,
                                                                  ac_passwords_sync_done_t done, void *context) {
  gWrites++;
  assert(strstr(json, "expectedPasswordHex") && strstr(json, "desiredPasswordHex"));
  assert(!strstr(json, "plain-secret"));
  done(context, authorized(context));
}

static bool AllZero(NSData *data) {
  const unsigned char *bytes = static_cast<const unsigned char *>(data.bytes);
  for (NSUInteger i = 0; i < data.length; i++) if (bytes[i]) return false;
  return true;
}

static NSMutableData *Arguments() {
  const char value[] = "{\"expectedPasswordHex\":\"61\",\"desiredPasswordHex\":\"62\"}";
  return [NSMutableData dataWithBytes:value length:sizeof(value)];
}

int main() {
  @autoreleasepool {
    __block BOOL allowed = YES;
    __block int completed = 0;
    BOOL (^authorized)(void) = ^BOOL { return allowed; };
    [ArdiaCoreEngineBridge readPasswordsForSync:@"" authorized:authorized completion:^(NSArray<NSDictionary<NSString *, id> *> *rows) {
      assert(rows.count == 1);
      NSString *password = rows[0][@"password"];
      assert(password.length == 3 && [password characterAtIndex:1] == 0);
      assert([rows[0][@"created"] doubleValue] == 1700000000123);
      completed++;
    }];
    assert(completed == 1 && gReads == 1);

    allowed = NO;
    [ArdiaCoreEngineBridge readPasswordsForSync:@"" authorized:authorized completion:^(NSArray *rows) { assert(!rows); completed++; }];
    assert(completed == 2 && gReads == 1);
    allowed = YES;
    [ArdiaCoreEngineBridge readPasswordsForSync:@"incognito:fixture" authorized:authorized completion:^(NSArray *rows) { assert(!rows); completed++; }];
    assert(completed == 3 && gReads == 1);

    const char nulName[] = "ac_passwords_sync_read\0suffix";
    NSString *embedded = [[NSString alloc] initWithBytes:nulName length:sizeof(nulName) - 1 encoding:NSUTF8StringEncoding];
    for (NSString *name in @[@"ac_passwords_sync_read", @"ac_passwords_sync_compare_and_set", embedded]) {
      [ArdiaCoreEngineBridge call:name profile:@"" args:nil completion:^(NSString *reply) {
        assert([reply containsString:@"native-only"]);
        completed++;
      }];
      NSMutableData *secret = Arguments();
      [ArdiaCoreEngineBridge callWithSecret:name profile:@"" args:secret completion:^(NSString *reply) {
        assert([reply containsString:@"native-only"]);
        completed++;
      }];
      assert(AllZero(secret));
      assert(![ArdiaCoreEngineBridge exports:name]);
    }
    assert(gReads == 1 && gWrites == 0 && completed == 9);

    NSMutableData *secret = Arguments();
    [ArdiaCoreEngineBridge compareAndSetPasswordForSync:@"" args:secret authorized:authorized completion:^(BOOL success) {
      assert(success);
      completed++;
    }];
    assert(AllZero(secret) && gWrites == 1 && completed == 10);

    gInvalidUTF8 = true;
    [ArdiaCoreEngineBridge readPasswordsForSync:@"" authorized:authorized completion:^(NSArray *rows) { assert(!rows); completed++; }];
    assert(completed == 11);
    gInvalidUTF8 = false;

    gDeferred = true;
    [ArdiaCoreEngineBridge readPasswordsForSync:@"" authorized:authorized completion:^(NSArray *rows) { assert(!rows); completed++; }];
    assert(completed == 11 && gPending.size() == 1);
    allowed = NO;
    Complete(gPending.back());
    gPending.clear();
    assert(completed == 12);
    allowed = YES;

    [ArdiaCoreEngineBridge readPasswordsForSync:@"" authorized:authorized completion:^(NSArray *rows) { assert(!rows); completed++; }];
    assert(gPending.size() == 1);
    gLoading = true;
    NSMutableData *waitingSecret = Arguments();
    [ArdiaCoreEngineBridge compareAndSetPasswordForSync:@"" args:waitingSecret authorized:authorized completion:^(BOOL success) {
      assert(!success);
      completed++;
    }];
    assert(gProfileWaiters.count == 1 && !AllZero(waitingSecret));
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:12];
    while (completed < 14 && deadline.timeIntervalSinceNow > 0) {
      [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    }
    assert(completed == 14 && AllZero(waitingSecret));
    assert(!gPending.back().authorized(gPending.back().context));
    Complete(gPending.back());
    gPending.clear();
    gLoading = false;
    for (void (^waiter)(ArdiaCoreProfile *) in [gProfileWaiters copy]) waiter([ArdiaCoreProfile new]);
    [gProfileWaiters removeAllObjects];
    assert(completed == 14 && gWrites == 1);
    gDeferred = false;
    gCreatedMillis = 0;
    [ArdiaCoreEngineBridge readPasswordsForSync:@"" authorized:authorized completion:^(NSArray<NSDictionary<NSString *, id> *> *rows) {
      assert([rows[0][@"created"] isKindOfClass:NSNumber.class]);
      assert([rows[0][@"created"] doubleValue] == 0);
      completed++;
    }];
    gHasCreated = false;
    gCreatedMillis = 1700000000123;
    [ArdiaCoreEngineBridge readPasswordsForSync:@"" authorized:authorized completion:^(NSArray<NSDictionary<NSString *, id> *> *rows) {
      assert(rows[0][@"created"] == NSNull.null);
      completed++;
    }];
    gHasCreated = true;
    gCreatedMillis = std::numeric_limits<double>::quiet_NaN();
    [ArdiaCoreEngineBridge readPasswordsForSync:@"" authorized:authorized completion:^(NSArray *rows) { assert(!rows); completed++; }];
    assert(completed == 17);
    puts("Production native bridge: typed dispatch, creation timestamps/epoch/null, denial, private profile, NUL-safe results, generic-call rejection, buffer clearing, revocation, timeout, and late callbacks passed");
  }
}
