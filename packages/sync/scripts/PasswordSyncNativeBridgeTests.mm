#import "ArdiaCoreEngineBridge.h"
#import "ArdiaCoreInternal.h"
#include "../../../engine/chromium/src/chrome/browser/ardia/public/ac_engine.h"

#include <cassert>
#include <cstring>
#include <limits>
#include <thread>
#include <vector>

static bool gLoading = false;
static bool gStarted = true;
static bool gDeferWrites = false;
static int gWriteStatus = AC_PASSWORDS_SYNC_COMMITTED;
static bool gDeferred = false;
static bool gInvalidUTF8 = false;
static int gReads = 0;
static int gWrites = 0;
static int gLegacyWrites = 0;
static int gCommittedWrites = 0;
static bool gHasCreated = true;
static double gCreatedMillis = 1700000000123;
static NSMutableArray *gProfileWaiters = [NSMutableArray array];
static NSMutableArray *gRequests = [NSMutableArray array];
static ArdiaCorePasswordSyncAuthorization *gAuthorization;
static ArdiaCorePasswordSyncKeyState *gKeyState;

static ArdiaCorePasswordSyncRequest *Request(NSString *profile = @"") {
  auto request = [gAuthorization requestForProfile:profile expiresAt:NSProcessInfo.processInfo.systemUptime + 10];
  assert(request);
  [gRequests addObject:request];
  return request;
}

@implementation ArdiaCoreHost
+ (BOOL)isStarted { return gStarted; }
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
  request.done(request.context, request.authorized(request.context) ? AC_PASSWORDS_SYNC_COMMITTED : AC_PASSWORDS_SYNC_UNAUTHORIZED);
}

extern "C" AC_ENGINE_EXPORT void ac_passwords_sync_read(const char *, ac_passwords_sync_authorized_t authorized,
                                                       ac_passwords_sync_login_t login, ac_passwords_sync_done_t done, void *context) {
  gReads++;
  PendingRead request{authorized, login, done, context};
  if (gDeferred) gPending.push_back(request);
  else Complete(request);
}

struct PendingWrite {
  ac_passwords_sync_begin_commit_t begin;
  ac_passwords_sync_end_commit_t end;
  ac_passwords_sync_done_t done;
  void *context;
};

static std::vector<PendingWrite> gPendingWrites;

static void CompleteWrite(PendingWrite request, int status = AC_PASSWORDS_SYNC_COMMITTED) {
  if (status == AC_PASSWORDS_SYNC_COMMITTED) {
    if (!request.begin(request.context)) status = AC_PASSWORDS_SYNC_UNAUTHORIZED;
    else {
      ++gCommittedWrites;
      request.end(request.context, AC_PASSWORDS_SYNC_COMMITTED);
    }
  }
  request.done(request.context, status);
}

extern "C" AC_ENGINE_EXPORT void ac_passwords_sync_compare_and_set(const char *, const char *,
                                                                  ac_passwords_sync_authorized_t,
                                                                  ac_passwords_sync_done_t done, void *context) {
  ++gLegacyWrites;
  done(context, AC_PASSWORDS_SYNC_UNAUTHORIZED);
}

#ifndef ARDIA_TEST_OLD_TYPED_ENGINE
extern "C" AC_ENGINE_EXPORT void ac_passwords_sync_compare_and_set_v2(const char *, const char *json,
                                                                  ac_passwords_sync_authorized_t authorized,
                                                                  ac_passwords_sync_begin_commit_t begin,
                                                                  ac_passwords_sync_end_commit_t end,
                                                                  ac_passwords_sync_done_t done, void *context) {
  gWrites++;
  assert(strstr(json, "expectedPasswordHex") && strstr(json, "desiredPasswordHex"));
  assert(!strstr(json, "plain-secret"));
  assert([NSThread isMainThread] && authorized(context));
  PendingWrite request{begin, end, done, context};
  if (gDeferWrites) gPendingWrites.push_back(request);
  else CompleteWrite(request, gWriteStatus);
}
#endif

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
    gKeyState = [ArdiaCorePasswordSyncKeyState new];
    gAuthorization = [[ArdiaCorePasswordSyncAuthorization alloc] initWithProfiles:@[@"", @"incognito:fixture"] expiresAt:NSProcessInfo.processInfo.systemUptime + 60 keyState:gKeyState generation:0];
    __block BOOL allowed = YES;
    __block int completed = 0;
    BOOL (^authorized)(void) = ^BOOL { assert([NSThread isMainThread]); return allowed; };
#ifdef ARDIA_TEST_OLD_TYPED_ENGINE
    auto arguments = Arguments();
    [ArdiaCoreEngineBridge compareAndSetPasswordForSync:@"" args:arguments request:Request() authorized:authorized completion:^(ArdiaCorePasswordSyncStatus status) {
      assert(status == ArdiaCorePasswordSyncStatusError);
      completed++;
    }];
    assert(completed == 1 && gLegacyWrites == 0 && gWrites == 0 && AllZero(arguments));
    puts("Production native bridge: old five-argument engine denied without calling legacy symbol");
    return 0;
#endif
    [ArdiaCoreEngineBridge readPasswordsForSync:@"" request:Request() authorized:authorized completion:^(NSArray<NSDictionary<NSString *, id> *> *rows) {
      assert(rows.count == 1);
      NSString *password = rows[0][@"password"];
      assert(password.length == 3 && [password characterAtIndex:1] == 0);
      assert([rows[0][@"created"] doubleValue] == 1700000000123);
      completed++;
    }];
    assert(completed == 1 && gReads == 1);

    allowed = NO;
    [ArdiaCoreEngineBridge readPasswordsForSync:@"" request:Request() authorized:authorized completion:^(NSArray *rows) { assert(!rows); completed++; }];
    assert(completed == 2 && gReads == 1);
    allowed = YES;
    [ArdiaCoreEngineBridge readPasswordsForSync:@"incognito:fixture" request:Request(@"incognito:fixture") authorized:authorized completion:^(NSArray *rows) { assert(!rows); completed++; }];
    assert(completed == 3 && gReads == 1);

    NSMutableArray<NSString *> *blockedNames = [NSMutableArray array];
    for (NSString *name in @[@"ac_passwords_sync_read", @"ac_passwords_sync_compare_and_set", @"ac_passwords_sync_compare_and_set_v2"]) {
      [blockedNames addObject:name];
      NSMutableData *embedded = [[name dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
      const char suffix[] = "\0suffix";
      [embedded appendBytes:suffix length:sizeof(suffix) - 1];
      [blockedNames addObject:[[NSString alloc] initWithData:embedded encoding:NSUTF8StringEncoding]];
    }
    __block int genericCompletions = 0;
    for (NSString *name in blockedNames) {
      [ArdiaCoreEngineBridge call:name profile:@"" args:nil completion:^(NSString *reply) {
        assert([reply containsString:@"native-only"]);
        genericCompletions++;
      }];
      NSMutableData *secret = Arguments();
      [ArdiaCoreEngineBridge callWithSecret:name profile:@"" args:secret completion:^(NSString *reply) {
        assert([reply containsString:@"native-only"]);
        genericCompletions++;
      }];
      assert(AllZero(secret));
      assert(![ArdiaCoreEngineBridge exports:name]);
    }
    assert(gReads == 1 && gWrites == 0 && gLegacyWrites == 0 && completed == 3);
    assert(genericCompletions == 12);

    NSMutableData *secret = Arguments();
    [ArdiaCoreEngineBridge compareAndSetPasswordForSync:@"" args:secret request:Request() authorized:authorized completion:^(ArdiaCorePasswordSyncStatus status) {
      assert(status == ArdiaCorePasswordSyncStatusCommitted);
      completed++;
    }];
    assert(AllZero(secret) && gWrites == 1 && completed == 4);

    gInvalidUTF8 = true;
    [ArdiaCoreEngineBridge readPasswordsForSync:@"" request:Request() authorized:authorized completion:^(NSArray *rows) { assert(!rows); completed++; }];
    assert(completed == 5);
    gInvalidUTF8 = false;

    gDeferred = true;
    [ArdiaCoreEngineBridge readPasswordsForSync:@"" request:Request() authorized:authorized completion:^(NSArray *rows) { assert(!rows); completed++; }];
    assert(completed == 5 && gPending.size() == 1);
    allowed = NO;
    Complete(gPending.back());
    gPending.clear();
    assert(completed == 6);
    allowed = YES;

    [ArdiaCoreEngineBridge readPasswordsForSync:@"" request:Request() authorized:authorized completion:^(NSArray *rows) { assert(!rows); completed++; }];
    assert(gPending.size() == 1);
    gLoading = true;
    NSMutableData *waitingSecret = Arguments();
    [ArdiaCoreEngineBridge compareAndSetPasswordForSync:@"" args:waitingSecret request:Request() authorized:authorized completion:^(ArdiaCorePasswordSyncStatus status) {
      assert(status != ArdiaCorePasswordSyncStatusCommitted);
      completed++;
    }];
    assert(gProfileWaiters.count == 1 && !AllZero(waitingSecret));
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:12];
    while (completed < 8 && deadline.timeIntervalSinceNow > 0) {
      [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    }
    assert(completed == 8 && AllZero(waitingSecret));
    assert(!gPending.back().authorized(gPending.back().context));
    Complete(gPending.back());
    gPending.clear();
    gLoading = false;
    for (void (^waiter)(ArdiaCoreProfile *) in [gProfileWaiters copy]) waiter([ArdiaCoreProfile new]);
    [gProfileWaiters removeAllObjects];
    assert(completed == 8 && gWrites == 1);
    gDeferred = false;
    gCreatedMillis = 0;
    [ArdiaCoreEngineBridge readPasswordsForSync:@"" request:Request() authorized:authorized completion:^(NSArray<NSDictionary<NSString *, id> *> *rows) {
      assert([rows[0][@"created"] isKindOfClass:NSNumber.class]);
      assert([rows[0][@"created"] doubleValue] == 0);
      completed++;
    }];
    gHasCreated = false;
    gCreatedMillis = 1700000000123;
    [ArdiaCoreEngineBridge readPasswordsForSync:@"" request:Request() authorized:authorized completion:^(NSArray<NSDictionary<NSString *, id> *> *rows) {
      assert(rows[0][@"created"] == NSNull.null);
      completed++;
    }];
    gHasCreated = true;
    gCreatedMillis = std::numeric_limits<double>::quiet_NaN();
    [ArdiaCoreEngineBridge readPasswordsForSync:@"" request:Request() authorized:authorized completion:^(NSArray *rows) { assert(!rows); completed++; }];
    assert(completed == 11);
    for (int status : {AC_PASSWORDS_SYNC_CONFLICT, AC_PASSWORDS_SYNC_ERROR, AC_PASSWORDS_SYNC_UNAUTHORIZED}) {
      gWriteStatus = status;
      [ArdiaCoreEngineBridge compareAndSetPasswordForSync:@"" args:Arguments() request:Request() authorized:authorized completion:^(ArdiaCorePasswordSyncStatus result) {
        assert(result == status && result != ArdiaCorePasswordSyncStatusCommitted);
        completed++;
      }];
    }
    assert(completed == 14);
    gWriteStatus = AC_PASSWORDS_SYNC_COMMITTED;
    gDeferWrites = true;
    auto cancelled = Request();
    [ArdiaCoreEngineBridge compareAndSetPasswordForSync:@"" args:Arguments() request:cancelled authorized:authorized completion:^(ArdiaCorePasswordSyncStatus status) {
      assert(status == ArdiaCorePasswordSyncStatusUnauthorized);
      completed++;
    }];
    [cancelled cancel];
    CompleteWrite(gPendingWrites.back());
    gPendingWrites.clear();
    assert(completed == 15);

    [ArdiaCoreEngineBridge compareAndSetPasswordForSync:@"" args:Arguments() request:Request() authorized:authorized completion:^(ArdiaCorePasswordSyncStatus status) {
      assert([NSThread isMainThread] && status == ArdiaCorePasswordSyncStatusCommitted);
      completed++;
    }];
    auto committed = gPendingWrites.back();
    gPendingWrites.clear();
    std::thread backend([committed] { CompleteWrite(committed); });
    backend.join();
    [gAuthorization revoke];
    allowed = NO;
    assert(completed == 15);
    deadline = [NSDate dateWithTimeIntervalSinceNow:2];
    while (completed < 16 && deadline.timeIntervalSinceNow > 0) {
      [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    }
    assert(completed == 16);
    allowed = YES;
    gAuthorization = [[ArdiaCorePasswordSyncAuthorization alloc] initWithProfiles:@[@""] expiresAt:NSProcessInfo.processInfo.systemUptime + 60 keyState:gKeyState generation:0];
    gLoading = true;
    auto shutdownRequest = Request();
    [ArdiaCoreEngineBridge compareAndSetPasswordForSync:@"" args:Arguments() request:shutdownRequest authorized:authorized completion:^(ArdiaCorePasswordSyncStatus status) {
      assert(status == ArdiaCorePasswordSyncStatusUnauthorized);
      completed++;
    }];
    gStarted = false;
    for (void (^waiter)(ArdiaCoreProfile *) in [gProfileWaiters copy]) waiter([ArdiaCoreProfile new]);
    [gProfileWaiters removeAllObjects];
    assert(completed == 17 && gPendingWrites.empty());
    gLoading = false;
    gStarted = true;

    [ArdiaCoreEngineBridge compareAndSetPasswordForSync:@"" args:Arguments() request:Request() authorized:authorized completion:^(ArdiaCorePasswordSyncStatus status) {
      assert(status == ArdiaCorePasswordSyncStatusUnauthorized && [NSThread isMainThread]);
      completed++;
    }];
    auto stale = gPendingWrites.back();
    gPendingWrites.clear();
    int beforeKeyChange = gCommittedWrites;
    std::thread workQueue([] {
      @autoreleasepool { [gKeyState replaceGeneration:1]; }
    });
    workQueue.join();
    std::thread staleBackend([stale] { CompleteWrite(stale); });
    staleBackend.join();
    assert(completed == 17 && gCommittedWrites == beforeKeyChange);
    assert(![[ArdiaCorePasswordSyncAuthorization alloc] initWithProfiles:@[@""] expiresAt:NSProcessInfo.processInfo.systemUptime + 60 keyState:gKeyState generation:0]);
    deadline = [NSDate dateWithTimeIntervalSinceNow:2];
    while (completed < 18 && deadline.timeIntervalSinceNow > 0) {
      [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    }
    assert(completed == 18);
    gAuthorization = [[ArdiaCorePasswordSyncAuthorization alloc] initWithProfiles:@[@""] expiresAt:NSProcessInfo.processInfo.systemUptime + 60 keyState:gKeyState generation:1];
    [ArdiaCoreEngineBridge compareAndSetPasswordForSync:@"" args:Arguments() request:Request() authorized:authorized completion:^(ArdiaCorePasswordSyncStatus status) {
      assert(status == ArdiaCorePasswordSyncStatusUnauthorized);
      completed++;
    }];
    [gKeyState invalidate];
    CompleteWrite(gPendingWrites.back());
    gPendingWrites.clear();
    assert(completed == 19 && gCommittedWrites == beforeKeyChange);
    [gRequests removeAllObjects];
    gAuthorization = nil;
    puts("Production native bridge: 19 native and 12 generic-denial completions; typed statuses, dates, private profiles, NUL safety, clearing, cancellation, revocation, timeout, shutdown, late completion, worker key changes with main blocked; fixture storage is not Chromium DB");
  }
}
