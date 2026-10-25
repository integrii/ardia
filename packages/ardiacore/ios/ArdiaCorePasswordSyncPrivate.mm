#import "ArdiaCorePasswordSyncPrivate.h"

#include <cmath>

using ardiacore_password_sync::AuthorizationLease;
using ardiacore_password_sync::AuthorizationRegistry;
using ardiacore_password_sync::RequestLease;

static double PasswordSyncUptime() { return NSProcessInfo.processInfo.systemUptime; }

@interface ArdiaCorePasswordSyncKeyState () {
  std::shared_ptr<AuthorizationRegistry> _registry;
}
- (std::shared_ptr<AuthorizationRegistry>)registry;
@end

@implementation ArdiaCorePasswordSyncKeyState
- (instancetype)init {
  if ((self = [super init])) _registry = std::make_shared<AuthorizationRegistry>();
  return self;
}
- (std::shared_ptr<AuthorizationRegistry>)registry { return _registry; }
- (void)replaceGeneration:(uint64_t)generation { _registry->ReplaceGeneration(generation); }
- (void)invalidate { _registry->Invalidate(); }
- (void)dealloc { [self invalidate]; }
@end

@interface ArdiaCorePasswordSyncRequest () {
  std::shared_ptr<RequestLease> _lease;
  NSString *_profile;
}
- (instancetype)initWithLease:(std::shared_ptr<RequestLease>)lease profile:(NSString *)profile;
@end

@implementation ArdiaCorePasswordSyncRequest
- (instancetype)initWithLease:(std::shared_ptr<RequestLease>)lease profile:(NSString *)profile {
  if ((self = [super init])) {
    _lease = std::move(lease);
    _profile = [profile copy];
  }
  return self;
}
- (std::shared_ptr<RequestLease>)leaseForProfile:(NSString *)profile {
  return [_profile isEqualToString:profile] ? _lease : nullptr;
}
- (void)cancel { if (_lease) _lease->Cancel(); }
- (void)dealloc { [self cancel]; }
@end

@implementation ArdiaCorePasswordSyncAuthorization {
  std::shared_ptr<AuthorizationLease> _authorization;
  NSSet<NSString *> *_profiles;
}
- (instancetype)initWithProfiles:(NSArray<NSString *> *)profiles expiresAt:(NSTimeInterval)expiresAt
                       keyState:(ArdiaCorePasswordSyncKeyState *)keyState generation:(uint64_t)generation {
  if (![NSThread isMainThread] || !profiles.count || !std::isfinite(expiresAt) || expiresAt <= PasswordSyncUptime()) return nil;
  if ((self = [super init])) {
    _profiles = [NSSet setWithArray:profiles];
    auto registry = [keyState registry];
    if (!registry) return nil;
    _authorization = registry->Authorize(generation, expiresAt, PasswordSyncUptime);
    if (!_authorization) return nil;
  }
  return self;
}
- (ArdiaCorePasswordSyncRequest *)requestForProfile:(NSString *)profile expiresAt:(NSTimeInterval)expiresAt {
  if (![NSThread isMainThread] || ![_profiles containsObject:profile] || !std::isfinite(expiresAt) || expiresAt <= PasswordSyncUptime()) return nil;
  auto lease = std::make_shared<RequestLease>(_authorization, expiresAt);
  if (!lease->Allowed()) return nil;
  return [[ArdiaCorePasswordSyncRequest alloc] initWithLease:std::move(lease) profile:profile];
}
- (void)revoke { if (_authorization) _authorization->Revoke(); }
- (void)dealloc { [self revoke]; }
@end

namespace ardiacore_password_sync __attribute__((visibility("hidden"))) {

void WipeSecret(NSMutableData *secret) {
  volatile unsigned char *bytes = (volatile unsigned char *)secret.mutableBytes;
  for (NSUInteger i = 0; i < secret.length; i++) bytes[i] = 0;
}

bool PasswordSyncCall::Allowed() {
  auto check = authorized;
  return [NSThread isMainThread] && !finished && valid && lease && lease->Allowed() && check && check() && !finished && valid && lease->Allowed();
}

void PasswordSyncCall::Finish(int status) {
  if (finished) return;
  bool allowed = Allowed();
  bool committed = lease && lease->Cancel();
  if (mutation && committed) status = AC_PASSWORDS_SYNC_COMMITTED;
  else if (status == AC_PASSWORDS_SYNC_COMMITTED && !allowed) status = AC_PASSWORDS_SYNC_UNAUTHORIZED;
  else if (mutation && status == AC_PASSWORDS_SYNC_COMMITTED) status = AC_PASSWORDS_SYNC_ERROR;
  if (status != AC_PASSWORDS_SYNC_COMMITTED && status != AC_PASSWORDS_SYNC_CONFLICT &&
      status != AC_PASSWORDS_SYNC_UNAUTHORIZED) status = AC_PASSWORDS_SYNC_ERROR;
  finished = true;
  auto done = completion;
  NSArray<NSDictionary<NSString *, id> *> *result = !mutation && status == AC_PASSWORDS_SYNC_COMMITTED ? [rows copy] : nil;
  WipeSecret(secret);
  secret = nil;
  rows = nil;
  authorized = nil;
  completion = nil;
  if (done) done(static_cast<ArdiaCorePasswordSyncStatus>(status), result);
}

int PasswordSyncAuthorized(void *context) {
  return (*static_cast<PasswordSyncHolder *>(context))->Allowed();
}

int PasswordSyncBeginCommit(void *context) {
  auto lease = (*static_cast<PasswordSyncHolder *>(context))->lease;
  return lease && lease->BeginCommit();
}

void PasswordSyncEndCommit(void *context, int committed) {
  (*static_cast<PasswordSyncHolder *>(context))->lease->EndCommit(committed == AC_PASSWORDS_SYNC_COMMITTED);
}

void PasswordSyncLogin(void *context, const ac_passwords_sync_login *login) {
  auto request = *static_cast<PasswordSyncHolder *>(context);
  if (!request->Allowed() || !login) return;
  NSString *origin = [[NSString alloc] initWithBytes:login->origin length:login->origin_size encoding:NSUTF8StringEncoding];
  NSString *username = [[NSString alloc] initWithBytes:login->username length:login->username_size encoding:NSUTF8StringEncoding];
  NSString *password = [[NSString alloc] initWithBytes:login->password length:login->password_size encoding:NSUTF8StringEncoding];
  if (!origin || !username || !password || (login->has_created && !std::isfinite(login->created_ms))) {
    request->valid = false;
    return;
  }
  [request->rows addObject:@{@"origin" : origin, @"username" : username, @"password" : password,
                            @"created" : login->has_created ? @(login->created_ms) : NSNull.null}];
}

void PasswordSyncDone(void *context, int status) {
  std::unique_ptr<PasswordSyncHolder> holder(static_cast<PasswordSyncHolder *>(context));
  auto request = *holder;
  if ([NSThread isMainThread]) request->Finish(status);
  else dispatch_async(dispatch_get_main_queue(), ^{ request->Finish(status); });
}

}
