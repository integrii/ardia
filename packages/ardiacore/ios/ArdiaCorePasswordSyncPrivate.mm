#import "ArdiaCorePasswordSyncPrivate.h"

#include <cmath>

namespace ardiacore_password_sync __attribute__((visibility("hidden"))) {

void WipeSecret(NSMutableData *secret) {
  volatile unsigned char *bytes = (volatile unsigned char *)secret.mutableBytes;
  for (NSUInteger i = 0; i < secret.length; i++) bytes[i] = 0;
}

bool PasswordSyncCall::Allowed() {
  auto check = authorized;
  return [NSThread isMainThread] && !finished && valid && check && check() && !finished && valid;
}

void PasswordSyncCall::Finish(bool success) {
  if (finished) return;
  success = success && Allowed();
  finished = true;
  auto done = completion;
  NSArray<NSDictionary<NSString *, id> *> *result = success ? [rows copy] : nil;
  WipeSecret(secret);
  secret = nil;
  rows = nil;
  authorized = nil;
  completion = nil;
  if (done) done(success, result);
}

int PasswordSyncAuthorized(void *context) {
  return (*static_cast<PasswordSyncHolder *>(context))->Allowed();
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

void PasswordSyncDone(void *context, int success) {
  std::unique_ptr<PasswordSyncHolder> holder(static_cast<PasswordSyncHolder *>(context));
  (*holder)->Finish(success != 0);
}

}
