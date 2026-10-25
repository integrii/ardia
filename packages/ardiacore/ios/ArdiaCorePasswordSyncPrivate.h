#pragma once

#import <Foundation/Foundation.h>
#import "ArdiaCoreServices.h"
#include "ArdiaCorePasswordSyncLease.h"

#include <memory>

#include "../../../engine/chromium/src/chrome/browser/ardia/public/ac_engine.h"

@interface ArdiaCorePasswordSyncRequest (NativeLease)
- (std::shared_ptr<ardiacore_password_sync::RequestLease>)leaseForProfile:(NSString *)profile;
@end

namespace ardiacore_password_sync __attribute__((visibility("hidden"))) {

void WipeSecret(NSMutableData *secret);

struct PasswordSyncCall {
  BOOL (^authorized)(void);
  void (^completion)(ArdiaCorePasswordSyncStatus, NSArray<NSDictionary<NSString *, id> *> *);
  std::shared_ptr<RequestLease> lease;
  NSMutableArray<NSDictionary<NSString *, id> *> *rows = [NSMutableArray array];
  NSMutableData *secret = nil;
  bool finished = false;
  bool valid = true;
  bool mutation = false;

  bool Allowed();
  void Finish(int status);
};

using PasswordSyncHolder = std::shared_ptr<PasswordSyncCall>;

int PasswordSyncAuthorized(void *context);
int PasswordSyncBeginCommit(void *context);
void PasswordSyncEndCommit(void *context, int committed);
void PasswordSyncLogin(void *context, const ac_passwords_sync_login *login);
void PasswordSyncDone(void *context, int success);

}
