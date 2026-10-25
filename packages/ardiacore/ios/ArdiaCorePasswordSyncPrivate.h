#pragma once

#import <Foundation/Foundation.h>

#include <memory>

#include "../../../engine/chromium/src/chrome/browser/ardia/public/ac_engine.h"

namespace ardiacore_password_sync __attribute__((visibility("hidden"))) {

void WipeSecret(NSMutableData *secret);

struct PasswordSyncCall {
  BOOL (^authorized)(void);
  void (^completion)(BOOL, NSArray<NSDictionary<NSString *, id> *> *);
  NSMutableArray<NSDictionary<NSString *, id> *> *rows = [NSMutableArray array];
  NSMutableData *secret = nil;
  bool finished = false;
  bool valid = true;

  bool Allowed();
  void Finish(bool success);
};

using PasswordSyncHolder = std::shared_ptr<PasswordSyncCall>;

int PasswordSyncAuthorized(void *context);
void PasswordSyncLogin(void *context, const ac_passwords_sync_login *login);
void PasswordSyncDone(void *context, int success);

}
