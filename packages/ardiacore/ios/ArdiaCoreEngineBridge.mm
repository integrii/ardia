#import "ArdiaCoreEngineBridge.h"

#import "ArdiaCoreInternal.h"
#import "ArdiaCorePasswordSyncPrivate.h"

#import <dlfcn.h>
#include <stdlib.h>
#include <memory>

#include "../../../engine/chromium/src/chrome/browser/ardia/public/ac_engine.h"

namespace {

using ardiacore_password_sync::PasswordSyncAuthorized;
using ardiacore_password_sync::PasswordSyncCall;
using ardiacore_password_sync::PasswordSyncDone;
using ardiacore_password_sync::PasswordSyncHolder;
using ardiacore_password_sync::PasswordSyncLogin;
using ardiacore_password_sync::WipeSecret;

void (^gEventHandler)(NSString *, NSString *);
NSSet<NSString *> *gForwardedTopics;
NSMutableArray<NSArray *> *gPendingForwards;

void *Symbol(const char *name) {
  return dlsym(RTLD_DEFAULT, name);
}

bool PasswordSyncSymbol(NSString *name) {
  const char *symbol = name.UTF8String;
  return symbol && (!strcmp(symbol, "ac_passwords_sync_read") || !strcmp(symbol, "ac_passwords_sync_compare_and_set"));
}

void StartPasswordSync(NSString *profile, PasswordSyncHolder request,
                       ac_passwords_sync_read_t read,
                       ac_passwords_sync_compare_and_set_t write) {
  if (!request->Allowed() || ardiacore_host::IsIncognito(profile) || (!read && !write)) return request->Finish(false);
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
    request->Finish(false);
  });
  ardiacore_host::WithProfile(profile ?: @"", ^(ArdiaCoreProfile *p) {
    if (!request->Allowed() || !p || !ArdiaCoreHost.isStarted || ([p respondsToSelector:@selector(offTheRecord)] && p.offTheRecord)) {
      return request->Finish(false);
    }
    auto holder = new PasswordSyncHolder(request);
    if (read) {
      read(p.path.UTF8String, PasswordSyncAuthorized, PasswordSyncLogin, PasswordSyncDone, holder);
    } else {
      NSMutableData *secret = request->secret;
      write(p.path.UTF8String, (const char *)secret.bytes, PasswordSyncAuthorized, PasswordSyncDone, holder);
      WipeSecret(secret);
      request->secret = nil;
    }
  });
}

NSString *JSON(id value) {
  NSData *data = [NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
  return data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"{}";
}

void Replied(void *context, const char *json) {
  void (^completion)(NSString *) = (__bridge_transfer void (^)(NSString *))context;
  completion(json ? @(json) : JSON(@{@"error" : @"bad reply from the engine"}));
}

NSString *RealPath(NSString *path) {
  char resolved[PATH_MAX];
  return realpath(path.fileSystemRepresentation, resolved) ? @(resolved) : path;
}

NSString *ProfileNamed(NSString *dir) {
  NSString *real = RealPath(dir);
  for (ArdiaCoreProfile *profile in ardiacore_host::LoadedProfiles())
    if (!([profile respondsToSelector:@selector(offTheRecord)] && profile.offTheRecord) && [RealPath(profile.path) isEqualToString:real]) return ardiacore_host::ProfileName(profile);
  NSString *name = real.lastPathComponent;
  return [name hasPrefix:@"Profile "] ? [name substringFromIndex:8] : @"";
}

int EngineABI() {
  static int abi = [] {
    auto version = (ac_engine_abi_version_t)Symbol("ac_engine_abi_version");
    return version ? version() : 0;
  }();
  return abi;
}

NSMutableDictionary<NSString *, NSMutableArray *> *Observers() {
  static NSMutableDictionary *observers = [NSMutableDictionary dictionary];
  return observers;
}

bool ForwardsEveryEngineEvent() {
  static const bool every = [] {
    const char *value = getenv("ARDIA_ENGINE_EVENT_FORWARD");
    return value && !strcmp(value, "all");
  }();
  return every;
}

bool Forwarded(NSString *topic) {
  return gEventHandler && (ForwardsEveryEngineEvent() || !gForwardedTopics || [gForwardedTopics containsObject:topic]);
}

void FlushForwards() {
  NSArray<NSArray *> *events = gPendingForwards;
  gPendingForwards = nil;
  for (NSArray *event in events)
    if (gEventHandler) gEventHandler(event[0], JSON(event[1]));
}

void Forward(NSString *topic, NSDictionary *payload) {
  if (ForwardsEveryEngineEvent()) return gEventHandler(topic, JSON(payload));
  NSArray *event = @[ topic, [payload copy] ];
  if (gPendingForwards) {
    if (![gPendingForwards.lastObject isEqualToArray:event]) [gPendingForwards addObject:event];
    return;
  }
  gPendingForwards = [NSMutableArray arrayWithObject:event];
  dispatch_async(dispatch_get_main_queue(), ^{
    FlushForwards();
  });
}

void Dispatch(void *, const char *topic, const char *json) {
  if (!topic) return;
  NSString *name = @(topic);
  NSArray *observers = [Observers()[name] copy];
  bool forwarded = Forwarded(name);
  if (!observers.count && !forwarded) return;
  NSData *data = [@(json ?: "{}") dataUsingEncoding:NSUTF8StringEncoding];
  NSMutableDictionary *payload = [[NSJSONSerialization JSONObjectWithData:data options:0 error:nil] mutableCopy] ?: [NSMutableDictionary dictionary];
  if ([payload[@"profile"] isKindOfClass:NSString.class]) payload[@"profile"] = ProfileNamed(payload[@"profile"]);
  for (void (^observer)(NSDictionary *) in observers) observer(payload);
  if (forwarded) Forward(name, payload);
}

void InstallSink() {
  static bool installed = false;
  if (installed) return;
  auto sink = (ac_engine_set_event_sink_t)Symbol("ac_engine_set_event_sink");
  if (!sink) return;
  installed = true;
  sink(Dispatch, nullptr);
}

}

@implementation ArdiaCoreEngineBridge

+ (void)call:(NSString *)name profile:(NSString *)profile args:(NSString *)args completion:(void (^)(NSString *))completion {
  if (PasswordSyncSymbol(name)) return completion(JSON(@{@"error" : @"native-only password sync endpoint"}));
  auto call = (ac_engine_call_t)Symbol(name.UTF8String);
  if (!call) return completion(JSON(@{@"error" : [NSString stringWithFormat:@"the engine has no %@", name]}));
  if (ardiacore_host::IsIncognito(profile)) {
    static NSSet<NSString *> *session = [NSSet setWithArray:@[
      @"ac_site_settings_get", @"ac_site_settings_origins", @"ac_site_settings_set", @"ac_site_settings_reset",
      @"ac_site_data_clear", @"ac_zoom_list", @"ac_zoom_set"
    ]];
    static NSSet<NSString *> *changes = [NSSet setWithArray:@[
      @"ac_site_settings_set", @"ac_site_settings_reset", @"ac_site_data_clear", @"ac_zoom_set", @"ac_external_apps_remove",
      @"ac_browsing_data_clear"
    ]];
    if ([session containsObject:name] && EngineABI() >= 2) {
      NSData *bytes = [(args.length ? args : @"{}") dataUsingEncoding:NSUTF8StringEncoding];
      NSMutableDictionary *parsed = [[NSJSONSerialization JSONObjectWithData:bytes options:0 error:nil] mutableCopy];
      if (![parsed isKindOfClass:NSMutableDictionary.class]) return completion(JSON(@{@"error" : @"bad arguments"}));
      parsed[@"offTheRecord"] = @YES;
      args = JSON(parsed);
    } else if ([changes containsObject:name]) {
      return completion(JSON(@{@"error" : @"private profile"}));
    }
  }
  NSString *data = ardiacore_host::OriginalProfileName(profile);
  void (^done)(NSString *) = [completion copy];
  NSString *argsCopy = [args copy];
  ardiacore_host::WithProfile(data, ^(ArdiaCoreProfile *p) {
    if (!p || !ArdiaCoreHost.isStarted) return done(JSON(@{@"error" : @"profile not loaded"}));
    call(p.path.UTF8String, argsCopy.UTF8String, Replied, (__bridge_retained void *)done);
  });
}

+ (void)callWithSecret:(NSString *)name profile:(NSString *)profile args:(NSMutableData *)args completion:(void (^)(NSString *))completion {
  NSMutableData *secret = args;
  void (^wipe)(void) = ^{
    volatile unsigned char *bytes = (volatile unsigned char *)secret.mutableBytes;
    for (NSUInteger i = 0; i < secret.length; i++) bytes[i] = 0;
  };
  if (PasswordSyncSymbol(name)) {
    wipe();
    return completion(JSON(@{@"error" : @"native-only password sync endpoint"}));
  }
  auto call = (ac_engine_call_t)Symbol(name.UTF8String);
  const char *bytes = (const char *)secret.bytes;
  if (!call || ardiacore_host::IsIncognito(profile) || !secret.length || bytes[secret.length - 1] != 0) {
    wipe();
    return completion(JSON(@{@"error" : !call ? [NSString stringWithFormat:@"the engine has no %@", name]
                                     : ardiacore_host::IsIncognito(profile) ? @"private profile" : @"bad arguments"}));
  }
  void (^done)(NSString *) = [completion copy];
  ardiacore_host::WithProfile(profile ?: @"", ^(ArdiaCoreProfile *p) {
    if (!p || !ArdiaCoreHost.isStarted || ([p respondsToSelector:@selector(offTheRecord)] && p.offTheRecord)) {
      wipe();
      return done(JSON(@{@"error" : @"profile not loaded"}));
    }
    call(p.path.UTF8String, (const char *)secret.mutableBytes, Replied, (__bridge_retained void *)done);
    wipe();
  });
}

+ (void)setEventHandler:(void (^)(NSString *, NSString *))handler {
  gEventHandler = [handler copy];
  InstallSink();
}

+ (void)readPasswordsForSync:(NSString *)profile authorized:(BOOL (^)(void))authorized
                completion:(void (^)(NSArray<NSDictionary<NSString *, id> *> *))completion {
  if (![NSThread isMainThread]) {
    dispatch_async(dispatch_get_main_queue(), ^{ [self readPasswordsForSync:profile authorized:authorized completion:completion]; });
    return;
  }
  auto request = std::make_shared<PasswordSyncCall>();
  request->authorized = [authorized copy];
  request->completion = ^(BOOL success, NSArray<NSDictionary<NSString *, id> *> *rows) { completion(success ? rows : nil); };
  auto read = reinterpret_cast<ac_passwords_sync_read_t>(Symbol("ac_passwords_sync_read"));
  StartPasswordSync(profile, request, read, nullptr);
}

+ (void)compareAndSetPasswordForSync:(NSString *)profile args:(NSMutableData *)args authorized:(BOOL (^)(void))authorized
                        completion:(void (^)(BOOL))completion {
  if (![NSThread isMainThread]) {
    dispatch_async(dispatch_get_main_queue(), ^{ [self compareAndSetPasswordForSync:profile args:args authorized:authorized completion:completion]; });
    return;
  }
  auto request = std::make_shared<PasswordSyncCall>();
  request->authorized = [authorized copy];
  request->completion = ^(BOOL success, NSArray<NSDictionary<NSString *, id> *> *) { completion(success); };
  request->secret = args;
  const char *bytes = (const char *)args.bytes;
  if (!args.length || bytes[args.length - 1] != 0) return request->Finish(false);
  auto write = reinterpret_cast<ac_passwords_sync_compare_and_set_t>(Symbol("ac_passwords_sync_compare_and_set"));
  StartPasswordSync(profile, request, nullptr, write);
}

+ (void)forwardTopics:(NSArray<NSString *> *)topics {
  gForwardedTopics = [NSSet setWithArray:topics];
}

+ (void)observe:(NSString *)topic handler:(void (^)(NSDictionary<NSString *, id> *))handler {
  if (!Observers()[topic]) Observers()[topic] = [NSMutableArray array];
  [Observers()[topic] addObject:[handler copy]];
  InstallSink();
}

+ (BOOL)exports:(NSString *)name {
  if (PasswordSyncSymbol(name)) return NO;
  return Symbol(name.UTF8String) != nullptr;
}

@end
