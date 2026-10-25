#import <Foundation/Foundation.h>
#import "ArdiaCoreServices.h"

NS_ASSUME_NONNULL_BEGIN

@interface ArdiaCoreEngineBridge : NSObject
+ (void)call:(NSString *)name
       profile:(NSString *)profile
          args:(nullable NSString *)args
    completion:(void (^)(NSString *json))completion NS_SWIFT_NAME(call(_:profile:args:completion:));
+ (void)callWithSecret:(NSString *)name
               profile:(NSString *)profile
                  args:(NSMutableData *)args
             completion:(void (^)(NSString *json))completion NS_SWIFT_NAME(callWithSecret(_:profile:args:completion:));
+ (void)readPasswordsForSync:(NSString *)profile request:(ArdiaCorePasswordSyncRequest *)request authorized:(BOOL (^)(void))authorized
                completion:(void (^)(NSArray<NSDictionary<NSString *, id> *> *_Nullable logins))completion
    NS_SWIFT_NAME(readPasswordsForSync(profile:request:authorized:completion:));
+ (void)compareAndSetPasswordForSync:(NSString *)profile args:(NSMutableData *)args request:(ArdiaCorePasswordSyncRequest *)request authorized:(BOOL (^)(void))authorized
                        completion:(void (^)(ArdiaCorePasswordSyncStatus status))completion
    NS_SWIFT_NAME(compareAndSetPasswordForSync(profile:args:request:authorized:completion:));
+ (void)setEventHandler:(nullable void (^)(NSString *topic, NSString *json))handler;
+ (void)forwardTopics:(NSArray<NSString *> *)topics;
+ (void)observe:(NSString *)topic handler:(void (^)(NSDictionary<NSString *, id> *payload))handler;
+ (BOOL)exports:(NSString *)name;
@end

NS_ASSUME_NONNULL_END
