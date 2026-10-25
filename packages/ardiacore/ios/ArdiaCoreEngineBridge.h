#import <Foundation/Foundation.h>

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
+ (void)readPasswordsForSync:(NSString *)profile authorized:(BOOL (^)(void))authorized
                completion:(void (^)(NSArray<NSDictionary<NSString *, id> *> *_Nullable logins))completion
    NS_SWIFT_NAME(readPasswordsForSync(profile:authorized:completion:));
+ (void)compareAndSetPasswordForSync:(NSString *)profile args:(NSMutableData *)args authorized:(BOOL (^)(void))authorized
                        completion:(void (^)(BOOL success))completion
    NS_SWIFT_NAME(compareAndSetPasswordForSync(profile:args:authorized:completion:));
+ (void)setEventHandler:(nullable void (^)(NSString *topic, NSString *json))handler;
+ (void)forwardTopics:(NSArray<NSString *> *)topics;
+ (void)observe:(NSString *)topic handler:(void (^)(NSDictionary<NSString *, id> *payload))handler;
+ (BOOL)exports:(NSString *)name;
@end

NS_ASSUME_NONNULL_END
