#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PasskeyKeystoreMMKV : NSObject

+ (BOOL)setString:(NSString *)value
           forKey:(NSString *)key
         appGroup:(NSString *)appGroup
            error:(NSError * _Nullable * _Nullable)error;

+ (nullable NSString *)stringForKey:(NSString *)key
                           appGroup:(NSString *)appGroup
                              error:(NSError * _Nullable * _Nullable)error;

+ (NSArray<NSString *> *)allKeysForAppGroup:(NSString *)appGroup
                                      error:(NSError * _Nullable * _Nullable)error;

+ (BOOL)removeValueForKey:(NSString *)key
                 appGroup:(NSString *)appGroup
                    error:(NSError * _Nullable * _Nullable)error;

@end

NS_ASSUME_NONNULL_END
