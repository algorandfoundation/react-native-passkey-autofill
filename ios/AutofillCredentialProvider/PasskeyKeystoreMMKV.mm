#import "PasskeyKeystoreMMKV.h"

#import <MMKVCore/MMKV.h>

@implementation PasskeyKeystoreMMKV

+ (nullable mmkv::MMKV *)keystoreForAppGroup:(NSString *)appGroup
                                       error:(NSError * _Nullable * _Nullable)error {
  NSURL *containerURL = [[NSFileManager defaultManager]
    containerURLForSecurityApplicationGroupIdentifier:appGroup];
  if (containerURL == nil) {
    if (error != nil) {
      *error = [NSError errorWithDomain:@"ReactNativePasskeyAutofill"
                                   code:2
                               userInfo:@{
                                 NSLocalizedDescriptionKey:
                                   [NSString stringWithFormat:@"App Group is not accessible: %@", appGroup]
                               }];
    }
    return nil;
  }

  std::string rootPath([containerURL.path UTF8String]);
  mmkv::MMKV::initializeMMKV(rootPath);
  return mmkv::MMKV::mmkvWithID("keystore", mmkv::MMKV_MULTI_PROCESS, nullptr, &rootPath);
}

+ (BOOL)setString:(NSString *)value
           forKey:(NSString *)key
         appGroup:(NSString *)appGroup
            error:(NSError * _Nullable * _Nullable)error {
  mmkv::MMKV *keystore = [self keystoreForAppGroup:appGroup error:error];
  if (keystore == nullptr) {
    return NO;
  }

  std::string cppValue([value UTF8String]);
  std::string cppKey([key UTF8String]);
  return keystore->set(cppValue, cppKey);
}

+ (nullable NSString *)stringForKey:(NSString *)key
                           appGroup:(NSString *)appGroup
                              error:(NSError * _Nullable * _Nullable)error {
  mmkv::MMKV *keystore = [self keystoreForAppGroup:appGroup error:error];
  if (keystore == nullptr) {
    return nil;
  }

  std::string result;
  std::string cppKey([key UTF8String]);
  if (!keystore->getString(cppKey, result)) {
    return nil;
  }
  return [NSString stringWithUTF8String:result.c_str()];
}

+ (NSArray<NSString *> *)allKeysForAppGroup:(NSString *)appGroup
                                      error:(NSError * _Nullable * _Nullable)error {
  mmkv::MMKV *keystore = [self keystoreForAppGroup:appGroup error:error];
  if (keystore == nullptr) {
    return @[];
  }

  std::vector<std::string> keys = keystore->allKeys();
  NSMutableArray<NSString *> *result = [NSMutableArray arrayWithCapacity:keys.size()];
  for (const auto &key : keys) {
    [result addObject:[NSString stringWithUTF8String:key.c_str()]];
  }
  return result;
}

+ (BOOL)removeValueForKey:(NSString *)key
                 appGroup:(NSString *)appGroup
                    error:(NSError * _Nullable * _Nullable)error {
  mmkv::MMKV *keystore = [self keystoreForAppGroup:appGroup error:error];
  if (keystore == nullptr) {
    return NO;
  }

  std::string cppKey([key UTF8String]);
  keystore->removeValueForKey(cppKey);
  return YES;
}

@end
