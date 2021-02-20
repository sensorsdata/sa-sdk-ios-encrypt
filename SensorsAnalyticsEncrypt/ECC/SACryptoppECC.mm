//
// SACryptoppECC.m
// SensorsAnalyticsSDK
//
// Created by wenquan on 2020/12/11.
// Copyright © 2020 Sensors Data Co., Ltd. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#if ! __has_feature(objc_arc)
#error This file must be compiled with ARC. Either turn on ARC for the project or use -fobjc-arc flag on this file.
#endif

#import "SACryptoppECC.h"
#include <string>
#include <stdexcept>
#include <iostream>

#if defined(SENSORS_ANALYTICS_ENABLE_CUSTOM_CRYPTOPP)

#include "sa_eccrypto.h"
#include "sa_pubkey.h"
#include "sa_osrng.h"
#include "sa_filters.h"
#include "sa_base64.h"
#include "sa_hex.h"

namespace SA_ECC_CryptoPP = SA_CryptoPP;

#else

#include "eccrypto.h"
#include "pubkey.h"
#include "osrng.h"
#include "filters.h"
#include "base64.h"
#include "hex.h"

namespace SA_ECC_CryptoPP = CryptoPP;

#endif

using std::string;
using std::cout;
using std::endl;
using std::exception;
using SA_ECC_CryptoPP::ECP;    // Prime field
using SA_ECC_CryptoPP::ECIES;
using SA_ECC_CryptoPP::PublicKey;
using SA_ECC_CryptoPP::AutoSeededRandomPool;
using SA_ECC_CryptoPP::StringSink;
using SA_ECC_CryptoPP::StringSource;
using SA_ECC_CryptoPP::PK_EncryptorFilter;
using SA_ECC_CryptoPP::Base64Encoder;
using SA_ECC_CryptoPP::Base64Decoder;
using SA_ECC_CryptoPP::HexEncoder;
using SA_ECC_CryptoPP::HexDecoder;

@implementation SACryptoppECC

#pragma mark - Public Methods

+ (nullable NSString *)encrypt:(NSString *)message withPublicKey:(NSString *)publicKey {
    if (![self isValidString:message] || ![self isValidString:publicKey]) {
        return nil;
    }
    
    NSString *messageCopy = [message copy];
    NSString *publicKeyCopy = [publicKey copy];
    try {
        StringSource source(publicKeyCopy.UTF8String, true, new Base64Decoder);
        ECIES<ECP>::Encryptor encryptor;
        encryptor.AccessPublicKey().Load(source);
        
        string sPublicKey;
        HexEncoder pubEncoder(new StringSink(sPublicKey));
        encryptor.GetKey().DEREncode(pubEncoder);
        pubEncoder.MessageEnd();
        
        StringSource pubString(sPublicKey, true, new HexDecoder);
        ECIES<ECP>::Encryptor newEncryptor(pubString);
        
        AutoSeededRandomPool prng;
        const char *data = messageCopy.UTF8String;
        string encryptedMessage;
        StringSource (data, true, new PK_EncryptorFilter(prng, newEncryptor, new StringSink(encryptedMessage) ) );
        
        // 对加密后的数据进行 base64 编码
        string cipher;
        StringSource ( (Byte*)encryptedMessage.data(), encryptedMessage.size(), true, new Base64Encoder(new StringSink(cipher)));
        // 移除 base64 编码后字符串中的换行符
        cipher.erase(std::remove(cipher.begin(), cipher.end(), '\n'), cipher.end());
        // base64 后的字符串转换成 NSString 对象
        return [NSString stringWithUTF8String:(char *)cipher.data()];
    }  catch (const exception &e) {
        // Exception we know we can get
        cout << "SACryptoppECC encrypt with exception: " << e.what() << endl;
        return nil;
    } catch (...) {
        // Other unknwon expections
        cout << "SACryptoppECC encrypt with unknwon exception" << endl;
        return nil;
    }
}

#pragma mark – Private Methods

+ (BOOL)isValidString:(NSString *)string {
    return ([string isKindOfClass:[NSString class]] && ([string length] > 0));
}

@end
