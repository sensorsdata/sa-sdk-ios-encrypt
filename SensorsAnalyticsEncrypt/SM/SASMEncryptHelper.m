//
// SASMEncryptHelper.h
// SensorsAnalyticsSDK
//
// Created by pengyuanyang on 2021/07/20.
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

#import "SASMEncryptHelper.h"

#if defined(SENSORS_ANALYTICS_ENABLE_SENSORS_OPENSSL)
#import <sensors_openssl/sm2.h>
#import <sensors_openssl/bn.h>
#import <sensors_openssl/evp.h>
#import <sensors_openssl/asn1t.h>
#import <sensors_openssl/sm4.h>
#import <sensors_openssl/modes.h>

#else

#import <openssl/sm2.h>
#import <openssl/bn.h>
#import <openssl/evp.h>
#import <openssl/asn1t.h>
#import <openssl/sm4.h>
#import <openssl/modes.h>

#endif

//SM2 加密后密文为 ASN1 编码，此处定义 ASN1 编解码存储数据的结构体
#ifndef GMSM2_CIPHERTEXT_ST_1
#define GMSM2_CIPHERTEXT_ST_1

typedef struct SA_SM2_Ciphertext_st_1 SA_SM2_Ciphertext_1;
DECLARE_ASN1_FUNCTIONS(SA_SM2_Ciphertext_1)

struct SA_SM2_Ciphertext_st_1 {
    BIGNUM *C1x;
    BIGNUM *C1y;
    ASN1_OCTET_STRING *C3;
    ASN1_OCTET_STRING *C2;
};

ASN1_SEQUENCE(SA_SM2_Ciphertext_1) = {
    ASN1_SIMPLE(SA_SM2_Ciphertext_1, C1x, BIGNUM),
    ASN1_SIMPLE(SA_SM2_Ciphertext_1, C1y, BIGNUM),
    ASN1_SIMPLE(SA_SM2_Ciphertext_1, C3, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SA_SM2_Ciphertext_1, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SA_SM2_Ciphertext_1)

IMPLEMENT_ASN1_FUNCTIONS(SA_SM2_Ciphertext_1)

#endif /* GMSM2_CIPHERTEXT_ST_1 */

// 默认椭圆曲线类型 NID_sm2
static int kDefaultEllipticCurveType = NID_sm2;

@implementation SASMEncryptHelper

#pragma mark - SM2 加密
// 加密 NSData 格式明文
+ (nullable NSData *)encryptDataBySM2:(NSData *)plainData publicKey:(NSString *)publicKey {
    if (plainData.length == 0 || publicKey.length == 0) {
        return nil;
    }
    // SM2 加密
    NSData *cipherData = [SASMEncryptHelper encryptData:plainData hexPubKey:publicKey];

    // ASN1 解码, 服务端需要 ASN1 解码后数据流
    return [SASMEncryptHelper asn1Decrypt:cipherData];
}

+ (nullable NSData *)encryptData:(NSData *)plainData hexPubKey:(NSString *)hexPubKey {
    uint8_t *plain_bytes = (uint8_t *)plainData.bytes; // 明文
    const char *public_key = hexPubKey.UTF8String; // 公钥
    size_t msg_len = plainData.length; // 明文长度
    
    const EVP_MD *digest = EVP_sm3(); // 摘要算法
    EC_GROUP *group = EC_GROUP_new_by_curve_name(kDefaultEllipticCurveType); // 椭圆曲线
    EC_KEY *key = NULL; // 密钥对
    EC_POINT *pub_point = NULL; // 坐标
    uint8_t *ctext = NULL; // 密文
    NSData *cipherData = nil; // 密文
    do {
        key = EC_KEY_new();
        if (!EC_KEY_set_group(key, group)) {
             break;
        }

        pub_point = EC_POINT_new(group);
        EC_POINT_hex2point(group, public_key, pub_point, NULL);
        if (!EC_KEY_set_public_key(key, pub_point)) {
            break;
        }

        size_t ctext_len = 0;
        if (!sm2_ciphertext_size(key, digest, msg_len, &ctext_len)) {
            break;
        }

        ctext = (uint8_t *)OPENSSL_zalloc(ctext_len);
        if (!sm2_encrypt(key, digest, plain_bytes, msg_len, ctext, &ctext_len)) {
            break;
        }
        cipherData = [NSData dataWithBytes:ctext length:ctext_len];
    } while (NO);
    
    if (group != NULL) EC_GROUP_free(group);
    EC_POINT_free(pub_point);
    OPENSSL_free(ctext);
    EC_KEY_free(key);

    return cipherData;
}

+ (nullable NSData *)asn1Decrypt:(NSData *)asn1Data {
    if (asn1Data.length == 0) {
        return nil;
    }

    long asn1_ctext_len = asn1Data.length; // ASN1格式密文原文长度
    const uint8_t *asn1_ctext = (uint8_t *)asn1Data.bytes;

    const EVP_MD *digest = EVP_sm3(); // 摘要算法
    struct SA_SM2_Ciphertext_st_1 *sm2_st = NULL;
    sm2_st = d2i_SA_SM2_Ciphertext_1(NULL, &asn1_ctext, asn1_ctext_len);
    // C1
    char *c1x_text = BN_bn2hex(sm2_st->C1x);
    char *c1y_text = BN_bn2hex(sm2_st->C1y);
    NSString *c1xStr = [NSString stringWithCString:c1x_text encoding:NSUTF8StringEncoding];
    NSString *c1yStr = [NSString stringWithCString:c1y_text encoding:NSUTF8StringEncoding];
    // 如果转 Hex 不足 64 位前面补 0
    NSString *paddingC1X = [SASMEncryptHelper bigNumberToHexPadding:c1xStr];
    NSString *paddingC1Y = [SASMEncryptHelper bigNumberToHexPadding:c1yStr];
    NSString *paddingHex = [NSString stringWithFormat:@"%@%@", paddingC1X, paddingC1Y];
    NSData *c1Data = [SASMEncryptHelper hexToData:paddingHex];
    // C3
    const int c3_len = EVP_MD_size(digest);
    NSData *c3Data = [NSData dataWithBytes:sm2_st->C3->data length:c3_len];
    // C2
    int c2_len = sm2_st->C2->length;
    NSData *c2Data = [NSData dataWithBytes:sm2_st->C2->data length:c2_len];

    OPENSSL_free(c1x_text);
    OPENSSL_free(c1y_text);
    SA_SM2_Ciphertext_1_free(sm2_st);

    if (!c1Data || !c3Data || !c2Data) {
        return nil;
    }

    NSMutableData *c1c3c2Data = [NSMutableData dataWithData:c1Data];
    [c1c3c2Data appendData:c3Data];
    [c1c3c2Data appendData:c2Data];
    return c1c3c2Data;
}

/// BIGNUM 转 Hex 时，不足 64 位前面补 0
/// @param orginHex 原 Hex 字符串
+ (NSString *)bigNumberToHexPadding:(NSString *)orginHex {
    if (orginHex.length == 0 || orginHex.length >= 64) {
        return orginHex;
    }
    static NSString *paddingZero = @"0000000000000000000000000000000000000000000000000000000000000000";
    NSString *padding = [paddingZero substringToIndex:(64 - orginHex.length)];
    return [NSString stringWithFormat:@"%@%@", padding, orginHex];
}

#pragma mark - SM4 加密
+ (nullable NSData *)createSM4Key {
    NSInteger len = SM4_BLOCK_SIZE;
    NSMutableString *result = [[NSMutableString alloc] initWithCapacity:(len * 2)];

    uint8_t bytes[len];
    int status = SecRandomCopyBytes(kSecRandomDefault, (sizeof bytes)/(sizeof bytes[0]), &bytes);
    if (status == errSecSuccess) {
        for (int i = 0; i < (sizeof bytes)/(sizeof bytes[0]); i++) {
            NSString *hexStr = [NSString stringWithFormat:@"%X",bytes[i]&0xff];///16进制数
            if (hexStr.length == 1) {
                [result appendFormat:@"0%@", hexStr];
            }else{
                [result appendString:hexStr];
            }
        }
        return [SASMEncryptHelper hexToData:result];
    }
    // 容错，若 SecRandomCopyBytes 失败
    NSString *keyStr = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < len; i++){
        uint32_t index = arc4random_uniform((uint32_t)keyStr.length);
        NSString *subChar = [keyStr substringWithRange:NSMakeRange(index, 1)];
        [result appendString:subChar];
    }
    return [result dataUsingEncoding:NSUTF8StringEncoding];
}

+ (nullable NSData *)encryptDataBySM4:(NSData *)plainData symmetricKey:(NSData *)symmetricKey symmetricIv:(NSData *)symmetricIv {
    if (plainData.length == 0 || symmetricKey.length != SM4_BLOCK_SIZE || symmetricIv.length != SM4_BLOCK_SIZE) {
        return nil;
    }
    // 明文
    uint8_t *p_obj = (uint8_t *)plainData.bytes;
    size_t p_obj_len = plainData.length;

    int pad_len = SM4_BLOCK_SIZE - p_obj_len % SM4_BLOCK_SIZE;
    size_t result_len = p_obj_len + pad_len;
    // PKCS7 填充
    uint8_t p_text[result_len];
    memcpy(p_text, p_obj, p_obj_len);
    for (int i = 0; i < pad_len; i++) {
        p_text[p_obj_len + i] = pad_len;
    }
    uint8_t *result = (uint8_t *)OPENSSL_zalloc((int)(result_len + 1));
    // 密钥 key Hex 转 uint8_t
    NSData *kData = symmetricKey;

    uint8_t *k_text = (uint8_t *)kData.bytes;
    SM4_KEY sm4Key;
    SM4_set_key(k_text, &sm4Key);
    // 初始化向量
    NSData *ivecData = symmetricIv;

    uint8_t *iv_text = (uint8_t *)ivecData.bytes;
    uint8_t ivec_block[SM4_BLOCK_SIZE] = {0};
    if (iv_text != NULL) {
        memcpy(ivec_block, iv_text, SM4_BLOCK_SIZE);
    }
    // cbc 加密
    CRYPTO_cbc128_encrypt(p_text, result, result_len, &sm4Key, ivec_block,
                          (block128_f)SM4_encrypt);

    NSData *cipherData = [NSData dataWithBytes:result length:result_len];

    OPENSSL_free(result);
    return cipherData;
}

#pragma mark - HEX
+ (nullable NSData *)hexToData:(NSString *)hexStr {
    if (!hexStr || hexStr.length < 2) {
        return nil;
    }

    long buf_len = 0;
    uint8_t *tmp_buf = OPENSSL_hexstr2buf(hexStr.UTF8String, &buf_len);
    NSData *tmpData = [NSData dataWithBytes:tmp_buf length:buf_len];
    OPENSSL_free(tmp_buf);

    return tmpData;
}

@end
