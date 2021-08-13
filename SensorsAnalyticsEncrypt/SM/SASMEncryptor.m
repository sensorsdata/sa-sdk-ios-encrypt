//
// SASMEncryptor.m
// SensorsAnalyticsSDK
//
// Created by 彭远洋 on 2021/7/21.
// Copyright © 2021 Sensors Data Co., Ltd. All rights reserved.
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

#import "SASMEncryptor.h"
#import "SASMEncryptHelper.h"

static const

@interface SASMEncryptor ()

/// SM4 对称加密 秘钥值
@property (nonatomic, strong) NSData *symmetricKey;

/// SM4 对称加密秘钥向量
@property (nonatomic, strong) NSData *symmetricIv;

@end

@implementation SASMEncryptor

- (instancetype)init {
    self = [super init];
    if (self) {
        _symmetricKey = [SASMEncryptHelper createSM4Key];
        _symmetricIv = [SASMEncryptHelper createSM4Key];
    }
    return self;
}

#pragma mark  - SAEncryptProtocol Methods
/// 返回对称加密的类型
- (NSString *)symmetricEncryptType {
    return @"SM4";
}

/// 返回非对称加密的类型
- (NSString *)asymmetricEncryptType {
    return @"SM2";
}

/// 返回加密后的事件数据
/// @param event gzip 压缩后的事件数据
- (NSString *)encryptEvent:(NSData *)event {
    // SM4 算法加密事件数据
    NSData *cipherData = [SASMEncryptHelper encryptDataBySM4:event symmetricKey:self.symmetricKey symmetricIv:self.symmetricIv];

    // SM4 加密失败
    if (!cipherData) {
        return nil;
    }

    // 拼接 iv 向量在事件加密数据最前面，服务端按长度截取
    NSMutableData *result = [NSMutableData dataWithData:self.symmetricIv];
    [result appendData:cipherData];

    // Base64 编码
    NSData *base64EncodeData = [result base64EncodedDataWithOptions:NSDataBase64EncodingEndLineWithCarriageReturn];

    // 数据流转换为字符串
    return [[NSString alloc] initWithData:base64EncodeData encoding:NSUTF8StringEncoding];
}

/// 返回加密后的对称密钥数据
/// @param publicKey 非对称加密算法的公钥，用于加密对称密钥
- (NSString *)encryptSymmetricKeyWithPublicKey:(NSString *)publicKey {
    // SM2 加密对称秘钥
    NSData *cipherData = [SASMEncryptHelper encryptDataBySM2:self.symmetricKey publicKey:publicKey];

    // Base64 编码
    NSData *base64EncodeData = [cipherData base64EncodedDataWithOptions:NSDataBase64EncodingEndLineWithCarriageReturn];

    // 数据流转换为字符串
    return [[NSString alloc] initWithData:base64EncodeData encoding:NSUTF8StringEncoding];
}

@end
