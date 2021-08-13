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

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SASMEncryptHelper : NSObject

#pragma mark - SM2
/// SM2 加密，OpenSSL 加密密文做了 ASN1 编码
/// @param plainData 明文内容
/// @param publicKey 04 开头的公钥（ Hex 编码格式）
/// @return 返回加密内容已做 ASN1 解码
+ (nullable NSData *)encryptDataBySM2:(NSData *)plainData publicKey:(NSString *)publicKey;

#pragma mark - SM4

///生成 16 位随机字节流，可作为 SM4 对称秘钥和 SM4 对称向量使用
/// @return 16 位字节流
+ (nullable NSData *)createSM4Key;

/// SM4 加密，使用 CBC 模式
/// @param plainData  明文（NSData 类型）
/// @param symmetricKey  对称秘钥
/// @param symmetricIv  对称向量
/// @return 加密后数据流
+ (nullable NSData *)encryptDataBySM4:(NSData *)plainData symmetricKey:(NSData *)symmetricKey symmetricIv:(NSData *)symmetricIv;

@end

NS_ASSUME_NONNULL_END
