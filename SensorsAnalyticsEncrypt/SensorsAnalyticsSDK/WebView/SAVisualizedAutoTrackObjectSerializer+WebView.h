//
// SAVisualizedAutoTrackObjectSerializer+WebView.h
// SensorsAnalyticsSDK
//
// Created by 储强盛 on 2020/12/13.
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

// 如果集成了 WebView 模块，同时手动删除了可视化模块，增加预编译宏判断，防止编译报错问题
#if __has_include("SAVisualizedAutoTrackObjectSerializer.h")

#import "SAVisualizedAutoTrackObjectSerializer.h"

NS_ASSUME_NONNULL_BEGIN

@interface SAVisualizedAutoTrackObjectSerializer (WebView)

/// 判断当前对象是否为 UIWebView
- (BOOL)isWebViewWithObject:(NSObject *)obj;

@end

NS_ASSUME_NONNULL_END

#endif
