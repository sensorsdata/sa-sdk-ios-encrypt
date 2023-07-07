//
// UIApplication+SAPushClick.m
// SensorsAnalyticsSDK
//
// Created by 陈玉国 on 2021/1/7.
// Copyright © 2015-2022 Sensors Data Co., Ltd. All rights reserved.
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

#import "UIApplication+SAPushClick.h"
#import "SAApplicationDelegateProxy.h"
#import <objc/runtime.h>

static void *const kSALaunchOptions = (void *)&kSALaunchOptions;

@implementation UIApplication (PushClick)

- (void)sensorsdata_setDelegate:(id<UIApplicationDelegate>)delegate {
    //resolve optional selectors
    [SAApplicationDelegateProxy resolveOptionalSelectorsForDelegate:delegate];
    
    [self sensorsdata_setDelegate:delegate];
    
    if (!self.delegate) {
        return;
    }
    [SAApplicationDelegateProxy proxyDelegate:self.delegate selectors:[NSSet setWithArray:@[@"application:didReceiveLocalNotification:", @"application:didReceiveRemoteNotification:fetchCompletionHandler:"]]];
}

- (NSDictionary *)sensorsdata_launchOptions {
    return objc_getAssociatedObject(self, kSALaunchOptions);
}

- (void)setSensorsdata_launchOptions:(NSDictionary *)sensorsdata_launchOptions {
    objc_setAssociatedObject(self, kSALaunchOptions, sensorsdata_launchOptions, OBJC_ASSOCIATION_COPY);
}

@end
