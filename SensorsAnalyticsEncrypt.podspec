Pod::Spec.new do |s|
  s.name         = "SensorsAnalyticsEncrypt"
  s.version      = "0.0.3"
  s.summary      = "The official iOS Encrypt of Sensors Analytics."
  s.homepage     = "http://www.sensorsdata.cn"
  s.source       = { :git => 'https://github.com/sensorsdata/sa-sdk-ios-encrypt.git', :tag => "v#{s.version}" } 
  s.license = { :type => "Boost Software License, Version 1.0" }
  s.author = { "Quan Wen" => "wenquan@sensorsdata.cn" }
  s.platform = :ios, "8.0"
  s.source_files = "SensorsAnalyticsEncrypt/**/*.{h,m,mm,cpp}"
  s.public_header_files = "SensorsAnalyticsEncrypt/ECC/SACryptoppECC.h", "SensorsAnalyticsEncrypt/SM/SASMEncryptor.h"
  s.dependency "SensorsAnalyticsSDK", ">= 3.1.0"
  s.vendored_frameworks = ['SensorsAnalyticsEncrypt/SM/openssl.framework']
  s.static_framework = true
  s.libraries = "c++"
  s.user_target_xcconfig = { 
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386 arm64'
  }
  s.pod_target_xcconfig = { 
    "GCC_PREPROCESSOR_DEFINITIONS" => "SENSORS_ANALYTICS_ENABLE_CUSTOM_CRYPTOPP=1", 
    # -DCRYPTOPP_DISABLE_ASM=1 为了解决在模拟器上编译报错的问题
    # issue：https://github.com/weidai11/cryptopp/issues/933
    # CMake：https://www.cryptopp.com/wiki/CMake
    "OTHER_CPLUSPLUSFLAGS[sdk=iphonesimulator*]" => "$(OTHER_CFLAGS) -DCRYPTOPP_DISABLE_ASM=1", 
    "CLANG_CXX_LANGUAGE_STANDARD" => "gnu++14",
    "CLANG_CXX_LIBRARY" => "libc++",
    "GCC_WARN_INHIBIT_ALL_WARNINGS" => "YES",
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386 arm64'
  }

end
