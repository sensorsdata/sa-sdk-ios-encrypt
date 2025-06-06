Pod::Spec.new do |s|
  s.name         = "SensorsAnalyticsEncrypt"
  s.version      = "0.0.9"
  s.summary      = "The official iOS Encryption Library of Sensors Analytics."
  s.homepage     = "https://www.sensorsdata.cn"
  s.source       = { :git => 'https://github.com/sensorsdata/sa-sdk-ios-encrypt.git', :tag => "v#{s.version}" } 
  s.license = { :type => "Boost Software License, Version 1.0" }
  s.author = { "chuqiangsheng" => "chuqiangsheng@sensorsdata.cn" }
  s.platform = :ios, "9.0"
  s.dependency "SensorsAnalyticsSDK", ">= 4.9.0"
  s.static_framework = true
  s.libraries = "c++"
  s.default_subspec = 'Default'
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

  s.subspec 'Base' do |base|
    base.source_files =  "SensorsAnalyticsEncrypt/ECC/*.{h,m,mm}", "SensorsAnalyticsEncrypt/OAEP/*.{h,m}", "SensorsAnalyticsEncrypt/SACryptopp/*.{h,m,mm,cpp}"
    base.public_header_files = "SensorsAnalyticsEncrypt/ECC/SACryptoppECC.h", "SensorsAnalyticsEncrypt/OAEP/SARSAOAEPEncryptor.h"
  end

  s.subspec 'Default' do |de|
    de.dependency 'SensorsAnalyticsEncrypt/Base'
    de.source_files =  "SensorsAnalyticsEncrypt/SM/*.{h,m}"
    de.public_header_files = "SensorsAnalyticsEncrypt/SM/SASMEncryptor.h"
    de.vendored_frameworks = ['SensorsAnalyticsEncrypt/SM/OpenSSL.xcframework']
  end

  s.subspec 'SAOpenSSL' do |sa|
    sa.dependency 'SensorsAnalyticsEncrypt/Base'
    sa.source_files =  "SensorsAnalyticsEncrypt/SM/*.{h,m}"
    sa.public_header_files = "SensorsAnalyticsEncrypt/SM/SASMEncryptor.h"
    sa.vendored_frameworks = ['SensorsAnalyticsEncrypt/SM/Sensors_OpenSSL.xcframework']
    sa.pod_target_xcconfig = {'GCC_PREPROCESSOR_DEFINITIONS' => 'SENSORS_ANALYTICS_ENABLE_SENSORS_OPENSSL=1'}
  end

end
