Pod::Spec.new do |s|
  s.name         = "SensorsAnalyticsEncrypt"
  s.version      = "0.0.1"
  s.summary      = "The official iOS Encrypt of Sensors Analytics."
  s.homepage     = "http://www.sensorsdata.cn"
  s.source       = { :git => 'https://github.com/sensorsdata/sa-sdk-ios-encrypt.git', :tag => "v#{s.version}" } 
  s.license = { :type => "Boost Software License, Version 1.0" }
  s.author = { "Quan Wen" => "wenquan@sensorsdata.cn" }
  s.platform = :ios, "8.0"

  # Cryptopp 加密库的桥接文件
  s.subspec 'ECC' do |c|
    c.source_files = "SensorsAnalyticsEncrypt/ECC/**/*.{h,mm}"
    c.public_header_files = "SensorsAnalyticsEncrypt/ECC/SACryptoppECC.h"
  end

  # 预置的 Cryptopp 加密库
  s.subspec 'SACryptopp' do |f|
    f.source_files = "SensorsAnalyticsEncrypt/SACryptopp/**/*.{h,cpp}"
    # -DCRYPTOPP_DISABLE_ASM=1 为了解决在模拟器上编译报错的问题
    # issue：https://github.com/weidai11/cryptopp/issues/933
    # CMake：https://www.cryptopp.com/wiki/CMake
    f.pod_target_xcconfig = { 'GCC_PREPROCESSOR_DEFINITIONS' => 'SENSORS_ANALYTICS_ENABLE_CUSTOM_CRYPTOPP=1', 'OTHER_CPLUSPLUSFLAGS[sdk=iphonesimulator*]' => '-DCRYPTOPP_DISABLE_ASM=1', 'GCC_WARN_INHIBIT_ALL_WARNINGS' => 'YES'}
  end

end