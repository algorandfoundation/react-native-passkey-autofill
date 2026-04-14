require 'json'

package = JSON.parse(File.read(File.join(__dir__, '..', 'package.json')))

Pod::Spec.new do |s|
  s.name           = 'ReactNativePasskeyAutofill'
  s.version        = package['version']
  s.summary        = package['description']
  s.description    = package['description']
  s.license        = package['license']
  s.author         = package['author']
  s.homepage       = package['homepage']
  s.platforms      = {
    :ios => '15.1',
    :tvos => '15.1'
  }
  s.swift_version  = '5.9'
  s.source         = { git: 'https://github.com/algorandfoundation/react-native-passkey-autofill' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'
  s.dependency 'MMKV'
  # s.dependency 'deterministicP256-swift' # Added as Swift Package in app.plugin.js
  # s.dependency 'LiquidAuthSDK' # Added as Swift Package in app.plugin.js

  s.frameworks = 'AuthenticationServices', 'CryptoKit', 'LocalAuthentication'

  # Swift/Objective-C compatibility
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'OTHER_SWIFT_FLAGS' => '-Xcc -fmodule-maps',
  }

  s.source_files = "**/*.{h,m,mm,swift,hpp,cpp}"
  s.exclude_files = "Autofill/**/*", "Credentials/CredentialRepository+HD.swift"
end
