#
# App Fortress iOS Plugin
#
Pod::Spec.new do |s|
  s.name             = 'app_fortress'
  s.version          = '1.0.0'
  s.summary          = 'Production-grade multi-layer app security for Flutter'
  s.description      = <<-DESC
App Fortress provides comprehensive security features including App Attest,
jailbreak detection, anti-debugging, hooking detection, and more.
                       DESC
  s.homepage         = 'https://github.com/girija870/app_fortress'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Girija' => 'girija870@users.noreply.github.com' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform         = :ios, '13.0'
  s.swift_version    = '5.0'

  # Privacy manifest (required for App Store submission since Spring 2024)
  s.resource_bundles = { 'app_fortress_privacy' => ['PrivacyInfo.xcprivacy'] }

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
end
