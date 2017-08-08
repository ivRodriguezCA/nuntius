
Pod::Spec.new do |s|
  s.name         = "nuntius"
  s.version      = "0.0.2"
  s.summary      = "Extended Triple Diffie-Hellman (X3DH) and Double Ratchet for iOS"
  s.description  = "Objc implementation of Extended Triple Diffie-Hellman (X3DH) and Double Ratchet protocols using libsodium for most of the crypto operations."
  s.homepage     = "https://github.com/ivRodriguezCA/nuntius"
  s.license      = "MIT"
  s.author             = "Ivan E. Rodriguez"
  s.social_media_url   = "http://twitter.com/ivRodriguezCA"
  s.source       = { :git => "https://github.com/ivRodriguezCA/nuntius.git", :tag => "#{s.version}" }
  s.source_files  = "nuntius/**/*.{h,m}"
  s.exclude_files = "nuntius/libsodium/**/*.{h,m}"
  s.platform     = :ios

  s.subspec 'libsodium' do |sodium|
    sodium.preserve_paths = 'nuntius/libsodium/include/**/*.{h,m}', 'nuntius/libsodium/LICENSE'
    sodium.vendored_libraries = 'nuntius/libsodium/lib/libsodium.a'
    sodium.libraries = 'sodium'
    sodium.xcconfig = { 'HEADER_SEARCH_PATHS' => "${PODS_ROOT}/#{s.name}/nuntius/libsodium/include/**" }
  end
end
