
Pod::Spec.new do |s|
  s.name         = "nuntius"
  s.version      = "0.0.8"
  s.summary      = "iOS Framework for end-to-end encrypted messages"
  s.description  = <<-DESC

  nuntius is an iOS framework that helps iOS developers integrate end-to-end encryption (e2ee) into their apps with simple APIs.
  It provides an objc implementation of the Extended Triple Diffie-Hellman (X3DH) and Double Ratchet protocols using libsodium for most of the crypto operations.
  nuntius provides Authenticated Encryption with Associated Data (AEAD) via AES-CBC-HMAC-256, it uses Apple's CommonCrypto framework for this operations, but in the future I'll move to libsodium-only crypto and use ChaCha20-Poly1305 instead.
  
  DESC
  s.homepage     = "https://github.com/ivRodriguezCA/nuntius"
  s.license      = "MIT"
  s.author             = "Ivan E. Rodriguez"
  s.social_media_url   = "http://twitter.com/ivRodriguezCA"
  s.source       = { :git => "https://github.com/ivRodriguezCA/nuntius.git", :branch => "master", :tag => "#{s.version}" }
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
