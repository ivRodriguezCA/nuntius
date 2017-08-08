# [alpha] nuntius
nuntius is an iOS framework that helps iOS developers integrate [end-to-end encryption (e2ee)](https://en.wikipedia.org/wiki/End-to-end_encryption) into their apps with simple APIs. It provides an objc implementation of the Extended Triple Diffie-Hellman (X3DH) and Double Ratchet protocols using [libsodium](https://github.com/jedisct1/libsodium) for most of the crypto operations. nuntius provides Authenticated Encryption with Associated Data (AEAD) via AES-CBC-HMAC-256, it uses Apple's CommonCrypto framework for this operations, but in the future I'll move to libsodium-only crypto and use [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/Poly1305) instead.

## Extended Triple Diffie-Hellman (X3DH)
As described [here](https://whispersystems.org/docs/specifications/x3dh/), X3DH is a key agreement protocol that establishes a shared *session* key between two parties that mutually authenticate each other based on public keys. `nuntius` uses:
- [Curve25519](https://cr.yp.to/ecdh.html) for elliptic curve public key cryptography [(ECDH)](https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman)
- [Ed25519](https://ed25519.cr.yp.to/) for public-key signatures
- [SHA256](https://en.wikipedia.org/wiki/SHA-2) hashing algorithm
- [BLAKE2b](https://blake2.net/) as [KDF](https://en.wikipedia.org/wiki/Key_derivation_function) for key derivation

## Double Ratchet
As described [here](https://whispersystems.org/docs/specifications/doubleratchet/), the Double Ratchet protocol is used after a shared *session* key is established between two parties (for example with X3DH) to send and receive encrypted messages. It provides [forward secrecy (FS)](https://en.wikipedia.org/wiki/Forward_secrecy) by deriving new encryption keys after every Double Ratchet message, meaning that if an encryption key is compromised, it cannot be used to decrypt passed messages. It provides a symmetric encryption key ratachet and a Diffie-Hellman public key encryption ratachet, this is why is called Double Ratchet. `nuntius` uses:
- [Curve25519](https://cr.yp.to/ecdh.html) for elliptic curve public key cryptography [(ECDH)](https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman)
- [BLAKE2b](https://blake2.net/) as [KDF](https://en.wikipedia.org/wiki/Key_derivation_function) for key derivation
- [AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) in [CBC mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) with PKCS#7 padding for symmectric encryption
- [HMAC-256](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code) for Authenticated Encryption

## Importing

### Cocoapods
```sh
pod "nuntius"
```
Then just import the nuntius header
```Objc
#import <nuntius/nuntius.h>
```
## Usage
TODO


## Contributions
Do you want to contribute? awesome! I'd love to see some PRs opened here.

## TODO
- [] Add examples
- [] Add Documentation
- [] Add project to Travis CI

## Disclaimer
- The Extended Triple Diffie-Hellman and Double Ratchet protocols' implementations where developed from scratch and do not share any source code with existing libraries.
- This library has no relation and is not backed nor supported by the authors of the X3DH and Double Ratchet protocols.