# SodiumBox

A pure Rust implementation of libsodium's sealed box encryption, compatible with libsodium/sodiumoxide but without any C dependencies.

## Overview

SodiumBox provides a standalone implementation of the sealed box functionality from libsodium (NaCl) using only pure Rust cryptographic libraries. It is designed to be a drop-in replacement for sodiumoxide's sealed box functionality.

The implementation uses modern, well-maintained Rust cryptographic libraries:

* `x25519-dalek` for Curve25519 key exchange
* `xsalsa20poly1305` for authenticated encryption
* `blake2` for key derivation
* `salsa20` for the HSalsa20 function

## Features

* Generate X25519 keypairs for sealed box operations
* Seal messages using a recipient's public key
* Open sealed boxes created by libsodium/sodiumoxide
* Pure Rust implementation with no C dependencies
* Comprehensive test vectors based on libsodium's test suite

## Usage

```rust
use sodiumbox::{generate_keypair, seal, open_sealed_box};

// Generate a new keypair
let (public_key, secret_key) = generate_keypair();

// Create a message to encrypt
let message = b"This is a secret message";

// Seal the message for the recipient
let sealed_box = seal(message, &public_key);

// Open a sealed box
let result = open_sealed_box(&sealed_box, &public_key, &secret_key);
match result {
    Ok(plaintext) => println!("Decrypted message: {:?}", plaintext),
    Err(_) => println!("Failed to decrypt"),
}
```

## License

This crate is licensed under either of:

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))
* MIT license ([LICENSE-MIT](LICENSE-MIT) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))

at your option.
