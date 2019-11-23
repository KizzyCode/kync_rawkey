[![License BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Travis CI](https://travis-ci.org/KizzyCode/kync_rawkey.svg?branch=master)](https://travis-ci.org/KizzyCode/kync_rawkey)
[![AppVeyor CI](https://ci.appveyor.com/api/projects/status/github/KizzyCode/kync_rawkey?svg=true)](https://ci.appveyor.com/project/KizzyCode/kync-rawkey)


# Rawkey for KyNc
This crate provides a plugin for [KyNc](https://github.com/KizzyCode/kync/blob/master/Kync.asciidoc)
which derives a salted AEAD key from a **high entropy** user secret and seals the secret using the
derived AEAD key and a random nonce.


## Why Rawkey
Rawkey is useful if you have already have a (static) high-entropy secret that you want to use to
protect your secret. Since Rawkey does not perform any kind of password strengthening for the
user secret, it *MUST NOT* be used with normal passwords.


## Algorithm
1. Create a secure random 16 byte Blake2b-KDF `salt` and a secure random 12 byte ChachaPoly-IETF
   `nonce`
2. Derive a ChachaPoly-IETF `aead_key` by using the Blake2b-KDF with the `user_secret` as key and
   `salt` as salt
3. Seal `secret` using ChachaPoly-IETF with `aead_key` as key and `nonce` as nonce

Pseudocode:
```c
// Create a random salt and key
uint8_t salt[16], nonce[12];
secure_random(salt);
secure_random(nonce);

// Derive the AEAD key
uint8_t aead_key[32];
blake2b_kdf(aead_key, /* The secret to derive the key from: */ user_secret, salt);

// Seal the key
uint8_t capsule[sizeof(key) + 16];
chachapoly_ietf(capsule, /* Secret to protect: */ secret, aead_key, nonce); 
```


## Format
The capsule format is a simple concatenation of the salt, nonce, ciphertext and the authentication
tag (`||` denotes concatenation):
```text
salt[16] || nonce[12] || chacha_ciphertext* || poly_tag[16]
```


## Build
Prerequisites: A working [Rust toolchain](https://rust-lang.org) `>= 1.39` and a unix-like `make`
environment.

To build, test and install the library, use `make`, `make check` and `make install` respectively. To
add additional `cargo`-flags, use the `CARGO_FLAGS` environment variable for your `make` invocation.