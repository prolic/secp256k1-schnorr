[![Build Status](https://app.travis-ci.com/prolic/secp256k1-schnorr.svg?branch=master)](https://app.travis-ci.com/prolic/secp256k1-schnorr)

# Haskell bindings for secp256k1

- forked from [haskoin/secp256k1-haskell](https://github.com/haskoin/secp256k1-haskell)
- supports schnorr signatures

This project contains Haskell bindings for the
[secp256k1](https://github.com/bitcoin-core/secp256k1) library.

## Building

### Secp256k1 dependency

```bash
git clone https://github.com/bitcoin-core/secp256k1
cd secp256k1
./autogen.sh
./configure --enable-module-schnorrsig --enable-module-extrakeys --enable-module-ecdh --enable-experimental
make
sudo make install
```

### This library

```bash
stack build
LD_LIBRARY_PATH=/usr/local/lib stack test
```
