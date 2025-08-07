# x3dh
[![tests](https://img.shields.io/github/actions/workflow/status/substrate-system/x3dh/nodejs.yml?style=flat-square)](https://github.com/substrate-system/x3dh/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/x3dh?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/x3dh?cache-control=no-cache)](https://packagephobia.com/result?p=@substrate-system/x3dh)
[![GZip size](https://flat.badgen.net/bundlephobia/minzip/@substrate-system/x3dh)](https://bundlephobia.com/package/@substrate-system/x3dh)
[![License: ISC](https://img.shields.io/badge/License-ISC-brightgreen.svg?style=flat-square)](https://opensource.org/licenses/ISC)


TypeScript implementation of X3DH, as described in
***[Going Bark: A Furry's Guide to End-to-End Encryption](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/)***.

## fork

This is a fork of [soatok/rawr-x3dh](https://github.com/soatok/rawr-x3dh).
Thanks `@soatok` for working in public.

## Contents

<!-- toc -->

- [What's This?](#whats-this)
- [Platform Independence](#platform-independence)
  * [Improved Browser Compatibility (v0.4.0)](#improved-browser-compatibility-v040)
  * [Key Storage](#key-storage)
- [Installation](#installation)
- [Usage](#usage)
- [Should I Use This?](#should-i-use-this)

<!-- tocstop -->

## What's This?

This library implements the [Extended Triple Diffie-Hellman](https://signal.org/docs/specifications/x3dh/)
key exchange, with a few minor tweaks:

1. Identity keys are Ed25519 public keys, not X25519 public keys.
   [See this for an explanation](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/#why-ed25519-keys-x3dh).
2. Encryption/decryption and KDF implementations are pluggable
   (assuming you implement the interface I provide), so you aren't
   married to HKDF or a particular cipher. (Although I recommend hard-coding
   it to your application!)

## Platform Independence

This library is designed to work across different JavaScript environments:

- **Browser environments** - Works with the Web Crypto API and handles Ed25519 key format differences
- **Node.js** - Uses `@substrate-system/one-webcrypto` for compatibility  
- **Web Workers** - Full support for background processing
- **React Native** - Compatible with React Native's crypto implementations

### Improved Browser Compatibility (v0.4.0)

The library now handles Ed25519 key format differences between browsers and Node.js automatically:
- Automatically detects and supports both raw (32-byte) and structured (SPKI/PKCS8) Ed25519 key formats
- Exports keys in the format most compatible with the current environment
- Fallback mechanisms ensure keys work across different Web Crypto API implementations

### Key Storage

The `DefaultIdentityKeyManager` no longer depends on Node.js filesystem operations. Instead:
- Use `exportIdentityKeypair()` to get key data for storage
- Use `loadIdentityKeypair(storedData)` to restore keys from your preferred storage method
- Implement your own storage strategy (localStorage, AsyncStorage, database, etc.)

## Installation

```sh
npm i -S @substrate-system/x3dh
```

## Usage

First, import the X3DH class from the module.

```ts
import { X3DH } from '@substrate-system/x3dh'

const x3dh = new X3DH()
```

Note: You can pass some classes to the constructor to replace the
algorithm implementations.

```ts
import { X3DH } from '@substrate-system/x3dh'

const x3dh = new X3DH(
    sessionKeyManager,  /* SessionKeyManagerInterface */
    identityKeyManager,  /* IdentityKeyManagerInterface */
    symmetricEncryptionHandler,  /* SymmetricEncryptionInterface */
    keyDerivationFunction  /* KeyDerivationFunction */
)
```

Once your X3DH object is instantiated, you will be able to initialize handshakes
either as a sender or as a recipient. Then you will be able to encrypt additional
messages on either side.

```ts
const firstEncrypted = await x3dh.initSend(
    'recipient@server2',
    serverApiCallFunc,
    firstMessage
); 
```

The `serverApiCallFunc` parameter should be a function that sends a request to
the server to obtain the identity key, signed pre-key, and optional one-time
key for the handshake.

See the definition of the `InitClientFunction` type in
[src/index.ts](https://github.com/substrate-system/x3dh/blob/ad4de8bf76fc5e72a3c292a06a1a281640cf4d4a/src/index.ts#L111).

Once this has completed, you can call `encryptNext()` multiple times to append
messages to send.

```ts
const nextEncrypted = await x3dh.encryptNext(
    'recipient@server2',
    'This is a follow-up message UwU'
);
```

On the other side, your communication partner will use the following feature.

```ts
const [sender, firstMessage] = await x3dh.initRecv(senderInfo);
const nextMessage = await x3dh.decryptNext(sender, nextEncrypted);
```

Note: `initRecv()` will always return the sender identity (a string) and the
message (a `Buffer` that can be converted to a string). The sender identity
should be usable for `decryptNext()` calls.

However, that doesn't mean it's trustworthy! This library only implements
the X3DH pattern. It doesn't implement the 
[Gossamer integration](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/#identity-key-management).

## Should I Use This?

Don't use it in production until version 1.0.0 has been tagged.
The API can break at any moment until that happens (especially if
I decide I hate the default key management classes I wrote).

However, feel free to test and play with it.
