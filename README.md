# x3dh
![tests](https://github.com/substrate-system/x3dh/actions/workflows/nodejs.yml/badge.svg?style=flat-square)
[![types](https://img.shields.io/npm/types/@substrate-system/x3dh?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/x3dh?cache-control=no-cache)](https://packagephobia.com/result?p=@substrate-system/x3dh)
[![License: ISC](https://img.shields.io/badge/License-ISC-brightgreen.svg?style=flat-square)](https://opensource.org/licenses/ISC)


TypeScript implementation of X3DH, as described in
***[Going Bark: A Furry's Guide to End-to-End Encryption](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/)***.

**[Support `soatok` on Patreon](https://patreon.com/soatok)**

The install size is kind of large because this package includes a pre-bundled [`sodium`](https://www.npmjs.com/package/sodium-plus).

## fork

This is a fork of [soatok/rawr-x3dh](https://github.com/soatok/rawr-x3dh).

## Contents

<!-- toc -->

- [What's This?](#whats-this)
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

## Installation

```sh
npm i -S @substrate-system/x3dh
```

If you're working server-side, you'll also want to install [sodium-native](https://www.npmjs.com/package/sodium-native),
so that [sodium-plus](https://www.npmjs.com/package/sodium-plus) will run faster.

If you're working in a browser or browser extension, don't install sodium-native.

## Usage

First, you'll want to import the X3DH class from our module.

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
