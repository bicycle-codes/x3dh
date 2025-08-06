import { test } from '@substrate-system/tapzero'
import type {
    Ed25519PublicKey,
    Ed25519SecretKey
} from 'sodium-plus'
import {
    SodiumPlus,
    X25519PublicKey,
    X25519SecretKey
} from 'sodium-plus'
import {
    concat,
    generateKeyPair,
    generateBundle,
    preHashPublicKeysForSigning,
    wipe,
    signBundle,
    verifyBundle
} from '../src/util.js'

test('concat', async (t) => {
    const A = new Uint8Array([0x02, 0x04, 0x08, 0x10])
    const B = new Uint8Array([0x03, 0x09, 0x1b, 0x51])
    const C = new Uint8Array([0x02, 0x04, 0x08, 0x10, 0x03, 0x09, 0x1b, 0x51])
    t.equal(C.join(','), concat(A, B).join(','))
})

test('generateKeypair', async t => {
    const kp = await generateKeyPair()
    t.ok(kp.secretKey instanceof X25519SecretKey, 'should return X25519 private key')
    t.ok(kp.publicKey instanceof X25519PublicKey, 'should return X25519 public key')
})

test('generateBundle', async t => {
    const bundle = await generateBundle(5)
    t.equal(bundle.length, 5, 'should have 5 things')
    for (let i = 0; i < 5; i++) {
        t.ok(bundle[i].secretKey instanceof X25519SecretKey)
        t.ok(bundle[i].publicKey instanceof X25519PublicKey)
    }
})

test('preHashPublicKeysForSigning', async t => {
    const sodium = await SodiumPlus.auto()
    const bundle = [
        X25519PublicKey.from('c52bb1d803b9721453b99a5d596e74d6d3ba48b1a07303244b0d76172bb55207'),
        X25519PublicKey.from('9abdd18b8ad24a6352bcca74bcd4156657d277348291cd8911660cc78836ad70'),
        X25519PublicKey.from('6cbeb8b66c686996ec65f59035445d65c2326781c44b9962d5bc8f6425c4e27b'),
        X25519PublicKey.from('e8d98550abea5c878a373bf5a06366d043b4c091b9a2e69bfffa69ae561bc877'),
        X25519PublicKey.from('19005e50996b96b4a9711a749a04a90fbd6a5781c4dc8d2a27219258354d5362'),
    ]

    const prehashed = await sodium.sodium_bin2hex(
        Buffer.from(await preHashPublicKeysForSigning(bundle))
    )

    t.equal(prehashed, 'fa59e2c4aaac08dd4186719ff9c436ca8cb0b1906ff6d230d68129cfba57d1a9')

    const prehash2 = await sodium.sodium_bin2hex(
        Buffer.from(await preHashPublicKeysForSigning(bundle.slice(1)))
    )

    t.equal(prehash2, 'c70d2b33b89971a621ab4c46e13819762f1dba63547f77500087f3107c1c248e')
})

test('signBundle / VerifyBundle', async t => {
    const sodium = await SodiumPlus.auto()
    const keypair = await sodium.crypto_sign_keypair()
    const sk:Ed25519SecretKey = await sodium.crypto_sign_secretkey(keypair)
    const pk:Ed25519PublicKey = await sodium.crypto_sign_publickey(keypair)
    const bundle = [
        X25519PublicKey.from('c52bb1d803b9721453b99a5d596e74d6d3ba48b1a07303244b0d76172bb55207'),
        X25519PublicKey.from('9abdd18b8ad24a6352bcca74bcd4156657d277348291cd8911660cc78836ad70'),
        X25519PublicKey.from('6cbeb8b66c686996ec65f59035445d65c2326781c44b9962d5bc8f6425c4e27b'),
        X25519PublicKey.from('e8d98550abea5c878a373bf5a06366d043b4c091b9a2e69bfffa69ae561bc877'),
        X25519PublicKey.from('19005e50996b96b4a9711a749a04a90fbd6a5781c4dc8d2a27219258354d5362'),
    ]

    const signature = await signBundle(sk, bundle)

    t.ok(
        (verifyBundle(pk, bundle, signature)),
        'should be valid a valid signature'
    )
    t.ok(!(await verifyBundle(pk, bundle.slice(1), signature)),
        'should not verify an invalid bundle')

    t.ok(!(await verifyBundle(pk, bundle.slice().reverse(), signature)),
        'should not valid an invalid bundle')
})

test('wipe', async t => {
    const sodium = await SodiumPlus.auto()
    const buf = await sodium.crypto_secretbox_keygen()
    t.notEqual(
        await sodium.sodium_bin2hex(buf.getBuffer()),
        '0000000000000000000000000000000000000000000000000000000000000000'
    )

    await wipe(buf)

    t.equal(
        await sodium.sodium_bin2hex(buf.getBuffer()),
        '0000000000000000000000000000000000000000000000000000000000000000',
        'should zero the buffer'
    )
})
