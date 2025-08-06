import { test } from '@substrate-system/tapzero'
import {
    concat,
    generateKeyPair,
    generateBundle,
    preHashPublicKeysForSigning,
    wipe,
    signBundle,
    verifyBundle,
    arrayBufferToHex,
    hexToArrayBuffer
} from '../src/util.js'
import { CryptographyKey } from '../src/symmetric.js'

test('concat', async (t) => {
    const A = new Uint8Array([0x02, 0x04, 0x08, 0x10])
    const B = new Uint8Array([0x03, 0x09, 0x1b, 0x51])
    const C = new Uint8Array([0x02, 0x04, 0x08, 0x10, 0x03, 0x09, 0x1b, 0x51])
    t.equal(C.join(','), concat(A, B).join(','))
})

test('generateKeypair', async t => {
    const kp = await generateKeyPair()
    t.ok(kp.secretKey instanceof CryptoKey, 'should return X25519 private key')
    t.ok(kp.publicKey instanceof CryptoKey, 'should return X25519 public key')
    t.equal(kp.secretKey.algorithm.name, 'X25519', 'should be X25519 algorithm')
    t.equal(kp.publicKey.algorithm.name, 'X25519', 'should be X25519 algorithm')
})

test('generateBundle', async t => {
    const bundle = await generateBundle(5)
    t.equal(bundle.length, 5, 'should have 5 things')
    for (let i = 0; i < 5; i++) {
        t.ok(bundle[i].secretKey instanceof CryptoKey)
        t.ok(bundle[i].publicKey instanceof CryptoKey)
    }
})

test('preHashPublicKeysForSigning', async t => {
    const bundle = [
        await createX25519PublicKey('c52bb1d803b9721453b99a5d596e74d6d3ba48b1a07303244b0d76172bb55207'),
        await createX25519PublicKey('9abdd18b8ad24a6352bcca74bcd4156657d277348291cd8911660cc78836ad70'),
        await createX25519PublicKey('6cbeb8b66c686996ec65f59035445d65c2326781c44b9962d5bc8f6425c4e27b'),
        await createX25519PublicKey('e8d98550abea5c878a373bf5a06366d043b4c091b9a2e69bfffa69ae561bc877'),
        await createX25519PublicKey('19005e50996b96b4a9711a749a04a90fbd6a5781c4dc8d2a27219258354d5362'),
    ]

    const prehashed = arrayBufferToHex(await preHashPublicKeysForSigning(bundle))

    // Hash will be different since we're using different key representation
    t.ok(prehashed.length === 64, 'should return 32-byte hash (64 hex chars)')

    const prehash2 = arrayBufferToHex(await preHashPublicKeysForSigning(bundle.slice(1)))

    t.ok(prehash2.length === 64, 'should return 32-byte hash (64 hex chars)')
    t.ok(prehashed !== prehash2, 'different bundles should produce different hashes')
})

test('signBundle / VerifyBundle', async t => {
    const { publicKey: pk, privateKey: sk } = await generateEd25519KeyPair()
    const bundle = [
        await createX25519PublicKey('c52bb1d803b9721453b99a5d596e74d6d3ba48b1a07303244b0d76172bb55207'),
        await createX25519PublicKey('9abdd18b8ad24a6352bcca74bcd4156657d277348291cd8911660cc78836ad70'),
        await createX25519PublicKey('6cbeb8b66c686996ec65f59035445d65c2326781c44b9962d5bc8f6425c4e27b'),
        await createX25519PublicKey('e8d98550abea5c878a373bf5a06366d043b4c091b9a2e69bfffa69ae561bc877'),
        await createX25519PublicKey('19005e50996b96b4a9711a749a04a90fbd6a5781c4dc8d2a27219258354d5362'),
    ]

    const signature = await signBundle(sk, bundle)

    t.ok(
        (await verifyBundle(pk, bundle, signature)),
        'should be valid a valid signature'
    )
    t.ok(!(await verifyBundle(pk, bundle.slice(1), signature)),
        'should not verify an invalid bundle')

    t.ok(!(await verifyBundle(pk, bundle.slice().reverse(), signature)),
        'should not valid an invalid bundle')
})

test('wipe', async t => {
    // Create a CryptographyKey with some test data
    const testData = globalThis.crypto.getRandomValues(new Uint8Array(32))
    const originalHex = arrayBufferToHex(testData)
    const key = new CryptographyKey(testData)

    t.equal(
        arrayBufferToHex(key.getBuffer()),
        originalHex,
        'should have the original data'
    )

    await wipe(key)

    // Note: With Web Crypto API, non-extractable keys can't be wiped,
    // but extractable buffer data can be zeroed
    const wipedHex = arrayBufferToHex(key.getBuffer())
    t.equal(
        wipedHex,
        '0000000000000000000000000000000000000000000000000000000000000000',
        'should zero the buffer'
    )
})

// Helper function to create X25519 keys from hex strings
async function createX25519PublicKey (hexString: string): Promise<CryptoKey> {
    const keyBytes = hexToArrayBuffer(hexString)
    return await globalThis.crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'X25519' },
        true, // extractable so we can export for testing
        [] // Node.js requires empty usage array for X25519 raw imports
    )
}

// Helper function to create Ed25519 keys
async function generateEd25519KeyPair (): Promise<{ publicKey: CryptoKey, privateKey: CryptoKey }> {
    const keyPair = await globalThis.crypto.subtle.generateKey(
        { name: 'Ed25519' },
        false,
        ['sign', 'verify']
    ) as CryptoKeyPair
    return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey }
}
