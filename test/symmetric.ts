import { test } from '@substrate-system/tapzero'
import {
    CryptographyKey,
    encryptData,
    decryptData,
    deriveKeys
} from '../src/symmetric.js'
import { arrayBufferToHex } from '../src/util.js'

test('Key derivation', async t => {
    // Create a test input using Web Crypto API
    const messageBytes = new TextEncoder().encode('Dhole fursonas rule <3')
    const hash = await globalThis.crypto.subtle.digest('SHA-256', messageBytes)
    const testInput = new CryptographyKey(new Uint8Array(hash))
    const { encKey, commitment } = await deriveKeys(testInput, new Uint8Array(24))
    const test1: string = arrayBufferToHex(encKey.getBuffer())
    const test2: string = arrayBufferToHex(commitment)
    t.ok(!(test1 === test2), 'should return different outputs')

    // Test vectors for key derivation will be different with Web Crypto API
    // since we're using different hashing than sodium's crypto_generichash
    t.ok(test1.length === 64, 'encKey should be 32 bytes (64 hex chars)')
    t.ok(test2.length === 64, 'commitment should be 32 bytes (64 hex chars)')
})

test('Symmetric Encryption / Decryption', async t => {
    // Generate a test key using Web Crypto API
    const keyMaterial = globalThis.crypto.getRandomValues(new Uint8Array(32))
    const key = new CryptographyKey(keyMaterial)

    const plaintext = "Rawr x3 nuzzles how are you *pounces on you* you're so warm o3o *notices you have a bulge*"
    const encrypted = await encryptData(plaintext, key)
    t.ok(!(encrypted === plaintext), 'Encrypted text should not equal plaintext')
    t.equal(encrypted[0], 'v', 'First letter should be "v')
    const decrypted = await decryptData(encrypted, key)
    t.equal(decrypted.toString(), plaintext, 'should be able to decrypt the text')
})
