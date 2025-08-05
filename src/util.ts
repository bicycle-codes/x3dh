import type { CryptographyKey } from './symmetric.js'

export type Keypair = {secretKey: CryptoKey, publicKey: CryptoKey};

/**
 * Concatenate some number of Uint8Array objects
 *
 * @param {Uint8Array[]} args
 * @returns {Uint8Array}
 */
export function concat (...args: Uint8Array[]): Uint8Array {
    let length = 0
    for (const arg of args) {
        length += arg.length
    }
    const output = new Uint8Array(length)
    length = 0
    for (const arg of args) {
        output.set(arg, length)
        length += arg.length
    }
    return output
}

/**
 * Generate an X25519 keypair.
 *
 * @returns {Keypair}
 */
export async function generateKeyPair ():Promise<Keypair> {
    const kp = await globalThis.crypto.subtle.generateKey(
        { name: 'X25519' },
        true, // extractable for public key export
        ['deriveKey']
    ) as CryptoKeyPair

    return {
        secretKey: kp.privateKey,
        publicKey: kp.publicKey
    }
}

/**
 * Generate a bundle of keypairs.
 *
 * @param {number} preKeyCount
 * @returns {Keypair[]}
 */
export async function generateBundle (preKeyCount: number = 100): Promise<Keypair[]> {
    const bundle:Keypair[] = []
    for (let i = 0; i < preKeyCount; i++) {
        bundle.push(await generateKeyPair())
    }
    return bundle
}

/**
 * SHA-256 hash of concatenated public keys for signing
 *
 * @param {CryptoKey[]} publicKeys
 * @returns {Uint8Array}
 */
export async function preHashPublicKeysForSigning (publicKeys: CryptoKey[]): Promise<Uint8Array> {
    // First, get the length as 4 bytes
    const pkLen = new Uint8Array(4)
    pkLen[0] = (publicKeys.length >>> 24) & 0xff
    pkLen[1] = (publicKeys.length >>> 16) & 0xff
    pkLen[2] = (publicKeys.length >>> 8) & 0xff
    pkLen[3] = publicKeys.length & 0xff

    // Get all public key raw bytes
    const keyBytes: Uint8Array[] = []
    keyBytes.push(pkLen)

    for (const pk of publicKeys) {
        const raw = await globalThis.crypto.subtle.exportKey('raw', pk)
        keyBytes.push(new Uint8Array(raw))
    }

    // Concatenate all bytes
    const combined = concat(...keyBytes)

    // Hash with SHA-256
    const hash = await globalThis.crypto.subtle.digest('SHA-256', combined)
    return new Uint8Array(hash)
}

/**
 * Signs a bundle using Ed25519. Returns the signature.
 *
 * @param {CryptoKey} signingKey Ed25519 private key
 * @param {CryptoKey[]} publicKeys X25519 public keys
 * @returns {Uint8Array}
 */
export async function signBundle (
    signingKey: CryptoKey,
    publicKeys: CryptoKey[]
): Promise<Uint8Array> {
    const hash = await preHashPublicKeysForSigning(publicKeys)
    const signature = await globalThis.crypto.subtle.sign(
        'Ed25519',
        signingKey,
        hash
    )
    return new Uint8Array(signature)
}

/**
 * Verify a bundle signature using Ed25519.
 *
 * @param {CryptoKey} verificationKey Ed25519 public key
 * @param {CryptoKey[]} publicKeys X25519 public keys
 * @param {Uint8Array} signature
 */
export async function verifyBundle (
    verificationKey: CryptoKey,
    publicKeys: CryptoKey[],
    signature: Uint8Array
): Promise<boolean> {
    try {
        const hash = await preHashPublicKeysForSigning(publicKeys)
        return await globalThis.crypto.subtle.verify(
            'Ed25519',
            verificationKey,
            signature,
            hash
        )
    } catch (error) {
        console.error('Bundle verification error:', error)
        return false
    }
}

/**
 * Wipe a cryptography key's internal buffer.
 * Note: This is a no-op for non-extractable keys in WebCrypto
 *
 * @param {CryptographyKey} key
 */
export async function wipe (key: CryptographyKey): Promise<void> {
    // For WebCrypto, non-extractable keys cannot be wiped manually
    // The garbage collector will handle this
    // We can try to zero the buffer if it's available
    try {
        const buffer = key.getBuffer()
        buffer.fill(0)
    } catch {
        // Key is not extractable, which is fine for security
    }
}

/**
 * Convert ArrayBuffer to hex string
 */
export function arrayBufferToHex (buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
}

/**
 * Convert hex string to ArrayBuffer
 */
export function hexToArrayBuffer (hex: string): ArrayBuffer {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
    }
    return bytes.buffer
}
