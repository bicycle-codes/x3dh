import { exportPublicKey } from '@substrate-system/keys/ecc'
import { ed25519Verify } from '@substrate-system/keys/util'
import type { CryptographyKey } from './symmetric.js'

export type Keypair = {secretKey:CryptoKey, publicKey:CryptoKey};

/**
 * Concatenate some number of Uint8Array objects
 *
 * @param {Uint8Array[]} args
 * @returns {Uint8Array}
 */
export function concat (...args:Uint8Array[]):Uint8Array {
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
 * Generate an Ed25519 identity key pair for signing operations.
 * Since the keys module doesn't directly support Ed25519 key generation,
 * we'll fall back to using Web Crypto API directly.
 *
 * @returns {Promise<{ publicKey: CryptoKey, privateKey: CryptoKey }>}
 */
export async function generateEd25519IdentityKeyPair (): Promise<{
    publicKey: CryptoKey,
    privateKey: CryptoKey
}> {
    try {
        // Use Web Crypto API directly for Ed25519 since keys module uses ECDSA
        const keyPair = await globalThis.crypto.subtle.generateKey(
            { name: 'Ed25519' },
            true, // extractable for export/import operations
            ['sign', 'verify']
        ) as CryptoKeyPair

        // Validate the generated keys
        if (!keyPair.privateKey || !keyPair.publicKey) {
            throw new Error('Failed to generate Ed25519 key pair')
        }

        if (keyPair.privateKey.algorithm.name !== 'Ed25519' ||
            keyPair.publicKey.algorithm.name !== 'Ed25519') {
            throw new Error('Generated keys are not Ed25519')
        }

        return {
            publicKey: keyPair.publicKey,
            privateKey: keyPair.privateKey
        }
    } catch (error) {
        throw new Error(`Failed to generate Ed25519 identity key pair: ${error}`)
    }
}/**
 * Generate an X25519 key pair for key exchange operations.
 *
 * @returns {Promise<Keypair>}
 */
export async function generateKeyPair ():Promise<Keypair> {
    // Use Web Crypto API directly for X25519 to avoid issues with keys module
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
export async function generateBundle (preKeyCount:number = 100):Promise<Keypair[]> {
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
export async function preHashPublicKeysForSigning (
    publicKeys:CryptoKey[]
):Promise<Uint8Array> {
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
        try {
            const raw = await globalThis.crypto.subtle.exportKey('raw', pk)
            keyBytes.push(new Uint8Array(raw))
        } catch (_error) {
            // If raw export fails, try with exportPublicKey from keys module
            const raw = await exportPublicKey({ publicKey: pk } as CryptoKeyPair)
            keyBytes.push(new Uint8Array(raw))
        }
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
    signingKey:CryptoKey,
    publicKeys:CryptoKey[]
): Promise<Uint8Array> {
    try {
        // Validate the signing key
        if (!signingKey || typeof signingKey !== 'object') {
            throw new Error('Invalid signing key: must be a CryptoKey object')
        }

        // Accept Ed25519 algorithm names (we're using Web Crypto directly for Ed25519)
        const algorithmName = signingKey.algorithm?.name
        if (algorithmName !== 'Ed25519') {
            throw new Error(`Invalid signing key algorithm: expected Ed25519, got ${algorithmName}`)
        }

        if (signingKey.type !== 'private') {
            throw new Error(`Invalid signing key type: expected private, got ${signingKey.type}`)
        }

        const hash = await preHashPublicKeysForSigning(publicKeys)

        // Use Ed25519 signing directly
        const signature = await globalThis.crypto.subtle.sign('Ed25519', signingKey, hash)
        const signatureBytes = new Uint8Array(signature)

        return signatureBytes
    } catch (error) {
        throw new Error(`Failed to sign bundle: ${error}`)
    }
}

/**
 * Verify a bundle signature using Ed25519.
 *
 * @param {CryptoKey} verificationKey Ed25519 public key
 * @param {CryptoKey[]} publicKeys X25519 public keys
 * @param {Uint8Array} signature
 */
export async function verifyBundle (
    verificationKey:CryptoKey,
    publicKeys:CryptoKey[],
    signature:Uint8Array
):Promise<boolean> {
    try {
        const hash = await preHashPublicKeysForSigning(publicKeys)

        // Export the verification key to use with keys module
        const publicKeyBytes = await exportPublicKey({ publicKey: verificationKey } as CryptoKeyPair)

        // Use the keys module's Ed25519 verification to match MLS repo
        const isValid = await ed25519Verify({
            message: hash,
            publicKey: new Uint8Array(publicKeyBytes),
            signature
        })

        return isValid
    } catch (error) {
        console.error('Bundle verification error:', error)
        return false
    }
}/**
 * Wipe a cryptography key's internal buffer.
 * Note: This is a no-op for non-extractable keys in WebCrypto
 *
 * @param {CryptographyKey} key
 */
export async function wipe (key:CryptographyKey):Promise<void> {
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
export function arrayBufferToHex (buffer:ArrayBuffer|Uint8Array):string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
}

/**
 * Convert hex string to ArrayBuffer
 */
export function hexToArrayBuffer (hex:string):ArrayBuffer {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
    }
    return bytes.buffer
}
