import { exportPublicKey } from '@substrate-system/keys/ecc'
import { generateEd25519IdentityKeyPair, wipe, arrayBufferToHex, hexToArrayBuffer } from './util.js'
import type { Keypair } from './util.js'
import { CryptographyKey } from './symmetric.js'

export type IdentityKeyPair = {
    identitySecret:CryptoKey,
    identityPublic:CryptoKey
};
export type PreKeyPair = {
    preKeySecret:CryptoKey,
    preKeyPublic:CryptoKey
};
type SessionKeys = {
    sending:CryptographyKey,
    receiving:CryptographyKey
};

export interface IdentityKeyManagerInterface {
    fetchAndWipeOneTimeSecretKey(pk:string):Promise<CryptoKey>;
    generateIdentityKeypair():Promise<IdentityKeyPair>;
    generatePreKeypair():Promise<PreKeyPair>;
    getIdentityKeypair():Promise<IdentityKeyPair>;
    getMyIdentityString():Promise<string>;
    getPreKeypair():Promise<PreKeyPair>;
    persistOneTimeKeys(bundle: Keypair[]):Promise<void>;
    setIdentityKeypair(identitySecret: CryptoKey, identityPublic?: CryptoKey):
        Promise<IdentityKeyManagerInterface>;
    setMyIdentityString(id: string):Promise<void>;
}

export interface SessionKeyManagerInterface {
    getAssocData(id:string):Promise<string>;
    getEncryptionKey(id:string, recipient?:boolean):Promise<CryptographyKey>;
    destroySessionKey(id:string):Promise<void>;
    listSessionIds():Promise<string[]>;
    setAssocData(id:string, assocData:string):Promise<void>;
    setSessionKey(id:string, key:CryptographyKey, recipient?:boolean):
        Promise<void>;
}

/**
 * This is a very basic example class for a session key manager.
 *
 * If you do not specify one, the X3DH library will use this.
 */
export class DefaultSessionKeyManager implements SessionKeyManagerInterface {
    assocData:Map<string, string>
    sessions:Map<string, SessionKeys>

    constructor () {
        this.sessions = new Map<string, SessionKeys>()
        this.assocData = new Map<string, string>()
    }

    async getAssocData (id:string):Promise<string> {
        return this.assocData.get(id) || ''
    }

    async listSessionIds ():Promise<string[]> {
        return Array.from(this.sessions.keys())
    }

    async setAssocData (id:string, assocData:string):Promise<void> {
        this.assocData.set(id, assocData)
    }

    /**
     * Override the session key for a given participation partner.
     *
     * Note that the actual sending/receiving keys will be derived from a
     * SHA-256 hash with domain separation (sending vs receiving) to ensure
     * that messages sent/received are encrypted under different keys.
     *
     * @param {string} id           Participant ID.
     * @param {CryptographyKey} key Incoming key.
     * @param {boolean} recipient   Are we the recipient? (Default: No.)
     */
    async setSessionKey (
        id:string,
        key:CryptographyKey,
        recipient?:boolean
    ):Promise<void> {
        this.sessions.set(id, {} as SessionKeys)

        // Create HMAC keys for domain separation
        const keyBuffer = key.getBuffer()

        if (recipient) {
            // We are the recipient: they send to us, we receive from them
            // Our sending key should match their receiving key
            const sendingKeyMaterial = await globalThis.crypto.subtle.digest(
                'SHA-256',
                new TextEncoder().encode(
                    'recipient_sending' + arrayBufferToHex(keyBuffer)
                )
            )
            this.sessions.get(id)!.sending = new CryptographyKey(
                new Uint8Array(sendingKeyMaterial)
            )

            // Our receiving key should match their sending key
            const receivingKeyMaterial = await globalThis.crypto.subtle.digest(
                'SHA-256',
                new TextEncoder().encode(
                    'sender_sending' + arrayBufferToHex(keyBuffer)
                )
            )
            this.sessions.get(id)!.receiving = new CryptographyKey(
                new Uint8Array(receivingKeyMaterial)
            )
        } else {
            // We are the sender: we send to them, they receive from us
            // Our receiving key should match their sending key
            const receivingKeyMaterial = await globalThis.crypto.subtle.digest(
                'SHA-256',
                new TextEncoder().encode('recipient_sending' +
                    arrayBufferToHex(keyBuffer))
            )
            this.sessions.get(id)!.receiving = new CryptographyKey(
                new Uint8Array(receivingKeyMaterial)
            )

            // Our sending key should match their receiving key
            const sendingKeyMaterial = await globalThis.crypto.subtle.digest(
                'SHA-256',
                new TextEncoder().encode('sender_sending' +
                    arrayBufferToHex(keyBuffer))
            )
            this.sessions.get(id)!.sending = new CryptographyKey(
                new Uint8Array(sendingKeyMaterial)
            )
        }
    }

    /**
     * Get the encryption key for a given message.
     *
     * !!!! IMPORTANT !!!!
     * This is a very rough proof-of-concept that doesn't
     * support out-of-order messages.
     *
     * Instead, it derives a 512-bit hash from the current key, then
     * updates the session key with the leftmost 256 bits of that hash,
     * and returns the rightmost 256 bits as the encryption key.
     *
     * You should design your session key management protocol more
     * appropriately for your use case.
     *
     * @param {string} id
     * @param {boolean} recipient
     * @returns {CryptographyKey}
     */
    async getEncryptionKey (id:string, recipient?:boolean):Promise<CryptographyKey> {
        const session = this.sessions.get(id)
        if (!session) {
            throw new Error('Key does not exist for client: ' + id)
        }
        if (recipient) {
            const keys = await this.symmetricRatchet(session.receiving)
            session.receiving = keys[0]
            return keys[1]
        } else {
            const keys = await this.symmetricRatchet(session.sending)
            session.sending = keys[0]
            return keys[1]
        }
    }

    /**
     * This is a very basic symmetric ratchet based on
     * SHA-256.
     *
     * The first 256 bits of the output are stored as the
     * future ratcheting key.
     *
     * The remaining bits are returned as the encryption key.
     *
     * @param {CryptographyKey} inKey
     * @returns {CryptographyKey[]}
     */
    async symmetricRatchet (inKey:CryptographyKey):Promise<CryptographyKey[]> {
        const keyBuffer = inKey.getBuffer()
        const fullhash = await globalThis.crypto.subtle.digest(
            'SHA-256',
            new TextEncoder().encode('Symmetric Ratchet' +
                arrayBufferToHex(keyBuffer))
        )

        const hashBytes = new Uint8Array(fullhash)
        return [
            new CryptographyKey(hashBytes.slice(0, 16)), // First 16 bytes for next key
            new CryptographyKey(hashBytes.slice(16, 32)), // Next 16 bytes for encryption
        ]
    }

    /**
     * Delete the session.
     *
     * @param {string} id
     */
    async destroySessionKey (id:string):Promise<void> {
        const session = this.sessions.get(id)
        if (!session) {
            return
        }
        if (session.sending) {
            await wipe(session.sending)
        }
        if (session.receiving) {
            await wipe(session.receiving)
        }
        this.sessions.delete(id)
    }
}

/**
 * This is an example implementation of an identity management class.
 *
 * You almost certainly want to build your own.
 */
export class DefaultIdentityKeyManager implements IdentityKeyManagerInterface {
    identitySecret?:CryptoKey
    identityPublic?:CryptoKey
    myIdentityString?:string
    preKey?:PreKeyPair
    oneTimeKeys:Map<string, CryptoKey>

    constructor (identitySecret?:CryptoKey, identityPublic?:CryptoKey) {
        if (identitySecret) {
            this.identitySecret = identitySecret
            if (identityPublic) {
                this.identityPublic = identityPublic
            }
        }

        this.oneTimeKeys = new Map<string, CryptoKey>()
    }

    /**
     * Search the one-time-keys pool for a given X25519 public key.
     * Return the corresponding secret key (and delete it from the pool).
     *
     * @param {string} pk
     * @returns {CryptoKey}
     */
    async fetchAndWipeOneTimeSecretKey (pk:string):Promise<CryptoKey> {
        const secretKey = this.oneTimeKeys.get(pk)
        if (!secretKey) {
            throw new Error('One-time key not found: ' + pk)
        }
        this.oneTimeKeys.delete(pk)
        return secretKey
    }

    /**
     * Generates an identity keypair (Ed25519).
     */
    async generateIdentityKeypair ():Promise<IdentityKeyPair> {
        const keypair = await generateEd25519IdentityKeyPair()

        return {
            identitySecret: keypair.privateKey,
            identityPublic: keypair.publicKey
        }
    }

    /**
     * Get (and generate, if it doesn't exist) the pre-key keypair.
     *
     * This only returns the X25519 keys. It doesn't include the Ed25519 signature.
     */
    async generatePreKeypair ():Promise<PreKeyPair> {
        const kp = await globalThis.crypto.subtle.generateKey(
            { name: 'X25519' },
            true, // extractable for public key export
            ['deriveKey']
        ) as CryptoKeyPair

        return {
            preKeySecret: kp.privateKey,
            preKeyPublic: kp.publicKey
        }
    }

    /**
     * Get the stored identity keypair (Ed25519).
     * If no identity keys are set, this will generate new ones.
     *
     * @returns {IdentityKeyPair}
     */
    async getIdentityKeypair ():Promise<IdentityKeyPair> {
        if (!this.identitySecret) {
            // Generate new identity keys if none exist
            const keypair = await this.generateIdentityKeypair()
            await this.setIdentityKeypair(keypair.identitySecret, keypair.identityPublic)
            return keypair
        }
        return {
            identitySecret: this.identitySecret,
            identityPublic: this.identityPublic!
        }
    }

    async getMyIdentityString ():Promise<string> {
        return this.myIdentityString!
    }

    /**
     * Get (and generate, if it doesn't exist) the pre-key keypair.
     *
     * This only returns the X25519 keys. It doesn't include the Ed25519 signature.
     */
    async getPreKeypair ():Promise<PreKeyPair> {
        if (!this.preKey) {
            this.preKey = await this.generatePreKeypair()
        }
        return this.preKey
    }

    /**
     * Load an Ed25519 keypair from stored data.
     * This method now expects the user to provide the stored data directly.
     *
     * @param {object} storedData - Object with 'sk' and 'pk' hex strings
     * @returns {IdentityKeyPair}
     */
    async loadIdentityKeypair (storedData?:{ sk: string, pk: string }):Promise<IdentityKeyPair> {
        if (!storedData) {
            throw new Error('No stored identity data provided. Please generate or provide identity keys.')
        }

        // Import the keys from stored hex data
        const secretKeyBuffer = hexToArrayBuffer(storedData.sk)
        const publicKeyBuffer = hexToArrayBuffer(storedData.pk)

        // For Ed25519, check if the data looks like raw format or structured format
        let secretKey: CryptoKey
        let publicKey: CryptoKey

        try {
            // Try raw format first (32 bytes for Ed25519)
            if (publicKeyBuffer.byteLength === 32) {
                publicKey = await globalThis.crypto.subtle.importKey(
                    'raw',
                    publicKeyBuffer,
                    { name: 'Ed25519' },
                    true,
                    ['verify']
                )
            } else {
                // Fall back to SPKI format
                publicKey = await globalThis.crypto.subtle.importKey(
                    'spki',
                    publicKeyBuffer,
                    { name: 'Ed25519' },
                    true,
                    ['verify']
                )
            }

            // Try raw format first (32 bytes for Ed25519)
            if (secretKeyBuffer.byteLength === 32) {
                secretKey = await globalThis.crypto.subtle.importKey(
                    'raw',
                    secretKeyBuffer,
                    { name: 'Ed25519' },
                    false,
                    ['sign']
                )
            } else {
                // Fall back to PKCS8 format
                secretKey = await globalThis.crypto.subtle.importKey(
                    'pkcs8',
                    secretKeyBuffer,
                    { name: 'Ed25519' },
                    false,
                    ['sign']
                )
            }
        } catch (error) {
            throw new Error(`Failed to import Ed25519 keys: ${error}`)
        }

        return { identitySecret: secretKey, identityPublic: publicKey }
    }

    /**
     * Store one-time keys in memory.
     *
     * @param {Keypair[]} bundle
     */
    async persistOneTimeKeys (bundle:Keypair[]):Promise<void> {
        for (const kp of bundle) {
            try {
                const publicKeyRaw = await globalThis.crypto.subtle.exportKey(
                    'raw',
                    kp.publicKey
                )
                const publicKeyHex = arrayBufferToHex(publicKeyRaw)
                this.oneTimeKeys.set(publicKeyHex, kp.secretKey)
            } catch (_error) {
                // Fallback to exportPublicKey from keys module
                const publicKeyRaw = await exportPublicKey({ publicKey: kp.publicKey } as CryptoKeyPair)
                const publicKeyHex = arrayBufferToHex(publicKeyRaw)
                this.oneTimeKeys.set(publicKeyHex, kp.secretKey)
            }
        }
    }

    /**
     * Export identity keypair data for storage.
     * Returns an object with hex-encoded keys that can be stored by the application.
     * Uses raw format for better browser compatibility.
     *
     * @param {CryptoKey} identitySecret
     * @returns {Promise<{sk: string, pk: string}>}
     */
    async exportIdentityKeypair (
        identitySecret:CryptoKey
    ):Promise<{ sk: string, pk: string }> {
        try {
            // Try to export as raw format first (better browser compatibility)
            const secretKeyBytes = await globalThis.crypto.subtle.exportKey(
                'raw',
                identitySecret
            )
            const publicKeyBytes = await globalThis.crypto.subtle.exportKey(
                'raw',
                this.identityPublic!
            )

            return {
                sk: arrayBufferToHex(secretKeyBytes),
                pk: arrayBufferToHex(publicKeyBytes),
            }
        } catch (_error) {
            // Fall back to structured formats if raw export fails
            try {
                const secretKeyBytes = await globalThis.crypto.subtle.exportKey(
                    'pkcs8',
                    identitySecret
                )
                const publicKeyBytes = await globalThis.crypto.subtle.exportKey(
                    'spki',
                    this.identityPublic!
                )

                return {
                    sk: arrayBufferToHex(secretKeyBytes),
                    pk: arrayBufferToHex(publicKeyBytes),
                }
            } catch (fallbackError) {
                throw new Error(`Failed to export Ed25519 keys: ${fallbackError}`)
            }
        }
    }

    /**
     * Sets the identity keys stored in this object.
     *
     * @param {CryptoKey} identitySecret
     * @param {CryptoKey} identityPublic
     */
    async setIdentityKeypair (
        identitySecret:CryptoKey,
        identityPublic?:CryptoKey
    ):Promise<this> {
        this.identitySecret = identitySecret
        this.identityPublic = identityPublic
        return this
    }

    async setMyIdentityString (id:string):Promise<void> {
        this.myIdentityString = id
    }
}
