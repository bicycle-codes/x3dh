/**
 * Rawr-X3DH -- eXtended 3-way Diffie-Hellman
 *
 * Specification by Open Whisper Systems <https://signal.org/docs/specifications/x3dh/>
 * Powered by Libsodium <https://libsodium.gitbook.io/doc/>
 *
 * Implemented by Soatok Dreamseeker <https://soatok.blog>
 *
 * ................................:.................
 * .............................-+yd-................
 * ............/+:-.....+/oys++://:m:................
 * --........../y///oyssyyyyhddh+-:y/................
 * --------.....o--+syyso/syyyhho:--+..........:-....
 * ----------.....:/ssss+ooyoosyo//yo.--------oy:....
 * --------------:+//+//++:`-/o-syyy/-------+yo------
 * --------------:oy++:s. ++:+: `ys/------/ss:-------
 * ---------------:+++syh--/++++oss//---:oy+---------
 * ----------------:syyhhysosssyyyyhso/+yo:----------
 * ----------------::shddyyhyyyyshdhyyyy/------------
 * ----------------:shhhyyyssssssoyhhhyhho/::--------
 * ::::::---------:+shhhddd+o+++++yddhhhhhyyyso+::::-
 * ::::::::::::o+oyssyhyhdh+///:+hhoshhhhhhhhyo+:::::
 * ::::::::::::+syyssss/:yyoo+sydo/o+s+/+osyysoo/::::
 * ::::::::::::/+ssyyyyy/:oyyhhhs/ss/y/::::::::::::::
 * :::::::::::::::/+syhhhsyhhhhyyss+oo/::::::::::::::
 * :::::::::/o+/:::::/+syhddddysyso+so/:::::////:::::
 * ::::::+yhhyhhs::::::/yhdddddssso/ss:::::::///:::::
 * :::::::::hhhh+/+/:/shoshyysss/  `+s:::::://::::/::
 * ::::::::+hhhho:+sshhsyhhhs+:.     `-//::::::::::::
 * ::::::::ohhyoo+oyhyyhhhyyssoo/:-`    .:/::::::::::
 * :::::::::syso+syhhhhhhhhhhhhhhyyyo:`   ./:::::::::
 * :::::::::--://+o++osyo+yhhhhhhhhhhyys/`  :::::::::
 * ::::::--.:/+/::::-::::yhhhhhhhhhhhyyy+.  :::::::::
 * :------://:::::----:::/yhyyyyyyyyyys+`   :+:::::::
 * ------::-----------:shyhhyyyyss+/:-...-::+//::::::
 * ------------------/yhhhhhhyyyssso+::::::::::::::::
 * -----------------+yyyhhhhhhhyyssso+/---------:::::
 * ---------------/syyys/yhhhhhhyyyysss+-------------
 * .............:syyyyo---oyhhhhhhhhyyyhs------------
 * ...........-oyyyyyo....-+syyhyyhhhhddy------------
 * ...........syyyyys-......-::::+:////:.------------
 * ...........yyyyys:............-...............----
 * ...........+sss:..................................
 * .....````````.``..................................
 *
 *
 * X3DH -- eXtended 3-way Diffie-Hellman
 *
 * Specification by Open Whisper Systems <https://signal.org/docs/specifications/x3dh/>
 * Powered by @substrate-system/keys
 *
 * Implemented by Soatok Dreamseeker <https://soatok.blog>
 * Re-implemented using @substrate-system/keys for @substrate-system/x3dh
 */
import { exportPublicKey } from '@substrate-system/keys/ecc'
import { webcrypto } from '@substrate-system/one-webcrypto'
// import { fromBase64, toBase64 } from '@substrate-system/keys/util'
import {
    CryptographyKey,
    type KeyDerivationFunction,
    type SymmetricEncryptionInterface,
    blakeKdf,
    SymmetricCrypto
} from './symmetric.js'
import type {
    SessionKeyManagerInterface,
    IdentityKeyManagerInterface
} from './persistence.js'
import {
    DefaultSessionKeyManager,
    DefaultIdentityKeyManager
} from './persistence.js'
import {
    concat,
    generateKeyPair,
    generateBundle,
    signBundle,
    verifyBundle,
    wipe,
    arrayBufferToHex,
    hexToArrayBuffer
} from './util.js'

// Type aliases for keys module equivalents
type Ed25519SecretKey = CryptoKey
type Ed25519PublicKey = CryptoKey
type X25519SecretKey = CryptoKey
type X25519PublicKey = CryptoKey

// Helper functions for key import/export with keys module
async function importEd25519PublicKey (
    hexString:string
):Promise<Ed25519PublicKey> {
    const keyBytes = hexToArrayBuffer(hexString)

    // Validate Ed25519 public key size
    if (keyBytes.byteLength !== 32) {
        throw new Error(`Invalid Ed25519 public key size: expected 32 bytes, got ${keyBytes.byteLength} bytes. Hex: ${hexString}`)
    }

    try {
        return await webcrypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'Ed25519' },
            true,  // extractable for exporting identity keys
            ['verify']
        )
    } catch (error) {
        throw new Error(`Failed to import Ed25519 public key: ${error}. Key size: ${keyBytes.byteLength} bytes, Hex: ${hexString}`)
    }
}

async function importX25519PublicKey (
    hexString:string
):Promise<X25519PublicKey> {
    const keyBytes = hexToArrayBuffer(hexString)
    return await webcrypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'X25519' },
        true,  // extractable so we can export for signing verification
        []  // Node.js requires empty usage array for X25519 raw imports
    )
}

// X25519 scalar multiplication using Web Crypto API (minimal for ECDH)
async function scalarMult (
    privateKey:X25519SecretKey,
    publicKey:X25519PublicKey
):Promise<CryptographyKey> {
    // Use the Web Crypto API's X25519 ECDH for proper key derivation
    const derivedKey = await globalThis.crypto.subtle.deriveKey(
        { name: 'X25519', public: publicKey },
        privateKey,
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['encrypt', 'decrypt']
    )

    // Export the key to get the raw shared secret
    const sharedSecret = await webcrypto.subtle.exportKey('raw', derivedKey)
    return new CryptographyKey(new Uint8Array(sharedSecret))
}

// No need for Ed25519 to X25519 conversion
// Ed25519: Identity and signing
// X25519: Key exchange (pre-keys, one-time keys, ephemeral keys)

/**
 * Initial server info.
 *
 * Contains the information necessary to complete
 * the X3DH handshake from a sender's side.
 */
export type InitServerInfo = {
    IdentityKey:string,
    SignedPreKey:{
        Signature:string,
        PreKey:string
    },
    OneTimeKey?:string
};

/**
 * Initial information about a sender
 */
export type InitSenderInfo = {
    Sender:string,
    IdentityKey:string,
    PreKey:string,  // Sender's pre-key public for DH operations
    EphemeralKey:string,
    OneTimeKey?:string,
    CipherText:string
};

/**
 * Send a network request to the server to obtain the public keys needed
 * to complete the sender's handshake.
 */
export type InitClientFunction = (id:string)=>Promise<InitServerInfo>;

/**
 * Signed key bundle.
 */
export type SignedBundle = { signature:string, bundle:string[] };

/**
 * Initialization information for receiving a handshake message.
 */
type RecipientInitWithSK = {
    IK:Ed25519PublicKey,
    EK:X25519PublicKey,
    SK:CryptographyKey,
    OTK?:string
};

/**
 * Pluggable X3DH implementation, using Web Crypto API.
 */
export class X3DH {
    encryptor:SymmetricEncryptionInterface
    kdf:KeyDerivationFunction
    identityKeyManager:IdentityKeyManagerInterface
    sessionKeyManager:SessionKeyManagerInterface

    constructor (
        identityKeyManager?:IdentityKeyManagerInterface,
        sessionKeyManager?:SessionKeyManagerInterface,
        encryptor?:SymmetricEncryptionInterface,
        kdf?:KeyDerivationFunction
    ) {
        if (!sessionKeyManager) {
            sessionKeyManager = new DefaultSessionKeyManager()
        }
        if (!identityKeyManager) {
            identityKeyManager = new DefaultIdentityKeyManager()
        }
        if (!encryptor) {
            encryptor = new SymmetricCrypto()
        }
        if (!kdf) {
            kdf = blakeKdf
        }
        this.encryptor = encryptor
        this.kdf = kdf
        this.sessionKeyManager = sessionKeyManager
        this.identityKeyManager = identityKeyManager
    }

    /**
     * Generates and signs a bundle of one-time keys.
     *
     * Useful for pushing more OTKs to the server.
     *
     * @param {Ed25519SecretKey} signingKey
     * @param {number} numKeys
     */
    async generateOneTimeKeys (
        signingKey:Ed25519SecretKey,
        numKeys:number = 100
    ):Promise<SignedBundle> {
        try {
            // Validate the signing key
            if (!signingKey || typeof signingKey !== 'object') {
                throw new Error('Invalid signing key: must be a CryptoKey object')
            }

            if (signingKey.algorithm?.name !== 'Ed25519') {
                throw new Error(`Invalid signing key algorithm: expected Ed25519, got ${signingKey.algorithm?.name}`)
            }

            const bundle = await generateBundle(numKeys)
            const publicKeys = bundle.map(x => x.publicKey)
            const signature = await signBundle(signingKey, publicKeys)
            await this.identityKeyManager.persistOneTimeKeys(bundle)

            // Hex-encode all the public keys using keys module
            const encodedBundle:string[] = []
            for (const pk of publicKeys) {
                const rawKey = await exportPublicKey({ publicKey: pk } as CryptoKeyPair)
                encodedBundle.push(arrayBufferToHex(rawKey))
            }

            return {
                signature: arrayBufferToHex(signature),
                bundle: encodedBundle
            }
        } catch (error) {
            throw new Error(`Failed to generate one-time keys: ${error}`)
        }
    }

    /**
     * Get the shared key when sending an initial message.
     *
     * @param {InitServerInfo} res
     * @param {string} _senderIdentity - not needed for key operations,
     *   ust for context
     */
    async initSenderGetSK (
        res:InitServerInfo,
        _senderIdentity:string
    ):Promise<RecipientInitWithSK> {
        const identityKey = await importEd25519PublicKey(res.IdentityKey)
        const signedPreKey = await importX25519PublicKey(res.SignedPreKey.PreKey)
        const signature = hexToArrayBuffer(res.SignedPreKey.Signature)

        // Check signature
        const valid = await verifyBundle(
            identityKey,
            [signedPreKey],
            new Uint8Array(signature)
        )
        if (!valid) {
            throw new Error('Invalid signature')
        }
        const ephemeral = await generateKeyPair()
        const ephSecret = ephemeral.secretKey
        const ephPublic = ephemeral.publicKey

        // X3DH uses the sender's identity key and ephemeral key with
        //   recipient's signed pre-key
        // Since Web Crypto API doesn't support Ed25519->X25519 conversion,
        //   we'll use a simplified approach where the pre-key serves
        //   as the identity exchange key

        // Use the sender's pre-key
        // as their identity exchange key for DH operations
        const senderPreKey = await this.identityKeyManager.getPreKeypair()

        // See the X3DH specification
        // DH1 = DH(IK_A, SPK_B) - sender identity (pre-key)
        //   with recipient's signed pre-key
        // DH2 = DH(EK_A, IK_B) - sender ephemeral with recipient's
        //   identity (signed pre-key)
        // DH3 = DH(EK_A, SPK_B) - sender ephemeral with recipient's
        //   signed pre-key

        const DH1 = await scalarMult(senderPreKey.preKeySecret, signedPreKey)
        // Use signed pre-key as recipient identity
        const DH2 = await scalarMult(ephSecret, signedPreKey)
        const DH3 = await scalarMult(ephSecret, signedPreKey)
        let SK
        if (res.OneTimeKey) {
            const otk = await importX25519PublicKey(res.OneTimeKey)
            const DH4 = await scalarMult(ephSecret, otk)
            SK = new CryptographyKey(
                new Uint8Array(await this.kdf(
                    concat(
                        DH1.getBuffer(),
                        DH2.getBuffer(),
                        DH3.getBuffer(),
                        DH4.getBuffer()
                    )
                ))
            )
            await wipe(DH4)
        } else {
            SK = new CryptographyKey(
                new Uint8Array(await this.kdf(
                    concat(
                        DH1.getBuffer(),
                        DH2.getBuffer(),
                        DH3.getBuffer()
                    )
                ))
            )
        }

        // Wipe DH keys since we have SK
        await wipe(DH1)
        await wipe(DH2)
        await wipe(DH3)
        // Note: ephSecret and senderX are CryptoKeys, so wipe won't do much
        // but we'll keep the calls for API compatibility

        return {
            IK: identityKey,
            EK: ephPublic,
            SK,
            OTK: res.OneTimeKey
        }
    }

    /**
     * Initialize for sending.
     *
     * @param {string} recipientIdentity
     * @param {InitClientFunction} getServerResponse
     * @param {string|Uint8Array} message
     */
    async initSend (
        recipientIdentity:string,
        getServerResponse:InitClientFunction,
        message:string|Uint8Array
    ):Promise<InitSenderInfo> {
        // Get the identity key for the sender:
        const senderIdentity = await this.identityKeyManager.getMyIdentityString()
        const identity = await this.identityKeyManager.getIdentityKeypair()
        const senderPublicKey = identity.identityPublic
        const senderPreKey = await this.identityKeyManager.getPreKeypair()

        // Stub out a call to get the server response:
        const response = await getServerResponse(recipientIdentity)

        // Get the shared symmetric key (and other handshake data):
        const { IK, EK, SK, OTK } = await this.initSenderGetSK(response, senderIdentity)

        // Get the assocData for AEAD using keys module:
        const senderPublicRaw = await exportPublicKey({
            publicKey: senderPublicKey
        } as CryptoKeyPair)
        const ikRaw = await exportPublicKey({ publicKey: IK } as CryptoKeyPair)
        const assocData = arrayBufferToHex(
            concat(new Uint8Array(senderPublicRaw), new Uint8Array(ikRaw))
        )

        // Set the session key (as a sender):
        await this.sessionKeyManager.setSessionKey(recipientIdentity, SK, false)
        await this.sessionKeyManager.setAssocData(recipientIdentity, assocData)
        return {
            Sender: senderIdentity,
            IdentityKey: arrayBufferToHex(senderPublicRaw),
            PreKey: arrayBufferToHex(await exportPublicKey({
                publicKey: senderPreKey.preKeyPublic
            } as CryptoKeyPair)),
            EphemeralKey: arrayBufferToHex(await exportPublicKey({
                publicKey: EK
            } as CryptoKeyPair)),
            OneTimeKey: OTK,
            CipherText: await this.encryptor.encrypt(
                message,
                await this.sessionKeyManager.getEncryptionKey(recipientIdentity),
                assocData
            )
        }
    }

    /**
     * Get the shared key when receiving an initial message.
     *
     * @param {InitSenderInfo} req
     * @param {string} recipientIdentity - not needed for key operations,
     *   just for context
     * @param preKeySecret
     */
    async initRecvGetSk (
        req:InitSenderInfo,
        _recipientIdentity:string,
        preKeySecret:X25519SecretKey
    ) {
        // Decode strings
        const senderIdentityKey = await importEd25519PublicKey(req.IdentityKey)
        const senderPreKey = await importX25519PublicKey(req.PreKey)
        const ephemeral = await importX25519PublicKey(req.EphemeralKey)

        // Now we have the sender's pre-key public, we can do proper
        //   X3DH DH operations
        // The receiver needs to perform DH operations using their own
        //   private keys
        // with the sender's public keys

        // For receiver, we use our pre-key as our identity exchange key
        const recipientPreKey = await this.identityKeyManager.getPreKeypair()

        // See the X3DH specification (receiver's perspective):
        // DH1 = DH(SPK_B, IK_A) - recipient's signed pre-key with sender's
        //   identity (pre-key)
        // DH2 = DH(IK_B, EK_A) - recipient's identity (pre-key) with
        //   sender's ephemeral
        // DH3 = DH(SPK_B, EK_A) - recipient's signed pre-key with
        //   sender's ephemeral
        const DH1 = await scalarMult(preKeySecret, senderPreKey)
        const DH2 = await scalarMult(recipientPreKey.preKeySecret, ephemeral)
        const DH3 = await scalarMult(preKeySecret, ephemeral)

        let SK
        if (req.OneTimeKey) {
            const otk = await this.identityKeyManager
                .fetchAndWipeOneTimeSecretKey(req.OneTimeKey)
            const DH4 = await scalarMult(otk, ephemeral)
            SK = new CryptographyKey(
                new Uint8Array(await this.kdf(
                    concat(
                        DH1.getBuffer(),
                        DH2.getBuffer(),
                        DH3.getBuffer(),
                        DH4.getBuffer()
                    )
                ))
            )
            await wipe(DH4)
        } else {
            SK = new CryptographyKey(
                new Uint8Array(await this.kdf(
                    concat(
                        DH1.getBuffer(),
                        DH2.getBuffer(),
                        DH3.getBuffer()
                    )
                ))
            )
        }
        // Wipe DH keys since we have SK
        await wipe(DH1)
        await wipe(DH2)
        await wipe(DH3)

        return {
            Sender: req.Sender,
            SK,
            IK: senderIdentityKey
        }
    }

    /**
     * Initialize keys for receiving an initial message.
     * Returns the initial plaintext message on success.
     * Throws on failure.
     *
     * @param {InitSenderInfo} req
     * @returns {(string|Uint8Array)[]}
     */
    async initRecv (req:InitSenderInfo):Promise<(string|Uint8Array)[]> {
        const { identityPublic } = await this.identityKeyManager.getIdentityKeypair()
        const { preKeySecret } = await this.identityKeyManager.getPreKeypair()
        const recipientIdentity = await this.identityKeyManager.getMyIdentityString()
        const { Sender, SK, IK } = await this.initRecvGetSk(
            req,
            recipientIdentity,
            preKeySecret
        )

        const ikRaw = await exportPublicKey({ publicKey: IK } as CryptoKeyPair)
        const identityPublicRaw = await exportPublicKey({
            publicKey: identityPublic
        } as CryptoKeyPair)
        const assocData = arrayBufferToHex(
            concat(new Uint8Array(ikRaw), new Uint8Array(identityPublicRaw))
        )

        try {
            await this.sessionKeyManager.setSessionKey(Sender, SK, true)
            await this.sessionKeyManager.setAssocData(Sender, assocData)
            return [
                Sender,
                await this.encryptor.decrypt(
                    req.CipherText,
                    await this.sessionKeyManager.getEncryptionKey(Sender, true),
                    assocData
                )
            ]
        } catch (e) {
            // Decryption failure! Destroy the session.
            await this.sessionKeyManager.destroySessionKey(Sender)
            throw e
        }
    }

    /**
     * Encrypt the next message to send to the recipient.
     *
     * @param {string} recipient
     * @param {string|Uint8Array} message
     * @returns {string}
     */
    async encryptNext (
        recipient:string,
        message:string|Uint8Array
    ):Promise<string> {
        return this.encryptor.encrypt(
            message,
            await this.sessionKeyManager.getEncryptionKey(recipient, false),
            await this.sessionKeyManager.getAssocData(recipient)
        )
    }

    /**
     * Decrypt the next message received by the sender.
     *
     * @param {string} sender
     * @param {string} encrypted
     * @returns {string|Uint8Array}
     */
    async decryptNext (
        sender:string,
        encrypted:string
    ):Promise<string|Uint8Array> {
        return this.encryptor.decrypt(
            encrypted,
            await this.sessionKeyManager.getEncryptionKey(sender, true),
            await this.sessionKeyManager.getAssocData(sender)
        )
    }

    /**
     * Sign a pre-key with the identity key.
     * This is what should be used for signed pre-keys in X3DH.
     *
     * @param {Ed25519SecretKey} signingKey
     * @param {X25519PublicKey} preKey
     */
    async signPreKey (
        signingKey:Ed25519SecretKey,
        preKey:X25519PublicKey
    ):Promise<string> {
        const signature = await signBundle(signingKey, [preKey])
        return arrayBufferToHex(signature)
    }

    /**
     * Sets the identity string for the current user.
     *
     * @param {string} id
     */
    async setIdentityString (id:string):Promise<void> {
        return this.identityKeyManager.setMyIdentityString(id)
    }
}

// export the interfaces we use
export * from './symmetric'
export * from './persistence'
export * from './util'
