import { test } from '@substrate-system/tapzero'
import { signBundle, X3DH } from '../src/index.js'

// Helper function to generate Ed25519 key pairs
async function generateEd25519KeyPair ():Promise<{
    publicKey: CryptoKey,
    privateKey: CryptoKey
}> {
    const keyPair = await globalThis.crypto.subtle.generateKey(
        { name: 'Ed25519' },
        true,  // extractable for getting raw bytes
        ['sign', 'verify']
    ) as CryptoKeyPair
    return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey }
}

// Helper function to get raw bytes from a CryptoKey
async function exportKeyAsBytes (key:CryptoKey):Promise<Uint8Array> {
    const rawKey = await globalThis.crypto.subtle.exportKey('raw', key)
    return new Uint8Array(rawKey)
}

// Helper function to convert bytes to hex string
function arrayBufferToHex (buffer: ArrayBuffer): string {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
}

test('generate one time keys', async t => {
    const { privateKey } = await generateEd25519KeyPair()
    const x3dh = new X3DH()
    const response = await x3dh.generateOneTimeKeys(privateKey, 4)
    t.equal(response.bundle.length, 4, '4 bundle length')
    t.equal(response.signature.length, 128, 'should be 128 bits')
})

test('x3dh Handshake with one-time keys', async t => {
    t.plan(26)

    // 1. Generate identity keys
    const fox_keys = await generateEd25519KeyPair()
    const fox_sk = fox_keys.privateKey
    const fox_pk = fox_keys.publicKey
    const wolf_keys = await generateEd25519KeyPair()
    const wolf_sk = wolf_keys.privateKey
    const wolf_pk = wolf_keys.publicKey

    // 2. Instantiate object with same config (defaults)
    const fox_x3dh = new X3DH()
    const wolf_x3dh = new X3DH()
    await fox_x3dh.identityKeyManager.setIdentityKeypair(fox_sk, fox_pk)
    await fox_x3dh.setIdentityString('fox')
    t.equal(
        await fox_x3dh.identityKeyManager.getMyIdentityString(),
        'fox'
    )
    await wolf_x3dh.identityKeyManager.setIdentityKeypair(wolf_sk, wolf_pk)
    await wolf_x3dh.setIdentityString('wolf')
    t.equal(
        await wolf_x3dh.identityKeyManager.getMyIdentityString(),
        'wolf'
    )

    // 3. Generate a pre-key for each.
    const fox_pre = await fox_x3dh.identityKeyManager.getPreKeypair()
    t.ok(fox_pre, 'should generate fox pre-key')
    const wolf_pre = await wolf_x3dh.identityKeyManager.getPreKeypair()

    // 4. Generate some one-time keys
    const fox_bundle = await fox_x3dh.generateOneTimeKeys(fox_sk, 3)
    t.ok(fox_bundle, 'should generate a fox bundle')
    const wolf_bundle = await wolf_x3dh.generateOneTimeKeys(wolf_sk, 3)

    const wolfResponse = async () => {
        const sig = await signBundle(wolf_sk, [wolf_pre.preKeyPublic])
        const wolfPkBytes = await exportKeyAsBytes(wolf_pk)
        const preKeyBytes = await exportKeyAsBytes(wolf_pre.preKeyPublic)
        return {
            IdentityKey: arrayBufferToHex(wolfPkBytes),
            SignedPreKey: {
                Signature: arrayBufferToHex(sig),
                PreKey: arrayBufferToHex(preKeyBytes)
            },
            OneTimeKey: wolf_bundle.bundle[0]
        }
    }

    // 5. Do an initial handshake from fox->wolf
    const message = 'hewwo UwU'
    const sent = await fox_x3dh.initSend('wolf', wolfResponse, message)

    // 6. Pass the handshake to wolf->fox
    const [sender, recv] = await wolf_x3dh.initRecv(sent)
    t.equal(sender, 'fox', 'sender should be "fox"')
    t.equal(recv.toString(), message, 'should decrypt the message')

    // Send and receive a few more:
    for (let i = 0; i < 20; i++) {
        try {
            const plain = `OwO what's this? ${i}`
            if ((i % 3) === 0) {
                const cipher = await wolf_x3dh.encryptNext('fox', plain)
                const decrypt = await fox_x3dh.decryptNext('wolf', cipher)
                t.equal(
                    decrypt.toString(),
                    plain,
                    `round ${i + 1}`
                )
            } else {
                const cipher = await fox_x3dh.encryptNext('wolf', plain)
                const decrypt = await wolf_x3dh.decryptNext('fox', cipher)
                t.equal(
                    decrypt.toString(),
                    plain,
                    `round ${i + 1}`
                )
            }
        } catch (err) {
            console.log('Failed at i = ' + i)
            throw err
        }
    }
})
