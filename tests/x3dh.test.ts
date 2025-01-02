import { test } from '@substrate-system/tapzero'
import type { Ed25519PublicKey, Ed25519SecretKey } from 'sodium-plus'
import { SodiumPlus } from 'sodium-plus'
import { X3DH } from '../src/index'
import { signBundle } from '../src/util'

test('generate one-time keys', async t => {
    const sodium = await SodiumPlus.auto()
    const keypair = await sodium.crypto_sign_keypair()
    const sk: Ed25519SecretKey = await sodium.crypto_sign_secretkey(keypair)
    const x3dh = new X3DH()
    const response = await x3dh.generateOneTimeKeys(sk, 4)
    t.equal(response.bundle.length, 4, 'right length .bundle')
    t.equal(response.signature.length, 128, 'right length signature')
    return t.plan(2)
})

test('X3DH Handshake with one-time keys', async t => {
    const sodium = await SodiumPlus.auto()

    // 1. Generate identity keys
    const fox_keypair = await sodium.crypto_sign_keypair()
    const fox_sk:Ed25519SecretKey = await sodium.crypto_sign_secretkey(fox_keypair)
    const fox_pk:Ed25519PublicKey = await sodium.crypto_sign_publickey(fox_keypair)
    const wolf_keypair = await sodium.crypto_sign_keypair()
    const wolf_sk:Ed25519SecretKey = await sodium.crypto_sign_secretkey(wolf_keypair)
    const wolf_pk:Ed25519PublicKey = await sodium.crypto_sign_publickey(wolf_keypair)

    // 2. Instantiate object with same config (defaults)
    const fox_x3dh = new X3DH()
    const wolf_x3dh = new X3DH()
    await fox_x3dh.identityKeyManager.setIdentityKeypair(fox_sk, fox_pk)
    await fox_x3dh.setIdentityString('fox')
    const foxX3Id = await fox_x3dh.identityKeyManager.getMyIdentityString()
    t.equal(foxX3Id, 'fox', 'should have the right ID string')
    await wolf_x3dh.identityKeyManager.setIdentityKeypair(wolf_sk, wolf_pk)
    await wolf_x3dh.setIdentityString('wolf')
    const wolfX3Id = await wolf_x3dh.identityKeyManager.getMyIdentityString()
    t.equal(wolfX3Id, 'wolf', 'should have the right X3 ID')

    // 3. Generate a pre-key for each.
    const fox_pre = await fox_x3dh.identityKeyManager.getPreKeypair()
    t.ok(fox_pre, 'fox pre key is ok')
    const wolf_pre = await wolf_x3dh.identityKeyManager.getPreKeypair()

    // 4. Generate some one-time keys
    const fox_bundle = await fox_x3dh.generateOneTimeKeys(fox_sk, 3)
    t.ok(fox_bundle, 'fox bundle should exist')
    const wolf_bundle = await wolf_x3dh.generateOneTimeKeys(wolf_sk, 3)

    const wolfResponse = async () => {
        const sig = await signBundle(wolf_sk, [wolf_pre.preKeyPublic])
        return {
            IdentityKey: await sodium.sodium_bin2hex(wolf_pk.getBuffer()),
            SignedPreKey: {
                Signature: await sodium.sodium_bin2hex(sig),
                PreKey: await sodium.sodium_bin2hex(wolf_pre.preKeyPublic.getBuffer())
            },
            OneTimeKey: wolf_bundle.bundle[0]
        }
    }

    // 5. Do an initial handshake from fox->wolf
    const message = 'hewwo UwU'
    const sent = await fox_x3dh.initSend('wolf', wolfResponse, message)

    // 6. Pass the handshake to wolf->fox
    const [sender, recv] = await wolf_x3dh.initRecv(sent)
    t.equal(sender, 'fox', 'should have the right sender')
    t.equal(recv.toString(), message, 'should have the right message content')

    // Send and receive a few more:
    for (let i = 0; i < 20; i++) {
        try {
            const plain = `OwO what's this? ${i}`
            if ((i % 3) === 0) {
                const cipher = await wolf_x3dh.encryptNext('fox', plain)
                const decrypt = await fox_x3dh.decryptNext('wolf', cipher)
                t.equal(decrypt.toString(), plain, `round ${i + 1}`)
            } else {
                const cipher = await fox_x3dh.encryptNext('wolf', plain)
                const decrypt = await wolf_x3dh.decryptNext('fox', cipher)
                t.equal(decrypt.toString(), plain, `round ${i + 1}`)
            }
        } catch (err) {
            console.log('Failed at i = ' + i)
            throw err
        }
    }
})
