#!/usr/bin/env node
// Prints the test vectors used in src/antelope.rs, made with @wharfkit/antelope.
import {Bytes, Checksum256, KeyType, PrivateKey} from '@wharfkit/antelope'

const secret = 'd2653ff7cbb2d8ff129ac27ef5781ce68b2558c41a74af1f2ddca635cbeef07d'
const key = new PrivateKey(KeyType.K1, Bytes.from(secret, 'hex'))
console.log(`const SECRET: &str = "${secret}";`)
console.log(`const PUBLIC: &str = "${key.toPublic()}";`)
console.log('const WHARFKIT_SIGNATURES: &[(&str, &str, &str)] = &[')
for (const text of ['dabao', 'XPR Network', 'Telos']) {
    const digest = Checksum256.hash(Bytes.from(text, 'utf8'))
    const sig = key.signDigest(digest)
    const raw = Buffer.concat([Buffer.from([sig.data.array[0]]), Buffer.from(sig.data.array.subarray(1))])
    console.log(`    ("${digest.hexString}", "${raw.toString('hex')}", "${sig}"),`)
}
console.log('];')
