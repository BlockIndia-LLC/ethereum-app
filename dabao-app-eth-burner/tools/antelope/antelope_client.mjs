#!/usr/bin/env node
// Host client for the dabao signer's Antelope commands (protocol.cddl), for
// XPR Network, Telos and other Antelope chains. Everything Antelope on the
// host side (serializing, digests, key and signature checks, broadcasting)
// is done by @wharfkit/antelope: `npm install` in this directory first.
//
//   antelope_client.mjs get-key [--path m/44'/194'/0'/0/0]
//   antelope_client.mjs selftest
//       emulator only: signs a made-up transfer and checks the key and the
//       signature against Wharfkit; approves it itself (the approval file)
//   antelope_client.mjs transfer --network xpr-testnet --from A --to B
//                       --quantity "0.0001 XPR" [--memo TEXT] [--permission active]
//                       [--contract eosio.token] [--no-broadcast]
//       builds the transfer, has it signed (touch the pad, or create the
//       approval file in the emulator), checks the signature and broadcasts it
//   antelope_client.mjs action --network xpr-testnet --from A --contract token.faucet
//                       --action claim --data '{"programId":2,"account":"A"}'
//       the same for any one action; its data is serialized with the
//       contract's ABI, fetched from the network
//
// Talking to the signer:
//   --tcp HOST:PORT   the emulator (default 127.0.0.1:7600)
//   --relay FILE      a board on another machine. The first run prints the
//                     request as hex and saves its state in FILE; send the hex
//                     with tools/windows/dabao-hid-send.ps1, then run the same
//                     command again with --reply <hex the board answered>.
//
// Networks: xpr-testnet, telos-testnet, or the URL of a node's API. Test
// networks only: the signer can't show what it signs.
import fs from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import {fileURLToPath} from 'node:url'
import {
    ABI, Action, APIClient, Bytes, Checksum256, KeyType, PublicKey, Serializer, Signature,
    SignedTransaction, Transaction,
} from '@wharfkit/antelope'

const TYPE_CUSTOM = 0x02
const CMD_ANTELOPE_KEY = 6
const CMD_ANTELOPE_SIGN = 7
const ERRORS = {1: 'user-rejected', 2: 'invalid-request', 3: 'unsupported', 4: 'busy', 5: 'internal', 6: 'not-ready'}
const DEFAULT_PATH = "m/44'/194'/0'/0/0"
const NETWORKS = {
    'xpr-testnet': 'https://testnet.protonchain.com',
    'telos-testnet': 'https://testnet.telos.net',
}
const HERE = path.dirname(fileURLToPath(import.meta.url))

// ------------------------------------------------------------ CBOR (subset)
class Tag {
    constructor(tag, value) { this.tag = tag; this.value = value }
}

function head(major, n) {
    if (n < 24) return [major << 5 | n]
    if (n < 0x100) return [major << 5 | 24, n]
    if (n < 0x10000) return [major << 5 | 25, n >> 8, n & 0xff]
    return [major << 5 | 26, n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]
}

function cborEncode(v) {
    if (typeof v === 'boolean') return [v ? 0xf5 : 0xf4]
    if (typeof v === 'number') return head(0, v)
    if (typeof v === 'string') { const b = Buffer.from(v, 'utf8'); return [...head(3, b.length), ...b] }
    if (v instanceof Uint8Array) return [...head(2, v.length), ...v]
    if (Array.isArray(v)) return [...head(4, v.length), ...v.flatMap(cborEncode)]
    if (v instanceof Tag) return [...head(6, v.tag), ...cborEncode(v.value)]
    if (v instanceof Map) return [...head(5, v.size), ...[...v].flatMap(([k, x]) => [...cborEncode(k), ...cborEncode(x)])]
    throw new Error('unsupported CBOR value')
}

function cborDecode(b, i = 0) {
    const major = b[i] >> 5, ai = b[i] & 31
    i += 1
    let n = ai
    if (ai >= 24 && ai <= 26) {
        const len = 1 << (ai - 24)
        n = 0
        for (let j = 0; j < len; j++) n = n * 256 + b[i + j]
        i += len
    } else if (ai > 26) throw new Error('unsupported CBOR')
    switch (major) {
        case 0: return [n, i]
        case 2: return [Uint8Array.from(b.subarray(i, i + n)), i + n]
        case 3: return [Buffer.from(b.subarray(i, i + n)).toString('utf8'), i + n]
        case 4: { const a = []; for (let j = 0; j < n; j++) { let v; [v, i] = cborDecode(b, i); a.push(v) } return [a, i] }
        case 5: { const m = new Map(); for (let j = 0; j < n; j++) { let k, v; [k, i] = cborDecode(b, i); [v, i] = cborDecode(b, i); m.set(k, v) } return [m, i] }
        case 6: { const [v, j] = cborDecode(b, i); return [v, j] }
        case 7: return [{20: false, 21: true, 22: null}[ai], i]
        default: throw new Error('unsupported CBOR')
    }
}

// ------------------------------------------------------------ requests
function keypath(p) {
    const comps = []
    for (const c of p.split('/').slice(1)) {
        const hardened = /['h]$/.test(c)
        comps.push(parseInt(c, 10), hardened)
    }
    return new Tag(304, new Map([[1, comps]]))
}

/** `type || message` of a custom request. */
function body(entries) {
    return Uint8Array.from([TYPE_CUSTOM, ...cborEncode(new Map(entries))])
}

function keyRequest(p) {
    return body([[1, CMD_ANTELOPE_KEY], [2, keypath(p)]])
}

function signRequest(p, chainId, transaction, expectedKey) {
    const entries = [[1, CMD_ANTELOPE_SIGN], [2, keypath(p)], [7, chainId], [8, transaction]]
    if (expectedKey) entries.push([10, expectedKey])
    return body(entries)
}

/** Decode a reply body (`type || message`); throws on an error-response. */
function reply(b) {
    const [m] = cborDecode(b, 1)
    if (b[0] !== TYPE_CUSTOM || !(m instanceof Map)) throw new Error('unexpected reply')
    const status = m.get(1)
    if (status !== 0) throw new Error(`the signer answered error ${status} (${ERRORS[status] ?? '?'}): ${m.get(6) ?? ''}`)
    return m
}

// ------------------------------------------------------------ transports
/** Emulator: `length (u32 BE) || body` over TCP. */
function tcpExchange(addr, b) {
    const i = addr.lastIndexOf(':')
    return new Promise((resolve, reject) => {
        const s = net.createConnection({host: addr.slice(0, i), port: Number(addr.slice(i + 1))})
        let buf = Buffer.alloc(0)
        s.on('connect', () => {
            const len = Buffer.alloc(4)
            len.writeUInt32BE(b.length)
            s.write(Buffer.concat([len, b]))
        })
        s.on('data', (d) => {
            buf = Buffer.concat([buf, d])
            if (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
                s.destroy()
                resolve(Uint8Array.from(buf.subarray(4, 4 + buf.readUInt32BE(0))))
            }
        })
        s.on('error', reject)
        s.on('close', () => reject(new Error('the signer closed the connection')))
    })
}

const hex = (b) => Buffer.from(b).toString('hex')
const unhex = (s) => Uint8Array.from(Buffer.from(s.replace(/^0x/, '').replace(/\s+/g, ''), 'hex'))

/** What dabao-hid-send.ps1 prints is the whole frame; accept that or a bare body. */
function replyBody(text) {
    const b = unhex(text)
    const framed = b.length >= 5 && Buffer.from(b).readUInt32BE(0) === b.length - 4
    // a HID reply is padded with zeros to 64-byte reports
    const padded = b.length >= 5 && Buffer.from(b).readUInt32BE(0) < b.length - 4 && b[0] === 0
    return framed ? b.subarray(4) : padded ? b.subarray(4, 4 + Buffer.from(b).readUInt32BE(0)) : b
}

// ------------------------------------------------------------ Antelope
const TRANSFER_ABI = ABI.from({
    structs: [{
        name: 'transfer',
        base: '',
        fields: [
            {name: 'from', type: 'name'},
            {name: 'to', type: 'name'},
            {name: 'quantity', type: 'asset'},
            {name: 'memo', type: 'string'},
        ],
    }],
    actions: [{name: 'transfer', type: 'transfer', ricardian_contract: ''}],
})

function transferAction(a) {
    return Action.from({
        account: a.contract ?? 'eosio.token',
        name: 'transfer',
        authorization: [{actor: a.from, permission: a.permission ?? 'active'}],
        data: {from: a.from, to: a.to, quantity: a.quantity, memo: a.memo ?? ''},
    }, TRANSFER_ABI)
}

const serialize = (tx) => Serializer.encode({object: tx}).array

/** Check a key reply against Wharfkit's own encoding; returns the PublicKey. */
function checkKey(m) {
    const key = new PublicKey(KeyType.K1, Bytes.from(m.get(2)))
    if (key.toString() !== m.get(10)) throw new Error(`key text mismatch: ${m.get(10)} is not ${key}`)
    return key
}

/** Check a signature reply: text form, canonical, and the key it recovers to. */
function checkSignature(m, tx, chainId, expectedKey) {
    const raw = m.get(9)
    const sig = Signature.from({type: 'K1', recid: raw[0] - 31, r: raw.subarray(1, 33), s: raw.subarray(33)})
    if (sig.toString() !== m.get(10)) throw new Error(`signature text mismatch: ${m.get(10)} is not ${sig}`)
    const canonical = (n) => !(n[0] & 0x80) && !(n[0] === 0 && !(n[1] & 0x80))
    if (!canonical(raw.subarray(1, 33)) || !canonical(raw.subarray(33))) throw new Error('signature is not canonical')
    const digest = tx.signingDigest(chainId)
    const signer = sig.recoverDigest(digest)
    if (expectedKey && !signer.equals(expectedKey)) throw new Error(`signed by ${signer}, expected ${expectedKey}`)
    if (!sig.verifyDigest(digest, signer)) throw new Error('signature does not verify')
    return {sig, signer, digest}
}

// ------------------------------------------------------------ commands
function parseArgs(argv) {
    const a = {_: []}
    for (let i = 0; i < argv.length; i++) {
        if (!argv[i].startsWith('--')) { a._.push(argv[i]); continue }
        const k = argv[i].slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())
        if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) a[k] = argv[++i]
        else a[k] = true
    }
    return a
}

/**
 * Send one request. With --relay, the first run saves `state` and prints the
 * hex to send; the run with --reply returns the saved state and the reply.
 */
async function exchange(a, makeRequest) {
    if (!a.relay) {
        const {request, state} = await makeRequest()
        return {state, body: await tcpExchange(a.tcp ?? '127.0.0.1:7600', request)}
    }
    if (a.reply) {
        const saved = JSON.parse(fs.readFileSync(a.relay, 'utf8'))
        return {state: saved.state, body: replyBody(a.reply)}
    }
    const {request, state} = await makeRequest()
    fs.writeFileSync(a.relay, JSON.stringify({state, request: hex(request)}, null, 2))
    console.log('send this to the board (tools/windows/dabao-hid-send.ps1 -Hex ...), then run again with --reply <hex>:')
    console.log(hex(request))
    process.exit(0)
}

async function getKey(a) {
    const p = a.path ?? DEFAULT_PATH
    const {body: b} = await exchange(a, async () => ({request: keyRequest(p), state: {}}))
    const key = checkKey(reply(b))
    console.log(`${p}`)
    console.log(`public key  ${key}`)
    console.log(`legacy form ${key.toLegacyString('EOS')}`)
    return key
}

/** Emulator: approve the pending request by creating the approval file. */
function approveSoon(ms = 400) {
    const file = process.env.ETH_BURNER_APPROVE ?? path.join(HERE, '../../target/eth-burner-approve')
    setTimeout(() => fs.writeFileSync(file, ''), ms)
}

async function selftest(a) {
    const tcp = a.tcp ?? '127.0.0.1:7600'
    const p = a.path ?? DEFAULT_PATH
    const key = checkKey(reply(await tcpExchange(tcp, keyRequest(p))))
    console.log(`key at ${p}: ${key}`)

    // the key Wharfkit and @scure derive from the emulator's seed file
    const seedFile = process.env.ETH_BURNER_SEED ?? path.join(HERE, '../../target/eth-burner-seed.bin')
    if (fs.existsSync(seedFile)) {
        const {HDKey} = await import('@scure/bip32')
        const {entropyToMnemonic, mnemonicToSeedSync} = await import('@scure/bip39')
        const {wordlist} = await import('@scure/bip39/wordlists/english')
        const entropy = fs.readFileSync(seedFile).subarray(0, 32)
        const node = HDKey.fromMasterSeed(mnemonicToSeedSync(entropyToMnemonic(entropy, wordlist))).derive(p)
        const expected = new PublicKey(KeyType.K1, Bytes.from(node.publicKey))
        if (!expected.equals(key)) throw new Error(`derivation mismatch: the seed file gives ${expected}`)
        console.log('ok: the key is the one BIP-39/BIP-32 give for the seed file')
    } else {
        console.log(`(no seed file at ${seedFile}: derivation not checked)`)
    }

    // paths outside m/44'/194' are refused
    for (const other of ["m/44'/60'/0'/0/0", "m/44'/194/0'/0/0"]) {
        let refused = false
        try { reply(await tcpExchange(tcp, keyRequest(other))) } catch { refused = true }
        if (!refused) throw new Error(`${other} was not refused`)
    }
    console.log("ok: paths outside m/44'/194' are refused")

    // several made-up transfers: about half of all first-try signatures aren't canonical
    const chainId = Checksum256.from('71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd')
    const count = Number(a.count ?? 8)
    for (let i = 0; i < count; i++) {
        const tx = Transaction.from({
            expiration: '2030-01-01T00:00:00',
            ref_block_num: 1234 + i,
            ref_block_prefix: 0xdeadbeef,
            actions: [transferAction({from: 'dabaotest', to: 'blocksindia', quantity: `0.000${i + 1} XPR`, memo: `selftest ${i}`})],
        })
        approveSoon()
        const m = reply(await tcpExchange(tcp, signRequest(p, chainId.array, serialize(tx), key.toString())))
        const {sig} = checkSignature(m, tx, chainId, key)
        console.log(`ok: transfer ${i} ${sig}`)
    }

    // a wrong expected key is refused at once, without waiting for an approval
    {
        const tx = Transaction.from({expiration: '2030-01-01T00:00:00', ref_block_num: 1, ref_block_prefix: 2, actions: []})
        const wrong = 'PUB_K1_6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5BoDq63'
        const started = Date.now()
        let refused = false
        try { reply(await tcpExchange(tcp, signRequest(p, chainId.array, serialize(tx), wrong))) } catch { refused = true }
        if (!refused || Date.now() - started > 2000) throw new Error('a wrong expected key was not refused at once')
        console.log('ok: a wrong expected key is refused at once')
    }

    // without an approval nothing is signed
    if (!a.skipTimeout) {
        const tx = Transaction.from({expiration: '2030-01-01T00:00:00', ref_block_num: 1, ref_block_prefix: 2, actions: []})
        let error = ''
        try { reply(await tcpExchange(tcp, signRequest(p, chainId.array, serialize(tx)))) } catch (e) { error = e.message }
        if (!error.includes('user-rejected')) throw new Error(`signed without an approval? ${error}`)
        console.log('ok: no approval, no signature')
    }
    console.log('selftest passed')
}

async function transfer(a) {
    for (const k of ['from', 'to', 'quantity']) if (!a[k]) throw new Error(`--${k} is needed`)
    await signAndPush(a, `${a.from} -> ${a.to}: ${a.quantity}`, async () => transferAction(a))
}

/** Any one action, its data given as JSON and serialized with the contract's ABI. */
async function action(a) {
    for (const k of ['from', 'contract', 'action', 'data']) if (!a[k]) throw new Error(`--${k} is needed`)
    await signAndPush(a, `${a.contract}::${a.action} ${a.data} as ${a.from}`, async (client) => {
        const {abi} = await client.v1.chain.get_abi(a.contract)
        if (!abi) throw new Error(`${a.contract} has no ABI`)
        return Action.from({
            account: a.contract,
            name: a.action,
            authorization: [{actor: a.from, permission: a.permission ?? 'active'}],
            data: JSON.parse(a.data),
        }, abi)
    })
}

async function signAndPush(a, what, makeAction) {
    if (!a.network) throw new Error('--network is needed')
    const url = NETWORKS[a.network] ?? a.network
    if (!/testnet|localhost|127\.0\.0\.1/.test(url) && !a.iKnowThisIsNotATestnet) {
        throw new Error('test networks only: this signer cannot show what it signs')
    }
    const client = new APIClient({url})
    const p = a.path ?? DEFAULT_PATH
    const {state, body: b} = await exchange(a, async () => {
        const info = await client.v1.chain.get_info()
        const tx = Transaction.from({...info.getTransactionHeader(Number(a.expireSeconds ?? 600)), actions: [await makeAction(client)]})
        const packed = serialize(tx)
        console.log(`${what} on ${url}`)
        console.log(`transaction ${tx.id}, ${packed.length} bytes, expires ${tx.expiration}`)
        if (!a.relay) console.log('approve it now: touch the pad (or create the approval file in the emulator)')
        return {
            request: signRequest(p, info.chain_id.array, packed, a.key),
            state: {chainId: String(info.chain_id), transaction: hex(packed)},
        }
    })
    const chainId = Checksum256.from(state.chainId)
    const tx = Serializer.decode({data: unhex(state.transaction), type: Transaction})
    const {sig, signer} = checkSignature(reply(b), tx, chainId, a.key ? PublicKey.from(a.key) : undefined)
    console.log(`signature ${sig}`)
    console.log(`signed by ${signer}`)
    if (a.noBroadcast) return
    const result = await client.v1.chain.push_transaction(SignedTransaction.from({...tx, signatures: [sig]}))
    console.log(`accepted: transaction ${result.transaction_id}`)
    console.log(`block ${result.processed.block_num}, status ${result.processed.receipt?.status}`)
}

const args = parseArgs(process.argv.slice(2))
const commands = {'get-key': getKey, selftest, transfer, action}
const command = commands[args._[0]]
if (!command) {
    console.error('usage: antelope_client.mjs get-key | selftest | transfer | action ... (see the top of this file)')
    process.exit(2)
}
command(args).then(() => process.exit(0), (e) => {
    console.error(`FAILED: ${e.message}`)
    process.exit(1)
})
