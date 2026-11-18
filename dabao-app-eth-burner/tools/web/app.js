import { Transaction, Signature, JsonRpcProvider, verifyMessage, parseEther, formatEther, getAddress, hexlify, getBytes, toUtf8Bytes }
  from "./vendor/ethers-6.13.4.min.js";

// ---------------------------------------------------------------- constants
const VID = 0x1d50, PID = 0x6197, USAGE_PAGE = 0xff00;
const TYPE_ERC4527 = 0x01, TYPE_CUSTOM = 0x02;
const CHAIN_ID = 11155111n;                       // Sepolia, and nothing else
const RPC = "https://ethereum-sepolia-rpc.publicnode.com";
const EXPLORER = "https://sepolia.etherscan.io";
const PATH = [44, true, 60, true, 0, true, 0, false, 0, false];   // m/44'/60'/0'/0/0
const APPROVE_SECONDS = 15;
const ERRORS = { 1: "not approved", 2: "invalid request", 3: "unsupported", 4: "busy", 5: "internal error", 6: "not ready" };

// ---------------------------------------------------------------- CBOR (the subset the signer uses)
export class Tag { constructor(tag, value) { this.tag = tag; this.value = value; } }

function head(major, n) {
  if (n < 24) return [major << 5 | n];
  if (n < 0x100) return [major << 5 | 24, n];
  if (n < 0x10000) return [major << 5 | 25, n >> 8, n & 255];
  if (n < 0x100000000) return [major << 5 | 26, n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
  throw new Error("integer too large for this encoder");
}

export function cborEncode(v) {
  if (typeof v === "boolean") return [v ? 0xf5 : 0xf4];
  if (typeof v === "number") return head(0, v);
  if (typeof v === "bigint") return head(0, Number(v));
  if (v instanceof Uint8Array) return [...head(2, v.length), ...v];
  if (typeof v === "string") { const b = toUtf8Bytes(v); return [...head(3, b.length), ...b]; }
  if (Array.isArray(v)) return [...head(4, v.length), ...v.flatMap(cborEncode)];
  if (v instanceof Map) return [...head(5, v.size), ...[...v].flatMap(([k, x]) => [...cborEncode(k), ...cborEncode(x)])];
  if (v instanceof Tag) return [...head(6, v.tag), ...cborEncode(v.value)];
  throw new Error("can't encode " + v);
}

export function cborDecode(b, i = 0) {
  const ib = b[i++], major = ib >> 5, ai = ib & 31;
  let n = ai;
  if (ai >= 24 && major !== 7) {
    const size = { 24: 1, 25: 2, 26: 4, 27: 8 }[ai];
    if (!size) throw new Error("unsupported CBOR");
    n = 0;
    for (let k = 0; k < size; k++) n = n * 256 + b[i++];
  }
  if (major === 0) return [n, i];
  if (major === 1) return [-1 - n, i];
  if (major === 2) return [b.slice(i, i + n), i + n];
  if (major === 3) return [new TextDecoder().decode(b.slice(i, i + n)), i + n];
  if (major === 4) { const out = []; for (let k = 0; k < n; k++) { let x; [x, i] = cborDecode(b, i); out.push(x); } return [out, i]; }
  if (major === 5) { const out = new Map(); for (let k = 0; k < n; k++) { let key, x; [key, i] = cborDecode(b, i); [x, i] = cborDecode(b, i); out.set(key, x); } return [out, i]; }
  if (major === 6) { let x; [x, i] = cborDecode(b, i); return [new Tag(n, x), i]; }
  if (ai === 20) return [false, i];
  if (ai === 21) return [true, i];
  if (ai === 22) return [null, i];
  throw new Error("unsupported CBOR");
}

const keypath = () => new Tag(304, new Map([[1, PATH]]));

export function customRequest(command, withPath = false) {
  const m = new Map([[1, command]]);
  if (withPath) m.set(2, keypath());
  return Uint8Array.from([TYPE_CUSTOM, ...cborEncode(m)]);
}

// ERC-4527 eth-sign-request. dataType: 3 = EIP-191 message, 4 = typed (EIP-1559) transaction.
export function signRequest(requestId, signData, dataType, chainId) {
  const m = new Map([[1, new Tag(37, requestId)], [2, signData], [3, dataType]]);
  if (chainId !== undefined) m.set(4, chainId);
  m.set(5, keypath());
  m.set(7, "dabao-web");
  return Uint8Array.from([TYPE_ERC4527, ...cborEncode(m)]);
}

// ---------------------------------------------------------------- the board, over WebHID
// Envelope: length (u32 BE) || type || message, cut into 64-byte reports.
class Board {
  constructor(device) {
    this.device = device; this.buf = []; this.waiter = null;
    device.addEventListener("inputreport", e => {
      this.buf.push(...new Uint8Array(e.data.buffer, e.data.byteOffset, e.data.byteLength));
      this.#deliver();
    });
  }
  #deliver() {
    if (!this.waiter || this.buf.length < 4) return;
    const n = ((this.buf[0] << 24) | (this.buf[1] << 16) | (this.buf[2] << 8) | this.buf[3]) >>> 0;
    if (this.buf.length < 4 + n) return;
    const body = Uint8Array.from(this.buf.slice(4, 4 + n));
    this.buf = [];
    const w = this.waiter; this.waiter = null; w(body);
  }
  async exchange(body, timeoutMs = 5000) {
    if (this.waiter) throw new Error("the board is still answering the previous request");
    this.buf = [];
    const frame = new Uint8Array(4 + body.length);
    new DataView(frame.buffer).setUint32(0, body.length);
    frame.set(body, 4);
    const reply = new Promise((resolve, reject) => {
      const t = setTimeout(() => { this.waiter = null; reject(new Error("the board did not answer in time")); }, timeoutMs);
      this.waiter = b => { clearTimeout(t); resolve(b); };
    });
    for (let off = 0; off < frame.length; off += 64) {
      const report = new Uint8Array(64);
      report.set(frame.subarray(off, off + 64));
      await this.device.sendReport(0, report);
    }
    return reply;
  }
  // Decoded reply: throws on an error-response.
  async ask(body, timeoutMs) {
    const r = await this.exchange(body, timeoutMs);
    const [m] = cborDecode(r, 1);
    if (r[0] === TYPE_CUSTOM && m.get(1) !== 0) {
      const e = new Error(`${ERRORS[m.get(1)] ?? "error " + m.get(1)}${m.get(6) ? ": " + m.get(6) : ""}`);
      e.code = m.get(1);
      throw e;
    }
    return { type: r[0], map: m };
  }
  // Ask for a signature and wait for the touch. Returns the 65 signature bytes.
  async sign(signData, dataType, chainId) {
    const requestId = crypto.getRandomValues(new Uint8Array(16));
    const { type, map } = await this.ask(signRequest(requestId, signData, dataType, chainId), (APPROVE_SECONDS + 6) * 1000);
    const echoed = map.get(1);
    if (type !== TYPE_ERC4527 || !(echoed instanceof Tag) || hexlify(echoed.value) !== hexlify(requestId)) {
      throw new Error("the reply doesn't belong to this request");
    }
    return map.get(2);
  }
}

// ---------------------------------------------------------------- bootloader check
// Boot stages that were rebuilt from the public source and compared with the official signed release.
// "code" is the SHA-512 of the stage without its signature block, "partition" that of the whole partition.
const VERIFICATION_RECORD = "https://github.com/BlockIndia-LLC/ethereum-app/blob/touch-confirm/dabao-app-eth-burner/docs/VERIFICATION.md";
export const KNOWN_BUILDS = [{
  version: "v0.10.0-61-g5397e1b48",
  baobit: "441559d7e1984623ec0a52f60f90240c740b6c41",
  boot0: {
    code: "563802e7f10fd0ca0a1c700c6313eff624aa57d9cd88d3c33af4b720eff5480432e01c116925a324a96e12d92953d7cb6076ea4557a22058e1a61be4c2b4dee2",
    partition: "a0680a73106600c4ece34f9393fc5c8eed4885e844b1b78b58fb3a8a299a885cd794c667a5e787083bce46bf7aff8d3f4affa6a93a38ba7b507bb0d47c70fa01",
  },
  boot1: {
    code: "e42b5aba61d98990ca24f5fc3b6cf012b14ea4d121f9bbe494baf4d9ae854d3ba88cdf26a288b88778826f816dc960c3ffe24b7c919108a3aca90f2dc4551a55",
    partition: "a12eb17f37c88e834bb7beef3f5163f232824e8044fcbab3bb37c6ac54d10f78d61ace96da9ebfc03e3cc9514312f22b18a9481747fc0526dc89733789db3927",
  },
  evidence: "rebuilt from source with baobit (GNU Guix) on 2026-11-17; equal to the official signed release v0.10.0",
}];

// The text printed by the bootloader's `audit` command, as fields.
export function parseAudit(text) {
  const line = re => (text.match(re) ?? [])[1]?.trim();
  const stage = n => ({
    code: line(new RegExp(`boot${n} code only:\\s*([0-9a-f]{128})`, "i")),
    partition: line(new RegExp(`boot${n} partition:\\s*([0-9a-f]{128})`, "i")),
    baobit: line(new RegExp(`boot${n} baobit toolchain:\\s*([0-9a-f]{40})`, "i")),
    key: line(new RegExp(`Boot${n}: key \\S+ \\(([^)]*)\\)`)),
  });
  const attacks = line(/Possible attack attempts:\s*(\d+)/);
  return {
    board: line(/Board type reads as:\s*(.+)/),
    version: line(/Semver is:\s*(\S+)/),
    stepping: line(/Stepping is:\s*(\S+)/),
    boot0: stage(0), boot1: stage(1),
    nextKey: line(/Next stage: key \S+ \(([^)]*)\)/),
    attacks: attacks === undefined ? undefined : Number(attacks),
    debugOff: /CM7 & debug confirmed fused off/.test(text),
    receiptsOk: /Boot1 receipts OK/.test(text),
    rollbackOk: /Boot1 anti-rollback OK/.test(text),
  };
}

// Compare an audit with the known builds. status: "ok", "bad" or "info".
export function checkAudit(a) {
  const rows = [];
  const add = (status, what, detail) => rows.push({ status, what, detail });
  const short = h => h ? `${h.slice(0, 16)}…${h.slice(-16)}` : "not reported";
  if (!a.boot0.code || !a.boot1.code) {
    return { verdict: "unreadable", rows: [{ status: "bad", what: "Audit output", detail: "The fingerprints could not be read from the bootloader's answer." }] };
  }
  const build = KNOWN_BUILDS.find(b => b.boot0.code === a.boot0.code || b.boot1.code === a.boot1.code || b.version === a.version);
  if (!build) {
    add("info", "Version", `${a.version ?? "unknown"} is not in this page's list of rebuilt versions.`);
    add("info", "boot0 code", short(a.boot0.code));
    add("info", "boot1 code", short(a.boot1.code));
    return { verdict: "unknown", rows };
  }
  let allMatch = true;
  for (const n of ["boot0", "boot1"]) {
    for (const part of ["code", "partition"]) {
      const good = a[n][part] === build[n][part];
      allMatch &&= good;
      add(good ? "ok" : "bad", `${n} ${part === "code" ? "code" : "whole partition"}`,
        good ? `${short(a[n][part])} equals the rebuilt image` : `${short(a[n][part])} differs from the rebuilt image ${short(build[n][part])}`);
    }
    if (a[n].baobit) add(a[n].baobit === build.baobit ? "ok" : "info", `${n} build recipe`, `baobit ${a[n].baobit.slice(0, 8)}`);
    if (a[n].key) add(a[n].key.trim() === "bao1" ? "ok" : "info", `${n} signed with`, `the "${a[n].key.trim()}" key`);
  }
  if (a.attacks !== undefined) add(a.attacks === 0 ? "ok" : "bad", "Attack attempts counted", String(a.attacks));
  add(a.debugOff ? "ok" : "info", "Debug access", a.debugOff ? "confirmed fused off" : "not confirmed off");
  if (a.nextKey) add("info", "Next stage (Xous) signed with", `the "${a.nextKey.trim()}" key${a.nextKey.trim() === "dev" ? ": a developer image, as this signer is" : ""}`);
  if (a.stepping) add("info", "Silicon", `stepping ${a.stepping}${a.stepping === "A0" ? " (pre-production)" : ""}`);
  return { verdict: allMatch ? "match" : "mismatch", build, rows };
}

// The bootloader's console, over Web Serial.
// A port the user already allowed is reused; otherwise the browser asks which one.
async function withBootloader(fn) {
  const allowed = (await navigator.serial.getPorts()).find(p => p.getInfo().usbVendorId === VID);
  const port = allowed ?? await navigator.serial.requestPort({ filters: [{ usbVendorId: VID }] });
  await port.open({ baudRate: 115200 });
  try {
    await port.setSignals({ dataTerminalReady: true, requestToSend: true });
    const writer = port.writable.getWriter(), reader = port.readable.getReader();
    const decoder = new TextDecoder();
    let pending = null;                       // one read at a time: a read that lost a race is kept
    // Send a command; collect the answer until `until` shows up or the line goes quiet.
    const command = async (cmd, until, maxMs = 8000) => {
      await writer.write(new TextEncoder().encode(cmd + "\r"));
      let text = "", quiet = 0;
      const end = Date.now() + maxMs;
      while (Date.now() < end) {
        pending ??= reader.read();
        const chunk = await Promise.race([pending, new Promise(r => setTimeout(() => r(null), 400))]);
        if (chunk === null) { if (text && ++quiet >= 4) break; continue; }
        pending = null;
        if (chunk.done) break;
        quiet = 0; text += decoder.decode(chunk.value, { stream: true });
        if (until && until.test(text)) break;
      }
      return text;
    };
    try { return await fn(command); }
    finally { await reader.cancel().catch(() => {}); reader.releaseLock(); writer.releaseLock(); }
  } finally { await port.close().catch(() => {}); }
}

// ---------------------------------------------------------------- page
const $ = id => document.getElementById(id);
const log = s => { $("log").textContent += `[${new Date().toLocaleTimeString()}] ${s}\n`; $("log").scrollTop = 1e9; };
const provider = new JsonRpcProvider(RPC, Number(CHAIN_ID), { staticNetwork: true });
let board = null, address = null, signedTx = null, metering = false;

function setOut(id, html) { $(id).innerHTML = html; }
const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function enable(on) {
  for (const id of ["s-message", "s-tx", "s-meter"]) on ? $(id).removeAttribute("disabled") : $(id).setAttribute("disabled", "");
  $("info").hidden = !on;
  $("b-to-boot").disabled = !on;
}

async function withTouch(fn) {
  const end = Date.now() + APPROVE_SECONDS * 1000;
  const tick = () => { $("touch-left").textContent = `${Math.max(0, Math.ceil((end - Date.now()) / 1000))} seconds left. Keep your finger off until now, then touch and hold for a second.`; };
  tick(); $("touch").classList.add("on");
  const timer = setInterval(tick, 250);
  try { return await fn(); } finally { clearInterval(timer); $("touch").classList.remove("on"); }
}

async function refreshBalance() {
  try { $("i-balance").textContent = formatEther(await provider.getBalance(address)) + " ETH"; }
  catch (e) { $("i-balance").textContent = "couldn't reach the Sepolia node"; }
}

async function connect() {
  const [device] = await navigator.hid.requestDevice({ filters: [{ vendorId: VID, productId: PID, usagePage: USAGE_PAGE }] });
  if (device) await attach(device);
}

// After the signer restarts, a board the user already allowed is picked up again without a dialog.
async function reattach() {
  if (board) return;
  const device = (await navigator.hid.getDevices()).find(d => d.vendorId === VID && d.productId === PID);
  if (device) await attach(device);
}

async function attach(device) {
  if (!device.opened) await device.open();
  board = new Board(device);
  log(`connected to "${device.productName}"`);
  const version = (await board.ask(customRequest(2))).map.get(5);
  const info = (await board.ask(customRequest(1, true))).map;
  address = getAddress(info.get(3));
  $("i-version").textContent = version;
  $("i-address").textContent = address;
  $("i-explorer").innerHTML = `<a href="${EXPLORER}/address/${address}" target="_blank" rel="noopener">${EXPLORER.replace("https://", "")}/address/…</a>`;
  // Which of the signer's two processes can reach the keystore (0.5.0 and later).
  try { $("i-keystore").textContent = (await board.ask(customRequest(5))).map.get(6) ?? "–"; }
  catch (e) { $("i-keystore").textContent = "not reported by this signer version"; }
  if (!$("t-to").value) $("t-to").value = address;
  enable(true);
  log(`signer ${version}, address ${address}`);
  refreshBalance();
}

async function toBootloader() {
  setOut("c-out", "Asking the signer to restart…");
  await board.ask(customRequest(4), 4000);
  log("the signer is restarting into the bootloader");
  setOut("c-out", "The board is restarting into its bootloader. Give it a few seconds, then click \"Read and check\".");
}

async function checkBoard() {
  setOut("c-out", "Reading the bootloader's audit…");
  let text;
  try {
    text = await withBootloader(command => command("audit", /anti-rollback/i));
  } catch (e) {
    setOut("c-out", `<span class="bad">Could not read the bootloader.</span> ${esc(e.message)}\nIs the board in its bootloader (a drive named BAOCHIP shows up)?`);
    log(`check failed: ${e.message}`);
    return;
  }
  const audit = parseAudit(text), result = checkAudit(audit);
  const mark = { ok: ["✓", "ok"], bad: ["✗", "bad"], info: ["·", "note"] };
  const verdicts = {
    match: `<span class="verdict ok">The bootloader matches the published source.</span>\nBoth stages equal build ${esc(result.build?.version)}, ${esc(result.build?.evidence)}.`,
    mismatch: `<span class="verdict bad">The bootloader does NOT match the rebuilt images.</span>\nDon't trust this board with a key until you know why.`,
    unknown: `<span class="verdict">This bootloader version isn't in this page's list.</span>\nThat is not a failure: nobody has recorded a rebuild of it here yet. The verification record explains how to rebuild and compare.`,
    unreadable: `<span class="verdict bad">The answer could not be understood.</span>`,
  };
  setOut("c-out", `${verdicts[result.verdict]}\n` +
    `<table class="check">${result.rows.map(r => `<tr><td class="${mark[r.status][1]}">${mark[r.status][0]}</td><td>${esc(r.what)}</td><td class="mono">${esc(r.detail)}</td></tr>`).join("")}</table>` +
    `<span class="note">What this can't show: the fingerprints are reported by the chip itself, so a dishonest factory step would not be caught. ` +
    `<a href="${VERIFICATION_RECORD}" target="_blank" rel="noopener">How the rebuild was done, and its limits</a>.</span>`);
  log(`bootloader check: ${result.verdict}${audit.version ? " (" + audit.version + ")" : ""}`);
  $("b-to-signer").disabled = false;
}

async function toSigner() {
  setOut("c-out", $("c-out").innerHTML + "\nStarting the signer…");
  try { await withBootloader(command => command("boot", null, 1500)); } catch (e) { log(`start signer: ${e.message}`); }
  $("b-to-signer").disabled = true;
  log("asked the bootloader to start the signer");
  for (let i = 0; i < 20 && !board; i++) { await new Promise(r => setTimeout(r, 1000)); await reattach().catch(() => {}); }
  log(board ? "the signer is back" : "the signer did not come back by itself: click Connect");
}

async function signMessage() {
  const text = $("m-text").value;
  setOut("m-out", "Waiting for the touch…");
  try {
    const sig = await withTouch(() => board.sign(toUtf8Bytes(text), 3));
    const signer = verifyMessage(text, hexlify(sig));
    const good = signer === address;
    setOut("m-out", `<span class="${good ? "ok" : "bad"}">${good ? "Signed, and the signature checks out." : "Signed, but the signer is not this board!"}</span>\n` +
      `Recovered signer: <span class="mono">${esc(signer)}</span>\nSignature: <span class="mono">${esc(hexlify(sig))}</span>`);
    log(`message signed; recovered signer ${signer}`);
  } catch (e) {
    setOut("m-out", `<span class="bad">Not signed.</span> ${esc(e.message)}`);
    log(`message not signed: ${e.message}`);
  }
}

async function signTx() {
  signedTx = null; $("b-broadcast").disabled = true;
  try {
    const to = getAddress($("t-to").value.trim());
    const value = parseEther($("t-amount").value.trim());
    setOut("t-out", "Reading the nonce and fees from Sepolia…");
    const [nonce, block] = await Promise.all([provider.getTransactionCount(address, "pending"), provider.getBlock("latest")]);
    const tip = 1_000_000_000n;                                   // 1 gwei
    const tx = Transaction.from({
      type: 2, chainId: CHAIN_ID, nonce, to, value, gasLimit: 21000n,
      maxPriorityFeePerGas: tip, maxFeePerGas: tip + 2n * (block.baseFeePerGas ?? 0n) + 1_000_000_000n,
    });
    setOut("t-out", `Asking the board to sign:\n  send ${esc(formatEther(value))} Sepolia ETH\n  to <span class="mono">${esc(to)}</span>\n  nonce ${nonce}, at most ${esc(formatEther(tx.maxFeePerGas * tx.gasLimit))} ETH in fees\nWaiting for the touch…`);
    const sig = await withTouch(() => board.sign(getBytes(tx.unsignedSerialized), 4, CHAIN_ID));
    tx.signature = Signature.from({ r: hexlify(sig.slice(0, 32)), s: hexlify(sig.slice(32, 64)), yParity: sig[64] });
    const good = tx.from === address;
    if (good) { signedTx = tx; $("b-broadcast").disabled = false; }
    setOut("t-out", `<span class="${good ? "ok" : "bad"}">${good ? "Signed, and the signature checks out." : "Signed, but the signer is not this board!"}</span>\n` +
      `Recovered sender: <span class="mono">${esc(tx.from)}</span>\nTransaction hash: <span class="mono">${esc(tx.hash)}</span>\n` +
      `Raw transaction: <span class="mono">${esc(tx.serialized)}</span>\n${good ? "Nothing has been sent yet. Broadcast it to put it on Sepolia." : ""}`);
    log(`transaction signed; hash ${tx.hash}`);
  } catch (e) {
    setOut("t-out", `<span class="bad">Not signed.</span> ${esc(e.shortMessage ?? e.message)}`);
    log(`transaction not signed: ${e.message}`);
  }
}

async function broadcast() {
  if (!signedTx) return;
  $("b-broadcast").disabled = true;
  try {
    const sent = await provider.broadcastTransaction(signedTx.serialized);
    $("t-out").innerHTML += `\n<span class="ok">Broadcast.</span> <a href="${EXPLORER}/tx/${sent.hash}" target="_blank" rel="noopener">View it on Sepolia Etherscan</a> (it can take half a minute to appear).`;
    log(`broadcast ${sent.hash}`);
    signedTx = null;
    setTimeout(refreshBalance, 20000);
  } catch (e) {
    $("t-out").innerHTML += `\n<span class="bad">Broadcast failed.</span> ${esc(e.shortMessage ?? e.message)}`;
    log(`broadcast failed: ${e.message}`);
    $("b-broadcast").disabled = false;
  }
}

async function meter() {
  metering = !metering;
  $("b-meter").textContent = metering ? "Stop meter" : "Start meter";
  while (metering && board) {
    try {
      const text = (await board.ask(customRequest(3), 3000)).map.get(6) ?? "";
      const m = text.match(/(\d+) (\d+)\s*$/);
      if (!m) { $("meter-val").textContent = text; break; }
      const hi = Number(m[2]);
      $("meter-val").textContent = `${m[1]} … ${m[2]}${hi > 54 ? "  touch" : ""}`;
      document.querySelector("#meter > div").style.width = Math.min(100, Math.max(0, (hi - 45) / 1.6)) + "%";
    } catch (e) { log(`meter: ${e.message}`); break; }
  }
  metering = false; $("b-meter").textContent = "Start meter";
}

function guard(fn) {
  return async () => { try { await fn(); } catch (e) { log(`error: ${e.message}`); } };
}

if (!("hid" in navigator)) {
  $("support").hidden = false; $("b-connect").disabled = true;
} else {
  $("b-connect").onclick = guard(connect);
  $("b-sign-msg").onclick = guard(signMessage);
  $("b-sign-tx").onclick = guard(signTx);
  $("b-broadcast").onclick = guard(broadcast);
  $("b-meter").onclick = guard(meter);
  $("b-to-boot").onclick = guard(toBootloader);
  navigator.hid.addEventListener("connect", () => reattach().catch(() => {}));
  if ("serial" in navigator) {
    $("b-check").onclick = guard(checkBoard);
    $("b-to-signer").onclick = guard(toSigner);
  } else {
    $("serial-support").hidden = false; $("b-check").disabled = true;
  }
  navigator.hid.addEventListener("disconnect", e => {
    if (board && e.device === board.device) { board = null; metering = false; enable(false); log("the board was disconnected"); }
  });
}

// Known-answer checks, with a request, a reply and a transaction captured from a real board.
// Nothing is sent anywhere. Run `dabao.selfTest()` in the console: every value should be true.
export function selfTest() {
  const hex = u => [...u].map(b => b.toString(16).padStart(2, "0")).join("");
  const un = h => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));
  const A = "0xb684148F96CE2FC06db8674403aB65FE33452d95";
  const out = {};
  out.getVersion = hex(customRequest(2)) === "02a10102";
  out.getAddress = hex(customRequest(1, true)) === "02a2010102d90130a1018a182cf5183cf500f500f400f4";
  const [v] = cborDecode(un("02a201000565302e312e30"), 1);
  out.decodeVersion = v.get(1) === 0 && v.get(5) === "0.1.0";
  const tx = Transaction.from({ type: 2, chainId: CHAIN_ID, nonce: 0, to: A, value: 10n ** 14n, gasLimit: 21000n,
    maxPriorityFeePerGas: 10n ** 9n, maxFeePerGas: 2n * 10n ** 9n });
  out.unsignedTx = tx.unsignedSerialized === "0x02f083aa36a780843b9aca00847735940082520894b684148f96ce2fc06db8674403ab65fe33452d95865af3107a400080c0";
  const [reply] = cborDecode(un("01a201d825509549ed7df1969010b6f902523f9798e702584112d1ac4de159e6206ffd9f7327c4bd3c894e9a7758b4f0088b53324a39473aa80c4f1a754d13c0de726aabe86bf2e5d420a619b8329c621e35f84e2a023b26f501"), 1);
  const sig = reply.get(2);
  tx.signature = Signature.from({ r: hexlify(sig.slice(0, 32)), s: hexlify(sig.slice(32, 64)), yParity: sig[64] });
  out.txSigner = tx.from === A;
  out.txHash = tx.hash === "0xdd4a2bfe3d43b7757218c0c065b9a6da3c3ac6c1536d0fe2f421af15e7835b84";
  out.messageSigner = verifyMessage("Hello", "0x28a71fa470568138dcde29d76cad16f822d9ef7771037c4dc138437602293cc52eb1b196a4c571821b66a4d7eb5e37c59fd1f5e6f3b28b2f2c388601e01eaad71c") === A;
  out.all = Object.values(out).every(Boolean);
  return out;
}
// For tests in the console: the encoders are pure functions.
window.dabao = { cborEncode, cborDecode, customRequest, signRequest, Tag, hexlify, parseAudit, checkAudit, KNOWN_BUILDS, selfTest };
