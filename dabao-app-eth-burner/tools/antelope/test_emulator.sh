#!/bin/bash
# Run the signer in the emulator with a known seed and check its Antelope
# commands against @wharfkit/antelope (antelope_client.mjs selftest).
# Needs: ./build.sh emu done, xous-core next to ethereum-app, node and npm.
#   CARGO_TARGET_DIR  where ./build.sh put the binaries (default: ../../target)
set -e
here=$(cd "$(dirname "$0")" && pwd)
crate=$(cd "$here/../.." && pwd)
bin=${CARGO_TARGET_DIR:-$crate/target}/release
work=$(mktemp -d)
export ETH_BURNER_SEED=$work/seed.bin ETH_BURNER_APPROVE=$work/approve
export ETH_BURNER_PORT=${ETH_BURNER_PORT:-7611} ETH_BURNER_CONFIRM_MS=3000

cd "$here"
[ -d node_modules ] || npm install --no-audit --no-fund
# the seed file: 32 bytes of entropy, then "ETHBURN1" and the first 24 bytes of its SHA-256
node -e '
const {createHash} = require("crypto")
const entropy = Buffer.alloc(32, 0x5a)
const check = createHash("sha256").update(entropy).digest().subarray(0, 24)
require("fs").writeFileSync(process.argv[1], Buffer.concat([entropy, Buffer.from("ETHBURN1"), check]))
' "$ETH_BURNER_SEED"

cd "$crate/../../xous-core"
# xtask finds its outputs in xous-core/target, whatever CARGO_TARGET_DIR says
env -u CARGO_TARGET_DIR cargo xtask dabao-emu "$bin/eth-approver" "$bin/eth-burner" > "$work/emulator.log" 2>&1 &
emu=$!
trap 'kill $emu 2>/dev/null; pkill -P $emu 2>/dev/null; true' EXIT
for _ in $(seq 600); do
    grep -q "listening on 127.0.0.1:$ETH_BURNER_PORT" "$work/emulator.log" && break
    kill -0 $emu 2>/dev/null || { cat "$work/emulator.log"; echo "the emulator stopped"; exit 1; }
    sleep 1
done
grep -q "listening on" "$work/emulator.log" || { tail -30 "$work/emulator.log"; echo "the emulator didn't start"; exit 1; }

cd "$here"
node antelope_client.mjs selftest --tcp 127.0.0.1:$ETH_BURNER_PORT
