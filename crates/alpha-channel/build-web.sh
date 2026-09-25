#!/bin/sh
# Builds the package a page loads (JavaScript glue, typings and the .wasm) into <out-dir>, then
# prints the .wasm's SHA-256 and the revision it was built from, so anyone can rebuild it from a
# public commit and compare.
set -eu

out=${1:?usage: build-web.sh <out-dir>}
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

pin=$(sed -n 's/^wasm-bindgen = "=\(.*\)"$/\1/p' crates/alpha-channel/Cargo.toml)
have=$(wasm-bindgen --version | cut -d' ' -f2)
if [ "$pin" != "$have" ]; then
  echo "the wasm-bindgen CLI is $have but the crate pins $pin:" >&2
  echo "  cargo install wasm-bindgen-cli --version $pin --locked" >&2
  exit 1
fi

# Absolute paths end up in the binary; mapping them keeps the hash independent of the checkout.
RUSTFLAGS="--remap-path-prefix=$root=/src --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo" \
  cargo build -p alpha-channel --release --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir "$out" target/wasm32-unknown-unknown/release/alpha_channel.wasm
wasm="$out/alpha_channel_bg.wasm"
if command -v wasm-opt >/dev/null 2>&1; then
  wasm-opt -Oz --all-features "$wasm" -o "$wasm"
fi

hash=$( (sha256sum "$wasm" 2>/dev/null || shasum -a 256 "$wasm") | cut -d' ' -f1)
echo "sha256 $hash alpha_channel_bg.wasm"
echo "revision $(git rev-parse HEAD)"
