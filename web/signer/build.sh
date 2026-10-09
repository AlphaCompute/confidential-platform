#!/bin/sh
# Builds the signer page into <out-dir>: index.html, headers, and the glue, wasm, page script and
# stylesheet under content-addressed names. index.html pins the scripts and the stylesheet by SRI,
# and the page script pins the wasm, so the SHA-256 of index.html (printed as bundle_sha256) covers
# every byte the page runs.
set -eu
LC_ALL=C
export LC_ALL

out=${1:?usage: build.sh <out-dir>}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

command -v openssl >/dev/null || { echo "build.sh needs openssl" >&2; exit 1; }

mkdir -p "$out"
if [ -n "$(ls -A "$out")" ]; then
  echo "$out is not empty" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

"$root/crates/alpha-channel/build-web.sh" "$tmp/pkg" no-modules >&2

hex() { (sha256sum "$1" 2>/dev/null || shasum -a 256 "$1") | cut -d' ' -f1; }
sri() { printf 'sha256-%s' "$(openssl dgst -sha256 -binary "$1" | openssl base64 -A)"; }
# Copies <file> to <stem>-<first 16 hex of its SHA-256>.<ext> in $out and prints that name.
place() {
  name="$2-$(hex "$1" | cut -c1-16).$3"
  cp "$1" "$out/$name"
  printf '%s' "$name"
}
unfilled() {
  if grep -q '@[A-Z_]*@' "$1"; then
    echo "a placeholder is left in $1" >&2
    exit 1
  fi
}

glue=$(place "$tmp/pkg/alpha_channel.js" alpha_channel js)
wasm=$(place "$tmp/pkg/alpha_channel_bg.wasm" alpha_channel_bg wasm)
style=$(place "$here/style.css" style css)

sed -e "s|@WASM_URL@|$wasm|" -e "s|@WASM_SRI@|$(sri "$out/$wasm")|" "$here/page.js" > "$tmp/page.js"
unfilled "$tmp/page.js"
page=$(place "$tmp/page.js" page js)

sed -e "s|@STYLE_NAME@|$style|" -e "s|@STYLE_SRI@|$(sri "$out/$style")|" \
  -e "s|@GLUE_NAME@|$glue|" -e "s|@GLUE_SRI@|$(sri "$out/$glue")|" \
  -e "s|@PAGE_NAME@|$page|" -e "s|@PAGE_SRI@|$(sri "$out/$page")|" \
  "$here/index.html.in" > "$out/index.html"
unfilled "$out/index.html"
cp "$here/headers" "$out/headers"

echo "bundle_sha256 sha256:$(hex "$out/index.html")"
echo "revision $(git -C "$root" rev-parse HEAD)$(git -C "$root" diff --quiet HEAD || echo -dirty)"
