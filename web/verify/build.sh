#!/bin/sh
# Builds the verify page into <out-dir>: index.html and the glue, wasm, page script and stylesheet
# under content-addressed names. index.html pins the scripts and the stylesheet by SRI and the page
# script pins the wasm, so the SHA-256 of index.html (printed as bundle_sha256) covers every byte
# the page runs. PLATFORM_DOCUMENT_URL is where the page reads the signed platform document;
# FEATURES=dev compiles in the dev stand's release key, as for build-web.sh.
set -eu
LC_ALL=C
export LC_ALL

out=${1:?usage: build.sh <out-dir>}
platform=${PLATFORM_DOCUMENT_URL:?set PLATFORM_DOCUMENT_URL}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

case $platform in https://*) ;; *) echo "PLATFORM_DOCUMENT_URL is not https" >&2; exit 1 ;; esac

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
place() {
  name="$2-$(hex "$1" | cut -c1-16).$3"
  cp "$1" "$out/$name"
  printf '%s' "$name"
}
unfilled() {
  if grep -q '@[A-Z_0-9]*@' "$1"; then
    echo "a placeholder is left in $1" >&2
    exit 1
  fi
}

glue=$(place "$tmp/pkg/alpha_channel.js" alpha_channel js)
wasm=$(place "$tmp/pkg/alpha_channel_bg.wasm" alpha_channel_bg wasm)
style=$(place "$here/style.css" style css)
revision=$(git -C "$root" rev-parse HEAD)

sed -e "s|@WASM_URL@|$wasm|" -e "s|@WASM_SRI@|$(sri "$out/$wasm")|" \
  -e "s|@WASM_SHA256@|$(hex "$out/$wasm")|" -e "s|@REVISION@|$revision|" \
  -e "s|@PLATFORM_URL@|$platform|" \
  "$here/page.js" > "$tmp/page.js"
unfilled "$tmp/page.js"
page=$(place "$tmp/page.js" page js)

sed -e "s|@STYLE_NAME@|$style|" -e "s|@STYLE_SRI@|$(sri "$out/$style")|" \
  -e "s|@GLUE_NAME@|$glue|" -e "s|@GLUE_SRI@|$(sri "$out/$glue")|" \
  -e "s|@PAGE_NAME@|$page|" -e "s|@PAGE_SRI@|$(sri "$out/$page")|" \
  "$here/index.html.in" > "$out/index.html"
unfilled "$out/index.html"

echo "wasm_sha256 sha256:$(hex "$out/$wasm")"
echo "bundle_sha256 sha256:$(hex "$out/index.html")"
echo "revision $revision$(git -C "$root" diff --quiet HEAD || echo -dirty)"
