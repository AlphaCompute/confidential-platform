#!/bin/sh
# Serves a built bundle with its headers and loads it in headless Chrome. The test platform
# document verifies but names no signer, so a page that ran through its SRI chain, the wasm and
# the release-key check ends on the signer refusal; with one byte of the page script changed, SRI
# must stop it before that. Usage: smoke.sh <dist>.
set -eu
LC_ALL=C
export LC_ALL

dist=$(cd "${1:?usage: smoke.sh <dist>}" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
platform="$root/testdata/channel/platform-document.json"
sentence="This page is not served from an AlphaCompute signer address."
ticket=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

chrome=${CHROME:-}
if [ -z "$chrome" ]; then
  for c in google-chrome chromium "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
    if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then
      chrome=$c
      break
    fi
  done
fi
[ -n "$chrome" ] || { echo "no Chrome found; set CHROME" >&2; exit 1; }

tmp=$(mktemp -d)
pids=
cleanup() {
  for p in $pids; do kill "$p" 2>/dev/null || true; done
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

fail() {
  echo "smoke: $*" >&2
  exit 1
}

# Starts serve.py for <dist> on a free port and sets $port.
serve() {
  port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
  python3 "$here/serve.py" "$1" "$port" "$platform" >/dev/null 2>&1 &
  pids="$pids $!"
  tries=0
  until curl -s -o /dev/null "http://127.0.0.1:$port/sign/approve"; do
    tries=$((tries + 1))
    [ "$tries" -lt 50 ] || fail "the server on $port did not start"
    sleep 0.1
  done
}

# Writes the DOM of /sign/approve#<ticket>, once the page has run, to <file>.
render() {
  profile=$(mktemp -d "$tmp/profile.XXXXXX")
  python3 "$here/render.py" "$chrome" "$profile" "http://127.0.0.1:$1/sign/approve#$ticket" > "$2"
}

# Requires every line of the bundle's headers file, and <type>, on the reply to HEAD <path>.
has_headers() {
  curl -sI "http://127.0.0.1:$1$2" | tr -d '\r' > "$tmp/reply"
  head -n 1 "$tmp/reply" | grep -q " $3 " || fail "$2 is not $3"
  while IFS= read -r line; do
    grep -qxF "$line" "$tmp/reply" || fail "$2 lacks: $line"
  done < "$dist/headers"
  [ -z "$4" ] || grep -qix "content-type: $4" "$tmp/reply" || fail "$2 is not $4"
}

serve "$dist"
wasm=$(cd "$dist" && ls alpha_channel_bg-*.wasm)
has_headers "$port" /sign/approve 200 "text/html; charset=utf-8"
has_headers "$port" /sign/claim 200 "text/html; charset=utf-8"
has_headers "$port" "/sign/$wasm" 200 application/wasm
has_headers "$port" /sign/ 404 ""
has_headers "$port" /sign/nope.js 404 ""

render "$port" "$tmp/good.html"
grep -qF "$sentence" "$tmp/good.html" || {
  cat "$tmp/good.html" >&2
  fail "the bundle did not reach the signer refusal"
}

cp -R "$dist" "$tmp/tampered"
page=$(cd "$tmp/tampered" && ls page-*.js)
sed 's/went wrong/went wronG/' "$tmp/tampered/$page" > "$tmp/page.js"
cmp -s "$tmp/page.js" "$tmp/tampered/$page" && fail "the tamper changed nothing"
cp "$tmp/page.js" "$tmp/tampered/$page"
serve "$tmp/tampered"
render "$port" "$tmp/tampered.html"
if grep -qF "$sentence" "$tmp/tampered.html"; then
  fail "a page script that does not match its integrity attribute ran"
fi

echo SMOKE_OK
