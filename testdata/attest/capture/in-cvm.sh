#!/bin/sh
# Runs inside a Phala dstack CVM container with /var/run/dstack.sock mounted.
# Produces the golden capture: two quotes bound to the same fresh P-256 key
# (one Instance-shaped, one KMS-node-shaped), the event log, and the capture time.
set -eu
apk add --no-cache openssl curl jq python3 >/dev/null
OUT=/capture; mkdir -p "$OUT"; cd "$OUT"

openssl ecparam -name prime256v1 -genkey -noout -out runtime.key.pem
openssl ec -in runtime.key.pem -pubout -outform DER -out runtime_spki.der 2>/dev/null
head -c 32 /dev/urandom > nonce.bin
head -c 1216 /dev/urandom > node_xwing_spki.der

first_half=$(cat runtime_spki.der nonce.bin | openssl dgst -sha256 -binary | od -An -v -tx1 | tr -d ' \n')
zeros=$(printf '%064d' 0)
node_half=$(openssl dgst -sha256 -binary node_xwing_spki.der | od -An -v -tx1 | tr -d ' \n')

for kind in instance node; do
  if [ "$kind" = instance ]; then rd="$first_half$zeros"; else rd="$first_half$node_half"; fi
  printf '%s' "$rd" > "report_data.$kind.hex"
  curl -sf --unix-socket /var/run/dstack.sock "http://dstack/GetQuote?report_data=0x$rd" > "getquote.$kind.json"
  jq -r .quote "getquote.$kind.json" | sed 's/^0x//' > "quote.$kind.hex"
  jq -r .event_log "getquote.$kind.json" > "event_log.$kind.json"
  date -u +%Y-%m-%dT%H:%M:%SZ > "captured_at.$kind.txt"
done

curl -sf --unix-socket /var/run/dstack.sock http://dstack/Info > info.json
cp /run/log/dstack/* . 2>/dev/null || true
rm -f runtime.key.pem
ls -l "$OUT"
exec python3 -m http.server 8080 --directory "$OUT"
