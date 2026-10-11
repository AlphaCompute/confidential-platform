#!/usr/bin/env bash
# check.sh against stand-ins for curl and alpha on PATH, with no network and no wait between
# rounds: the variable guards, the retry, and what each check reports and runs. Needs bash and jq.
set -u -o pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"

# Each stand-in logs its arguments (and stdin, for curl's -K -) and answers call N from the files
# <name>.N: .code holds its exit status (0 when absent), .out its stdout and .err its stderr.
for name in curl alpha; do
  cat >"$work/bin/$name" <<EOF
#!/usr/bin/env bash
n=\$(( \$(cat "$work/$name.calls" 2>/dev/null || echo 0) + 1 ))
echo "\$n" >"$work/$name.calls"
printf '%s\n' "\$*" >>"$work/$name.log"
case " \$* " in *" -K - "*) cat >>"$work/$name.log" ;; esac
prev=
for arg in "\$@"; do
  [ "\$prev" != --cacert ] || cat "\$arg" >>"$work/$name.log"
  prev=\$arg
done
[ ! -f "$work/$name.\$n.out" ] || cat "$work/$name.\$n.out"
[ ! -f "$work/$name.\$n.err" ] || cat "$work/$name.\$n.err" >&2
exit "\$(cat "$work/$name.\$n.code" 2>/dev/null || echo 0)"
EOF
  chmod +x "$work/bin/$name"
done

failures=0
out=""
status=0

# reply NAME N CODE [STDOUT [STDERR]]
reply() {
  echo "$3" >"$work/$1.$2.code"
  [ $# -lt 4 ] || [ -z "$4" ] || printf '%s\n' "$4" >"$work/$1.$2.out"
  [ $# -lt 5 ] || printf '%s\n' "$5" >"$work/$1.$2.err"
}

# run [VAR=value...] COMMAND...: in a clean environment with the stand-ins first on PATH; sets
# out and status. The replies for it are written between reset and run.
run() {
  out=$(env -i PATH="$work/bin:$PATH" HOME="$work" STAND_RETRY_SECONDS=0 "$@" 2>&1)
  status=$?
}

reset() {
  rm -f "$work"/curl.* "$work"/alpha.*
}

ok() {
  echo "ok   $1"
}

bad() {
  echo "FAIL $1"
  echo "     status $status, output:"
  printf '%s\n' "$out" | sed 's/^/     | /'
  failures=$((failures + 1))
}

expect() { # expect NAME STATUS [SUBSTRING...]: status equals, output holds every substring
  local name=$1 want=$2 s
  shift 2
  if [ "$status" != "$want" ]; then
    bad "$name (status)"
    return
  fi
  for s in "$@"; do
    if [[ $out != *"$s"* ]]; then
      bad "$name (no \"$s\")"
      return
    fi
  done
  ok "$name"
}

refute() { # refute NAME SUBSTRING: the output does not hold it
  if [[ $out == *"$2"* ]]; then bad "$1 (has \"$2\")"; else ok "$1"; fi
}

that() { # that NAME COMMAND...: the command succeeds
  local name=$1
  shift
  if "$@"; then ok "$name"; else bad "$name"; fi
}

has() { # has TEXT SUBSTRING
  [[ $1 == *"$2"* ]]
}

lacks() { # lacks TEXT SUBSTRING
  [[ $1 != *"$2"* ]]
}

log() {
  cat "$work/$1.log" 2>/dev/null
}

calls() {
  cat "$work/$1.calls" 2>/dev/null || echo 0
}

serving='{"instances":[{"id":"i1","state":"running","serving":true}]}'
stopped='{"instances":[{"id":"i1","state":"running","serving":false}]}'
proto=(STAND_SHROUD_URL=https://shroud.example/ STAND_LIST_KEY=sk_test STAND_APPS="app-a app-b")

# --- the mode and the subcommand --------------------------------------------------------------
reset
run STAND_TARGET=Owned "${proto[@]}" bash "$here/check.sh" prototype
expect "a misspelt STAND_TARGET is refused" 1 '::error::STAND_TARGET is "Owned"'
reset
run bash "$here/check.sh"
expect "no subcommand is a usage error" 2 "usage:"

# --- prototype ----------------------------------------------------------------------------------
for apps in "" " " $'\n\t '; do
  reset
  run STAND_SHROUD_URL=https://shroud.example STAND_LIST_KEY=sk_test STAND_APPS="$apps" \
    bash "$here/check.sh" prototype
  expect "a blank STAND_APPS ($(printf '%q' "$apps")) is refused" 1 "::error::STAND_APPS names no App"
done
reset
run STAND_LIST_KEY=sk_test STAND_APPS=app-a bash "$here/check.sh" prototype
expect "an unset STAND_SHROUD_URL is refused" 1 "::error::STAND_SHROUD_URL names no shroud-go"
reset
run STAND_SHROUD_URL=https://shroud.example STAND_APPS=app-a bash "$here/check.sh" prototype
expect "an empty STAND_LIST_KEY is refused" 1 "::error::STAND_LIST_KEY is empty"

reset
reply curl 1 0 "$serving"
reply curl 2 0 "$serving"
run "${proto[@]}" bash "$here/check.sh" prototype
expect "every copy serving passes in one round" 0
that "one list per App" [ "$(calls curl)" = 2 ]
that "the first list URL is app-a's" has "$(log curl)" "https://shroud.example/v1/apps/app-a/instances"
that "the second list URL is app-b's" has "$(log curl)" "https://shroud.example/v1/apps/app-b/instances"
that "the key goes on stdin" has "$(log curl)" 'header = "Authorization: Bearer sk_test"'
that "the key is not an argument" lacks "$(log curl)" "Bearer sk_test -"

reset
reply curl 1 0 "$serving"
reply curl 2 0 "$serving"
run STAND_TARGET=both "${proto[@]}" bash "$here/check.sh" prototype
expect "STAND_TARGET=both still runs the prototype check" 0
that "  and lists every App" [ "$(calls curl)" = 2 ]

reset
reply curl 1 0 "$stopped"
reply curl 2 0 "$serving"
reply curl 3 0 "$serving"
reply curl 4 0 "$serving"
run "${proto[@]}" bash "$here/check.sh" prototype
expect "a copy back within the retry passes" 0 'app-a: [{"id":"i1","state":"running","serving":false}]'
refute "a first-round finding is not an error" "::error::"

reset
reply curl 1 0 "$serving"
reply curl 2 22 "" "curl: (22) The requested URL returned error: 503"
reply curl 3 0 "$serving"
reply curl 4 22 "" "curl: (22) The requested URL returned error: 503"
run "${proto[@]}" bash "$here/check.sh" prototype
expect "a list that fails twice fails the check" 1 "::error::app-b: the list did not answer"
that "the first round is reported plainly" has "$out" $'app-b: the list did not answer\n'
refute "a serving App is not reported" "app-a"

reset
reply curl 1 0 '{"instances":[]}'
reply curl 2 0 '{"instances":[]}'
run STAND_SHROUD_URL=https://shroud.example STAND_LIST_KEY=sk_test STAND_APPS=app-a \
  bash "$here/check.sh" prototype
expect "an App with no copies is not serving" 1 "::error::app-a: []"

# --- owned --------------------------------------------------------------------------------------
app="https://broker.example=sha256:$(printf 'a%.0s' {1..64})"
owned=(STAND_ALPHA=alpha STAND_PLATFORM_DOCUMENT_URL=https://release.example/platform.json
  STAND_KMS_ENDPOINTS="https://kms-a.example:8443 https://kms-b.example:8443"
  STAND_APP_ENDPOINTS="$app")
for var in STAND_PLATFORM_DOCUMENT_URL STAND_KMS_ENDPOINTS STAND_APP_ENDPOINTS STAND_ALPHA; do
  reset
  run "${owned[@]}" "$var= " bash "$here/check.sh" owned
  expect "a blank $var is refused" 1 "::error::$var "
  that "  and nothing is probed" [ "$(calls alpha)" = 0 ]
done

reset
reply alpha 1 0 '{"kms":[],"apps":[]}'
run "${owned[@]}" bash "$here/check.sh" owned
expect "a probe that passes passes" 0
that "the probe gets the document and both lists" [ "$(log alpha)" = "--platform-document-url \
https://release.example/platform.json probe --kms https://kms-a.example:8443 \
https://kms-b.example:8443 --app $app" ]

report='{"kms":[{"target":"https://kms-a.example:8443","state":"ready","serving":true},
{"target":"https://kms-b.example:8443","state":"sealed","serving":false,"finding":"https://kms-b.example:8443: sealed"}],
"apps":[{"target":"https://broker.example","state":"silent","serving":false,"finding":"https://broker.example: no leaf from the KMS CA"}]}'
reset
reply alpha 1 1 "$report"
reply alpha 2 1 "$report"
run "${owned[@]}" bash "$here/check.sh" owned
expect "a target down twice fails the check" 1 \
  $'https://kms-b.example:8443: sealed\nhttps://broker.example: no leaf from the KMS CA\n::error::https://kms-b.example:8443: sealed\n::error::https://broker.example: no leaf from the KMS CA'
refute "a serving node is not reported" "kms-a"

reset
reply alpha 1 1 "$report"
reply alpha 2 0 '{"kms":[],"apps":[]}'
run "${owned[@]}" bash "$here/check.sh" owned
expect "a target back within the retry passes" 0 "https://kms-b.example:8443: sealed"
refute "  without an error" "::error::"

reset
reply alpha 1 1 "" "alpha: platform document fetch: connection refused"
reply alpha 2 1 "" "alpha: platform document fetch: connection refused"
run "${owned[@]}" bash "$here/check.sh" owned
expect "a probe that stops before its report says why" 1 \
  "::error::alpha: platform document fetch: connection refused"

reset
reply alpha 1 2
reply alpha 2 2
run "${owned[@]}" bash "$here/check.sh" owned
expect "a probe that says nothing is still a failure" 1 "::error::alpha probe failed and said nothing"

# --- site ---------------------------------------------------------------------------------------
site=(STAND_SITE_RUNNER=alpha-site1 STAND_PCCS_URL=https://pccs.site1.example:8081/
  STAND_SITE_CA_PEM=$'-----BEGIN CERTIFICATE-----\nsite\n-----END CERTIFICATE-----')
for var in STAND_SITE_RUNNER STAND_PCCS_URL STAND_SITE_CA_PEM; do
  reset
  run "${site[@]}" "$var=" bash "$here/check.sh" site
  expect "an empty $var is refused" 1 "::error::$var "
  that "  and nothing is asked" [ "$(calls curl)" = 0 ]
done

reset
run "${site[@]}" bash "$here/check.sh" site
expect "a PCCS that serves the CRL passes" 0
that "the CRL is asked over https only" has "$(log curl)" "--proto =https --cacert "
that "  at the PCCS's CRL path" has "$(log curl)" \
  " -o /dev/null https://pccs.site1.example:8081/sgx/certification/v4/rootcacrl"
that "the CA file holds STAND_SITE_CA_PEM" has "$(log curl)" \
  $'-----BEGIN CERTIFICATE-----\nsite\n-----END CERTIFICATE-----'

reset
reply curl 1 60 "" "curl: (60) SSL certificate problem: unable to get local issuer certificate"
reply curl 2 60 "" "curl: (60) SSL certificate problem: unable to get local issuer certificate"
run "${site[@]}" bash "$here/check.sh" site
expect "a PCCS that fails twice fails the check" 1 \
  "::error::https://pccs.site1.example:8081/: the PCCS did not serve the root CA CRL: curl: (60) SSL certificate problem"

reset
reply curl 1 7 "" "curl: (7) Failed to connect"
run "${site[@]}" bash "$here/check.sh" site
expect "a PCCS back within the retry passes" 0 "the PCCS did not serve the root CA CRL: curl: (7)"
refute "  without an error" "::error::"

echo
if [ "$failures" -gt 0 ]; then
  echo "$failures failed"
  exit 1
fi
echo "all passed"
