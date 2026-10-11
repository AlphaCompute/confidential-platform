#!/usr/bin/env bash
# The stand's checks, one per job of .github/workflows/stand.yml. Each asks whether what it
# watches is serving and fails when something is not, which is what makes GitHub send a
# notification. A failing round is retried once after STAND_RETRY_SECONDS (120), because a copy
# does not serve for a minute while it is being redeployed; only the second round's findings are
# errors.
#
#   check.sh prototype  until M-D: every copy of each App in STAND_APPS serving, as the
#                       prototype's shroud-go (STAND_SHROUD_URL) lists them under STAND_LIST_KEY
#   check.sh owned      from M-D: every KMS node (STAND_KMS_ENDPOINTS) and App Endpoint
#                       (STAND_APP_ENDPOINTS) through `alpha probe` (the binary STAND_ALPHA),
#                       pinned to the KMS CA and node Revisions of the release-signed platform
#                       document (STAND_PLATFORM_DOCUMENT_URL), never to a host name
#   check.sh site       from M-D, on a runner at the site (STAND_SITE_RUNNER): the site PCCS
#                       (STAND_PCCS_URL) serves the root CA CRL under the site CA
#                       (STAND_SITE_CA_PEM)
#
# STAND_TARGET says which of them the workflow runs: prototype (the default), both, or owned.
set -u -o pipefail
# Lists are split on whitespace and never globbed.
set -f

fail() {
  echo "::error::$*"
  exit 1
}

# A value of only whitespace names nothing.
blank() {
  [ -z "${1//[[:space:]]/}" ]
}

# need NAME WHAT: refuse a variable that is unset, empty or only whitespace.
need() {
  if blank "${!1-}"; then
    fail "$1 $2"
  fi
}

# retry ROUND: ROUND prefixes each finding with its argument; only the second round's are errors.
retry() {
  "$1" "" && return 0
  sleep "${STAND_RETRY_SECONDS:-120}"
  "$1" "::error::"
}

prototype_round() {
  local down=0 app list
  for app in $STAND_APPS; do
    if ! list=$(printf 'header = "Authorization: Bearer %s"\n' "$STAND_LIST_KEY" |
      curl -sS -f -m 30 -K - "${STAND_SHROUD_URL%/}/v1/apps/$app/instances"); then
      echo "$1$app: the list did not answer"
      down=1
    elif ! echo "$list" | jq -e '.instances | length > 0 and all(.serving == true)' >/dev/null; then
      echo "$1$app: $(echo "$list" | jq -c '[.instances[] | {id, state, serving}]')"
      down=1
    fi
  done
  return $down
}

prototype() {
  need STAND_APPS "names no App"
  need STAND_SHROUD_URL "names no shroud-go"
  need STAND_LIST_KEY "is empty: shroud-go lists copies only under an API key"
  retry prototype_round
}

owned_round() {
  local out findings
  if out=$("$STAND_ALPHA" --platform-document-url "$STAND_PLATFORM_DOCUMENT_URL" probe \
    --kms "$STAND_KMS_ENDPOINTS" --app "$STAND_APP_ENDPOINTS" 2>"$tmp/probe.err"); then
    return 0
  fi
  # A probe that printed its report names each target that is not serving; one that stopped
  # before it (a document that does not verify, a malformed target) said why on stderr.
  findings=$(jq -r '((.kms // []) + (.apps // []))[] | select(.serving | not) | .finding' \
    <<<"$out" 2>/dev/null) || findings=
  [ -n "$findings" ] || findings=$(cat "$tmp/probe.err")
  [ -n "$findings" ] || findings="alpha probe failed and said nothing"
  while IFS= read -r line; do
    echo "$1$line"
  done <<<"$findings"
  return 1
}

owned() {
  need STAND_PLATFORM_DOCUMENT_URL "names no platform document: the probes pin its KMS CA and node Revisions"
  need STAND_KMS_ENDPOINTS "names no KMS node"
  need STAND_APP_ENDPOINTS "names no App Endpoint"
  need STAND_ALPHA "names no alpha binary"
  retry owned_round
}

site_round() {
  local why
  if ! why=$(curl -sS -f -m 30 --proto =https --cacert "$tmp/site-ca.pem" -o /dev/null \
    "${STAND_PCCS_URL%/}/sgx/certification/v4/rootcacrl" 2>&1); then
    echo "$1$STAND_PCCS_URL: the PCCS did not serve the root CA CRL: ${why//$'\n'/ }"
    return 1
  fi
}

# The PCCS is on the path of every attestation: a quote whose collateral cannot be fetched fails
# appraisal.
site() {
  need STAND_SITE_RUNNER "names no runner at the site, and the PCCS answers only inside the site"
  need STAND_PCCS_URL "names no PCCS"
  need STAND_SITE_CA_PEM "names no site CA for the PCCS certificate"
  printf '%s\n' "$STAND_SITE_CA_PEM" >"$tmp/site-ca.pem"
  retry site_round
}

case ${STAND_TARGET:-} in
  "" | prototype | both | owned) ;;
  *) fail "STAND_TARGET is \"$STAND_TARGET\", not prototype, both or owned" ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

case ${1-} in
  prototype | owned | site) "$1" ;;
  *)
    echo "usage: $0 prototype|owned|site" >&2
    exit 2
    ;;
esac
