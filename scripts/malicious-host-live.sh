#!/usr/bin/env bash
# The malicious-host full suite, live layer (PRD-02 deliverable 18): the hostile actions a host
# operator can take against a running Kata confidential pod, done for real, each of which must be
# refused. docs/kata-attestation.md ("Malicious-host full suite") says how to run it at G0.
#
#   KUBECONFIG=... MHS_NAMESPACE=app-<id> MHS_DEPLOYMENT=app-<id> scripts/malicious-host-live.sh
#
# MHS_NAMESPACE / MHS_DEPLOYMENT  the attested test App: a Deployment of one Ready pod, deployed
#                                 with its Revision registered (its runtime holds a leaf).
# MHS_TIMEOUT                     seconds to wait for a refusal to show (default 180).
# MHS_NODE_SHELL                  optional: a command that runs its arguments as root on the pod's
#                                 node (e.g. "ssh root@b300-01"), for the crictl cases.
#
# Without KUBECONFIG it exits 0 (skipped); a configured but unreachable cluster is an error.
# Every pod it creates is labelled alphacompute.ai/malicious-host=1 and deleted on exit. It never
# changes the test Deployment itself.
set -uo pipefail

skip() { echo "malicious-host live suite: skipped: $*"; exit 0; }
[ -n "${KUBECONFIG:-}" ] || skip "no cluster configured (set KUBECONFIG, MHS_NAMESPACE and MHS_DEPLOYMENT)"
[ -n "${MHS_NAMESPACE:-}" ] && [ -n "${MHS_DEPLOYMENT:-}" ] || { echo "MHS_NAMESPACE and MHS_DEPLOYMENT are required" >&2; exit 2; }
for tool in kubectl jq base64 gzip python3 timeout; do
  command -v "$tool" >/dev/null 2>&1 || { echo "malicious-host live suite: $tool is required" >&2; exit 2; }
done
kubectl version --request-timeout=10s >/dev/null 2>&1 || { echo "the configured cluster does not answer" >&2; exit 2; }

ns="$MHS_NAMESPACE"
timeout_secs="${MHS_TIMEOUT:-180}"
[[ "$timeout_secs" =~ ^[1-9][0-9]*$ ]] || { echo "MHS_TIMEOUT must be positive seconds" >&2; exit 2; }
k() { kubectl -n "$ns" --request-timeout=30s "$@"; }
work="$(mktemp -d)"
trap 'k delete pod -l alphacompute.ai/malicious-host=1 --wait=false >/dev/null 2>&1; rm -rf "$work"' EXIT

failures=0
skipped=0
pass() { printf 'refused  %s\n' "$1"; }
fail() { printf 'FAILED   %s: %s\n' "$1" "$2"; failures=$((failures + 1)); }

skip_case() { printf 'skipped  %s\n' "$1"; skipped=$((skipped + 1)); }

# A nonzero exit alone is not a policy verdict: missing tools, RBAC and transport
# failures must not pass a security test. Keep arbitrary output out of the report.
policy_denied() {
  local what="$1" request="$2" status
  shift 2
  if "$@" >"$work/out" 2>"$work/err"; then
    fail "$what" "operation succeeded"
  else
    status=$?
    if [ "$status" -ne 124 ] && grep -Eq "($request) is blocked by policy" "$work/out" "$work/err"; then
      pass "$what"
    else
      fail "$what" "no explicit agent-policy denial (exit $status)"
    fi
  fi
}

empty_logs() {
  local what="$1"
  shift
  if "$@" >"$work/out" 2>"$work/err"; then
    if [ -s "$work/out" ]; then fail "$what" "log data returned"; else pass "$what (empty stream)"; fi
  else
    fail "$what" "log request failed; an error is not an empty denied stream"
  fi
}

selector="$(k get deployment "$MHS_DEPLOYMENT" -o json | jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")')"
pod="$(k get pods -l "$selector" -o json | jq -r '[.items[] | select(.status.phase == "Running")][0].metadata.name // empty')"
[ -n "$pod" ] || { echo "no running pod of deployment $MHS_DEPLOYMENT in $ns" >&2; exit 2; }
k get pod "$pod" -o json > "$work/pod.json"
[ "$(jq -r '.status.conditions[] | select(.type == "Ready") | .status' "$work/pod.json")" = True ] ||
  { echo "$pod is not Ready: deploy the test App and let it attest first" >&2; exit 2; }
containers="$(jq -r '[.spec.initContainers[]? | select(.restartPolicy == "Always") | .name] + [.spec.containers[].name] | .[]' "$work/pod.json")"
echo "malicious-host live suite against $ns/$pod ($(echo $containers))"

# The test workload must emit stdout/stderr by construction; empty logs from a
# silent application do not demonstrate the stream policy (see the runbook).
for c in $containers; do
  policy_denied "exec into $c" ExecProcessRequest k exec "$pod" -c "$c" -- sh -c 'echo reached'
  policy_denied "exec -i into $c" ExecProcessRequest k exec -i "$pod" -c "$c" -- cat /proc/1/environ </dev/null
  empty_logs "logs of $c" k logs "$pod" -c "$c"
  restarts="$(jq -r --arg c "$c" '[.status.containerStatuses[]?, .status.initContainerStatuses[]?] | map(select(.name == $c)) | .[0].restartCount // 0' "$work/pod.json")"
  if [ "$restarts" -gt 0 ]; then
    empty_logs "previous logs of $c" k logs "$pod" -c "$c" --previous
  else
    skip_case "previous logs of $c (no previous container instance)"
  fi
done

first="$(echo "$containers" | head -1)"
echo probe > "$work/probe"
policy_denied "cp into $first" 'ExecProcessRequest|CopyFileRequest' k cp "$work/probe" "$pod:/tmp/probe" -c "$first"
policy_denied "cp out of $first" 'ExecProcessRequest|CopyFileRequest' k cp "$pod:/etc/hostname" "$work/out-copy" -c "$first"
policy_denied "attach to $first" 'ReadStreamRequest|WriteStreamRequest|CloseStdinRequest' timeout 20 kubectl -n "$ns" attach "$pod" -c "$first" -i </dev/null

# Waits for container $2 of pod $1 to be refused at creation (CreateContainerRequest blocked by the
# policy). A cloned pod must not be Ready. For an ephemeral debug container the
# original pod may stay Ready; only the attempted new container must be refused.
refused_at_create() {
  local p="$1" c="$2" what="$3" require_not_ready="${4:-true}" deadline=$((SECONDS + timeout_secs)) msg status
  while [ $SECONDS -lt $deadline ]; do
    status="$(k get pod "$p" -o json 2>"$work/err")" || { fail "$what" "pod status request failed"; return; }
    msg="$(printf '%s' "$status" | jq -r --arg c "$c" \
      '[.status.containerStatuses[]?, .status.initContainerStatuses[]?, .status.ephemeralContainerStatuses[]?]
       | map(select(.name == $c)) | .[0].state.waiting.message // .[0].state.terminated.message // empty')"
    if echo "$msg" | grep -q 'CreateContainerRequest is blocked by policy'; then
      if [ "$require_not_ready" = true ] && [ "$(printf '%s' "$status" | jq -r '.status.conditions[]? | select(.type == "Ready") | .status')" = True ]; then
        fail "$what" "refused, but the pod is Ready"
      else
        pass "$what"
      fi
      return
    fi
    if [ "$(printf '%s' "$status" | jq -r --arg c "$c" \
      '[.status.containerStatuses[]?, .status.initContainerStatuses[]?] | map(select(.name == $c)) | .[0].state.running // empty')" != "" ]; then
      fail "$what" "container $c is running"
      return
    fi
    sleep 5
  done
  fail "$what" "no refusal within ${timeout_secs}s (status: $(k get pod "$p" -o json | jq -c '.status.containerStatuses'))"
}

# kubectl debug: an ephemeral container is a CreateContainerRequest the policy has no entry for.
if k debug "$pod" -c mhs-debug --image=busybox:1.37 -- sleep 600 >/dev/null 2>&1; then
  refused_at_create "$pod" mhs-debug "ephemeral debug container" false
else
  fail "ephemeral debug container" "API request failed before agent-policy enforcement could be tested"
fi

# The test pod's spec, cloned with one change into a new pod: what a host that rewrites the
# Deployment, or a node that edits the pod it was handed, gets the kubelet to ask the agent for.
# The init-data annotation is the original, so the pod's Revision is the attested one.
template="$(k get deployment "$MHS_DEPLOYMENT" -o json | jq '.spec.template')"
main="$(jq -r '.spec.containers[0].name' "$work/pod.json")"
# Writes the clone to $work/<name>.json; a jq error is the suite's own and stops it.
clone() {
  local name="$1" change="$2"
  echo "$template" | jq -e --arg name "$name" "
    {apiVersion: \"v1\", kind: \"Pod\",
     metadata: (.metadata + {name: \$name, labels: ((.metadata.labels // {}) + {\"alphacompute.ai/malicious-host\": \"1\"})}),
     spec: .spec} | $change" > "$work/$name.json" ||
    { echo "malicious-host live suite: cannot apply '$change' to the pod template" >&2; exit 2; }
}
hostile() {
  local name="mhs-$1" what="$2" change="$3" container="${4:-$main}"
  clone "$name" "$change"
  if k create -f "$work/$name.json" >/dev/null 2>"$work/err"; then
    refused_at_create "$name" "$container" "$what"
    k delete pod "$name" --wait=false >/dev/null 2>&1
  else
    fail "$what" "pod creation failed before agent-policy enforcement could be tested"
  fi
}
image="$(jq -r --arg c "$main" '.spec.containers[] | select(.name == $c) | .image' "$work/pod.json")"
other="${MHS_OTHER_IMAGE:-${image%@*}@sha256:$(printf 0bad%.0s {1..16})}"
hostile image "another image digest for $main" ".spec.containers[0].image = \"$other\""
hostile env "an extra environment variable" '.spec.containers[0].env += [{"name": "LD_PRELOAD", "value": "/dev/shm/x.so"}]'
hostile env-changed "a changed environment value" '.spec.containers[0].env |= ((. // [{"name": "MHS", "value": ""}]) | .[0].value += "0")'
hostile mount "an extra mount" '.spec.volumes += [{"name": "mhs", "emptyDir": {}}] | .spec.containers[0].volumeMounts += [{"name": "mhs", "mountPath": "/etc/ld.so.preload.d"}]'
hostile sa "a service account token" '.spec.automountServiceAccountToken = true'
hostile command "another command" '.spec.containers[0].command = ["/bin/sh", "-c", "sleep 3600"]'
hostile privileged "a privileged container" '.spec.containers[0].securityContext = {"privileged": true}'
hostile caps "CAP_SYS_ADMIN" '.spec.containers[0].securityContext = {"capabilities": {"add": ["SYS_ADMIN"]}}'
hostile user "another user" '.spec.containers[0].securityContext = ((.spec.containers[0].securityContext // {}) + {"runAsUser": 4242})'
hostile hostpath "a host path volume" '.spec.volumes += [{"name": "mhs", "hostPath": {"path": "/"}}] | .spec.containers[0].volumeMounts += [{"name": "mhs", "mountPath": "/host"}]'
hostile sidecar "an extra container" '.spec.containers += [{"name": "mhs-extra", "image": "busybox:1.37", "command": ["sleep", "3600"]}]' mhs-extra

# A pod launched with a policy of the host's (MRCONFIGID consistent): the pod runs, the agent lets
# the host in, and the KMS refuses its runtime a leaf (attestation_unknown), so it is never Ready.
annotation='io.katacontainers.config.hypervisor.cc_init_data'
jq -r --arg a "$annotation" '.metadata.annotations[$a]' "$work/pod.json" | base64 -d | gunzip > "$work/initdata.toml"
python3 -I - "$work/initdata.toml" > "$work/hostile.toml" <<'EOF'
import re, sys
text = open(sys.argv[1]).read()
policy = "package agent_policy\ndefault AllowRequestsFailingPolicy := true\n"
out, n = re.subn(r"(\"policy\.rego\" = ''')\n.*?(''')", lambda m: m.group(1) + "\n" + policy + m.group(2), text, flags=re.S)
assert n == 1, "no policy.rego entry"
sys.stdout.write(out)
EOF
hostile_initdata="$(gzip -9n < "$work/hostile.toml" | base64 | tr -d '\n')"
name=mhs-initdata
clone "$name" ".metadata.annotations[\"$annotation\"] = \"$hostile_initdata\""
if k create -f "$work/$name.json" >/dev/null 2>"$work/err"; then
  deadline=$((SECONDS + timeout_secs)); verdict=""
  while [ $SECONDS -lt $deadline ] && [ -z "$verdict" ]; do
    if ! k get pod "$name" -o json >"$work/status" 2>"$work/err"; then
      verdict="error"
      break
    fi
    ready="$(jq -r '.status.conditions[]? | select(.type == "Ready") | .status' "$work/status")" || { verdict="error"; break; }
    if [ "$ready" = True ]; then
      verdict="ready"
    elif k logs "$name" -c alpha-runtime >"$work/kms-result" 2>"$work/err" && grep -q 'attestation_unknown' "$work/kms-result"; then
      verdict="refused"
    fi
    [ -n "$verdict" ] || sleep 1
  done
  case "$verdict" in
    refused) pass "the host's own policy in the init-data (the KMS refused: attestation_unknown)" ;;
    ready) fail "the host's own policy in the init-data" "the pod became Ready: its runtime got a leaf" ;;
    *) fail "the host's own policy in the init-data" "no confirmed KMS rejection within ${timeout_secs}s; not becoming Ready is inconclusive" ;;
  esac
  k delete pod "$name" --wait=false >/dev/null 2>&1
else
  fail "the host's own policy in the init-data" "pod creation failed before KMS appraisal could be tested"
fi

# The init-data annotation edited on the running pod: the downward-API copy changes, the TD's
# MRCONFIGID does not, so the runtime's next attestation is refused. The pod keeps its leaf until it
# expires (at most an hour) and gets no new one; here only that it stays the pod it was is checked.
before="$(k get pod "$pod" -o json | jq -r '.metadata.uid')"
if k annotate pod "$pod" --overwrite "$annotation=$hostile_initdata" >/dev/null 2>&1; then
  if k annotate pod "$pod" --overwrite "$annotation=$(jq -r --arg a "$annotation" '.metadata.annotations[$a]' "$work/pod.json")" >/dev/null 2>&1; then
    printf '%s\n' "observed init-data annotation edit and restoration (KMS MRCONFIGID rejection is not asserted by this operation)"
  else
    fail "restore original init-data annotation" "API request failed"
  fi
else
  fail "init-data annotation edit" "API request failed; no KMS check occurred"
fi
[ "$(k get pod "$pod" -o json | jq -r '.metadata.uid')" = "$before" ] || fail "test pod" "was replaced during the run"

# On the node: the container runtime's own exec and logs reach the same agent calls.
if [ -n "${MHS_NODE_SHELL:-}" ]; then
  sandbox="$($MHS_NODE_SHELL crictl pods --namespace "$ns" --name "$pod" -q 2>"$work/err")" ||
    { echo "node sandbox lookup failed" >&2; exit 2; }
  [ -n "$sandbox" ] && [ "$(printf '%s\n' "$sandbox" | wc -l)" -eq 1 ] ||
    { echo "expected one node sandbox" >&2; exit 2; }
  ids="$($MHS_NODE_SHELL crictl ps --pod "$sandbox" -q 2>"$work/err")" ||
    { echo "node container lookup failed" >&2; exit 2; }
  [ -n "$ids" ] || { echo "no node containers to test" >&2; exit 2; }
  for cid in $ids; do
    policy_denied "crictl exec $cid" ExecProcessRequest $MHS_NODE_SHELL crictl exec "$cid" sh -c 'echo reached'
    empty_logs "crictl logs $cid" $MHS_NODE_SHELL crictl logs "$cid"
  done
  policy_denied "kata-runtime exec (debug console)" 'ExecProcessRequest|debug console' timeout 20 $MHS_NODE_SHELL kata-runtime exec "$sandbox" </dev/null
else
  skip_case "node-runtime checks (MHS_NODE_SHELL not configured)"
fi

if [ "$failures" -gt 0 ]; then
  echo "malicious-host live suite: $failures required check(s) failed or lacked denial evidence" >&2
  exit 1
fi
echo "malicious-host live suite: required checks passed; $skipped optional checks skipped"
