#!/usr/bin/env bash
# Regenerates the agent-policy fixtures (see README.md) with genpolicy from the Kata Containers
# 4.1.0 release, and re-serializes requests.json through Kata 4.1.0's own agent API types.
#
#   testdata/agent-policy/generate.sh            # the policies
#   testdata/agent-policy/generate.sh requests   # requests.json (needs cargo)
#
# Needs curl, sha256sum, tar, patch and zstd (or python3 with the zstandard module). The vLLM
# image's layers are pulled to read its /etc/passwd: about 10 GB, in a temporary directory that is
# removed on exit, as is the release download.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
kata=4.1.0
tools="kata-tools-static-$kata-amd64.tar.zst"
tools_sha256=58fd166094b456d792b61eda218c44d3b4717281e0debd6869c8e787453f8f30
genpolicy_sha256=c32ad5371d0c348100edf76758ce56682b2868fb250b883d2c7f0a68c342aa59
rules_sha256=a1ad4280a7d1db83649de18640fb30f08cc160fadd7f4360d1dde09977b090b7
settings_sha256=46bf9ac5460393f626ff2ed6fa2501ec5a82893da57c06e5c53a8f8e50e9dfa0
source_sha256=781a69dd69ffc56b0547e3c9ba9992cdcf6993b9e98bfcc155ed6e9953a59b4a

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

unzstd_to_stdout() {
  if command -v zstd >/dev/null 2>&1; then
    zstd -dc "$1"
  else
    python3 -I -c 'import sys, zstandard; zstandard.ZstdDecompressor().copy_stream(open(sys.argv[1], "rb"), sys.stdout.buffer)' "$1"
  fi
}

policies() {
  curl -fsSL -o "$work/$tools" "https://github.com/kata-containers/kata-containers/releases/download/$kata/$tools"
  echo "$tools_sha256  $work/$tools" | sha256sum -c --quiet -
  mkdir "$work/kata"
  unzstd_to_stdout "$work/$tools" | tar -x -C "$work/kata" \
    ./opt/kata/bin/genpolicy \
    ./opt/kata/share/defaults/kata-containers/rules.rego \
    ./opt/kata/share/defaults/kata-containers/genpolicy-settings.json
  rm "$work/$tools"

  local bin="$work/kata/opt/kata/bin/genpolicy"
  local defaults="$work/kata/opt/kata/share/defaults/kata-containers"
  sha256sum -c --quiet - <<EOF
$genpolicy_sha256  $bin
$rules_sha256  $defaults/rules.rego
$settings_sha256  $defaults/genpolicy-settings.json
EOF

  # The settings directory: the release's settings with our drop-in, which genpolicy applies as
  # an RFC 6902 patch.
  mkdir -p "$work/settings/genpolicy-settings.d"
  cp "$defaults/genpolicy-settings.json" "$work/settings/"
  cp "$here"/genpolicy-settings.d/*.json "$work/settings/genpolicy-settings.d/"
  patch -s -o "$work/alpha-rules.rego" "$defaults/rules.rego" "$here/alpha-rules.patch"

  # rules: path of the rules file; out: fixture path, relative to this directory.
  run() {
    local pod="$1" rules="$2" out="$3"
    mkdir -p "$work/run"
    cp "$here/$pod/pod.yaml" "$work/run/pod.yaml"
    # -u with a cache file in $work: the second policy of a pod reuses the first's image layers.
    (cd "$work/run" && "$bin" -u --layers-cache-file-path="$work/layers-cache.json" \
      -p "$rules" -j "$work/settings" -y pod.yaml -r) > "$here/$out"
    rm -rf "$work/run"
  }
  run gpu-model-server "$work/alpha-rules.rego" gpu-model-server/policy.rego
  run cpu-app "$work/alpha-rules.rego" cpu-app/policy.rego
  run cpu-app "$defaults/rules.rego" cpu-app/policy-genpolicy-rules.rego
}

requests() {
  curl -fsSL -o "$work/kata.tar.gz" "https://codeload.github.com/kata-containers/kata-containers/tar.gz/refs/tags/$kata"
  echo "$source_sha256  $work/kata.tar.gz" | sha256sum -c --quiet -
  tar -xzf "$work/kata.tar.gz" -C "$work" "kata-containers-$kata/src/libs/protocols"
  rm "$work/kata.tar.gz"
  local protocols="$work/kata-containers-$kata/src/libs/protocols"
  # Outside Kata's workspace: its two workspace dependencies at the versions Kata's lock pins.
  sed -i 's/^ttrpc = { workspace = true }/ttrpc = "=0.9.0"/; s/^oci-spec = { workspace = true }/oci-spec = { version = "=0.10.0", features = ["runtime"] }/' \
    "$protocols/Cargo.toml"

  mkdir -p "$work/canon/src"
  cat > "$work/canon/Cargo.toml" <<EOF
[package]
name = "canon"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
protocols = { path = "$protocols", features = ["with-serde"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
EOF
  cat > "$work/canon/src/main.rs" <<'EOF'
// Each request through Kata's own type and back, as the agent's policy.rs serializes it before it
// asks the policy: every field present, with the agent's encoding.
use std::io::Read;

use protocols::agent::*;
use serde_json::Value;

#[derive(serde::Deserialize, serde::Serialize, Default)]
enum FileType {
    #[default]
    Unknown,
    Regular,
    Directory,
    Symlink,
}

// kata_agent_policy::policy::PolicyCopyFileRequest: what the agent hands the policy for CopyFile.
#[derive(serde::Deserialize, serde::Serialize, Default)]
#[serde(default)]
struct PolicyCopyFileRequest {
    path: String,
    file_type: FileType,
    symlink_target: Option<String>,
    file_size: i64,
    file_mode: u32,
    dir_mode: u32,
    uid: i32,
    gid: i32,
    offset: i64,
}

macro_rules! canon {
    ($kind:expr, $req:expr, $($t:ident),*) => {
        match $kind {
            $(stringify!($t) => serde_json::to_value(serde_json::from_value::<$t>($req).unwrap()).unwrap(),)*
            "CopyFileRequest" => serde_json::to_value(serde_json::from_value::<PolicyCopyFileRequest>($req).unwrap()).unwrap(),
            other => panic!("unknown kind {other}"),
        }
    };
}

fn main() {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text).unwrap();
    let requests: serde_json::Map<String, Value> = serde_json::from_str(&text).unwrap();
    let out: serde_json::Map<String, Value> = requests
        .into_iter()
        .map(|(label, req)| {
            let kind = label.split('/').next().unwrap().to_owned();
            let canonical = canon!(
                kind.as_str(),
                req,
                CreateContainerRequest, StartContainerRequest, RemoveContainerRequest,
                ExecProcessRequest, SignalProcessRequest, WaitProcessRequest,
                UpdateContainerRequest, UpdateEphemeralMountsRequest, StatsContainerRequest,
                PauseContainerRequest, ResumeContainerRequest,
                RemoveStaleVirtiofsShareMountsRequest, GetDiagnosticDataRequest,
                WriteStreamRequest, ReadStreamRequest, CloseStdinRequest, TtyWinResizeRequest,
                UpdateInterfaceRequest, UpdateRoutesRequest, ListInterfacesRequest,
                ListRoutesRequest, AddARPNeighborsRequest, GetIPTablesRequest, SetIPTablesRequest,
                GetMetricsRequest, MemAgentMemcgConfig, MemAgentCompactConfig,
                CreateSandboxRequest, DestroySandboxRequest, OnlineCPUMemRequest,
                ReseedRandomDevRequest, GuestDetailsRequest, MemHotplugByProbeRequest,
                SetGuestDateTimeRequest, GetOOMEventRequest, AddSwapRequest, AddSwapPathRequest,
                VolumeStatsRequest, ResizeVolumeRequest, SetPolicyRequest
            );
            (label, canonical)
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
EOF
  cargo run -q --release --manifest-path "$work/canon/Cargo.toml" < "$here/requests.json" > "$work/requests.json"
  mv "$work/requests.json" "$here/requests.json"
}

case "${1:-policies}" in
  policies) policies ;;
  requests) requests ;;
  *) echo "usage: $0 [policies|requests]" >&2; exit 2 ;;
esac
