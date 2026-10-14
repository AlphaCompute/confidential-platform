# Verifying a tagged release on a second machine

Before a release signer signs a document that lists a release's KMS Revision, someone outside the
CI run rebuilds the release from its tag and gets the same images. CI already builds each
image on two runners ([What a release produces](README.md#what-a-release-produces)); this check
covers what both runners share: GitHub's runner image, network and account.

## The machine

Linux on x86_64, not a GitHub runner, with Docker Engine using its classic image store, where an
image's id is the digest of its configuration: `docker info -f '{{.Driver}}'` prints `overlay2`
(the containerd store prints `overlayfs` and reports other ids). `git`, `gh`, `jq` and the Rust
toolchain in `rust-toolchain.toml`.

## Inputs

The tag, and from the release run of that tag
(`gh run list -R AlphaCompute/confidential-platform -w release.yml`): its id, each image's two
`<name> on runner a|b …` lines from the `build` jobs and its `pushed ghcr.io/…@sha256:…` line
from the `image` job, all in the run's summary, and the artifact `alpha-kms-release-manifest`
from the `render` job. Every `ci / …` job of the run passed, or nothing was pushed:

```sh
gh run view <run id> -R AlphaCompute/confidential-platform --json jobs --jq '.jobs[] | select(.name | startswith("ci /")) | .conclusion'
gh run download <run id> -R AlphaCompute/confidential-platform -n alpha-kms-release-manifest -D release
```

## 1. The source

```sh
git clone https://github.com/AlphaCompute/confidential-platform && cd confidential-platform
git checkout <tag>
git rev-parse HEAD   # equals: gh run view <run id> --json headSha --jq .headSha
cat crates/alpha-channel/release-keys/prod.pub   # the three keys of the record, no dev key
```

## 2. The images

For each image, with its Dockerfile from `.github/workflows/release.yml` (`alpha-kms`:
`images/kms/Dockerfile`; `alpha-kms-dev` adds `--build-arg FEATURES=dev-root`):

```sh
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
docker build --no-cache --platform linux/amd64 --provenance=false \
  --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" -f images/kms/Dockerfile -t alpha-kms:verify .
docker pull <pushed ghcr.io/…/alpha-kms@sha256:…>
docker image inspect --format '{{.Id}} {{.RootFS.Layers}}' alpha-kms:verify <pushed reference>
```

The two lines are equal, and equal to both runners' lines in the release run's summary. For
`alpha-kms` the pushed reference is also `image` in `release/kata/manifest.json`. The ceremony
needs `alpha-kms`; the others are checked the same way.

## 3. The provenance

As in [What a release produces](README.md#what-a-release-produces): the attestation must come
from the release workflow, at this tag, on a GitHub-hosted runner.

```sh
gh attestation verify oci://<pushed reference> --repo AlphaCompute/confidential-platform \
  --signer-workflow AlphaCompute/confidential-platform/.github/workflows/release.yml \
  --source-ref refs/tags/<tag> --deny-self-hosted-runners
```

## 4. The KMS nodes' init-data

Render it again as in [What a release produces](kata/README.md#what-a-release-produces), with
the production `alpha` built at the tag (`cargo build --release --locked -p alpha-cli`), the
pushed `alpha-kms` digest and the three URLs the tag's `render` job used, which its log prints
in that step's environment (`gh run view <run id> -R AlphaCompute/confidential-platform --log`);
the repository variables may have changed since. Write the JSON `alpha coco render` prints to
`rendered.json`. Then:

```sh
jq -r .revision rendered.json                  # equals compose_hash in release/kata/manifest.json
jq -j .init_data rendered.json | cmp - release/kata/init-data.toml
```

## 5. The record

The tag, the commit, every image's id line and pushed reference, and the `compose_hash`.
Each custodian and signer builds `alpha` at the tag on their own machine and records the
SHA-256 of that build; it embeds the build paths, so it differs from machine to machine and is
not compared. A difference at any step stops the ceremony until it is explained.
