# Verifying a tagged release on a second machine

Before a release signer signs a document that lists a release's KMS Revision, someone outside the
CI run rebuilds the release from its tag and gets the same images. CI already builds each
image on two runners ([What a release produces](README.md#what-a-release-produces)); this check
covers what both runners share: GitHub's runner image, network and account.

## The machine

Linux on x86_64, not a GitHub runner, with Docker Engine using its classic image store, where an
image's id is the digest of its configuration: `docker info -f '{{.Driver}}'` prints `overlay2`
(the containerd store prints `overlayfs` and reports other ids). `git`, `gh` and `jq`.

## Inputs

The tag, and from the release run of that tag
(`gh run list -R AlphaCompute/confidential-platform -w release.yml`): its id, each image's two
`<name> on runner a|b …` lines from the `build` jobs and its `pushed ghcr.io/…@sha256:…` line
from the `image` job, all in the run's summary, and the artifact `alpha-kms-release-manifest`
from the `render` job. Every `ci / …` job of the run passed, or nothing was pushed:

```sh
TAG='PASTE_TAG'
RUN='PASTE_RUN_ID'
gh run view "$RUN" -R AlphaCompute/confidential-platform --json jobs --jq '.jobs[] | select(.name | startswith("ci /")) | .conclusion'
```

## 1. The source

```sh
git clone https://github.com/AlphaCompute/confidential-platform && cd confidential-platform
git checkout "$TAG"
gh run download "$RUN" -n alpha-kms-release-manifest -D release
git rev-parse HEAD   # equals: gh run view "$RUN" --json headSha --jq .headSha
printf '%s\n' RECORDED_KEY_1 RECORDED_KEY_2 RECORDED_KEY_3 | sort |
  diff - <(sort crates/alpha-channel/release-keys/prod.pub)   # the three keys of the record
```

## 2. The images

For each image, with its Dockerfile from `.github/workflows/release.yml` (`alpha-kms`:
`images/kms/Dockerfile`; `alpha-kms-dev` adds `--build-arg FEATURES=dev-root`):

```sh
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
docker build --no-cache --platform linux/amd64 --provenance=false \
  --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" -f images/kms/Dockerfile -t alpha-kms:verify .
IMAGE='PASTE_PUSHED_REFERENCE'   # ghcr.io/…/alpha-kms@sha256:… from the pushed line
docker pull "$IMAGE"
docker image inspect --format '{{.Id}} {{.RootFS.Layers}}' alpha-kms:verify "$IMAGE"
```

The two lines are equal, and equal to both runners' lines in the release run's summary. For
`alpha-kms` the pushed reference is also `image` in `release/kata/manifest.json`. The ceremony
needs `alpha-kms`; the others are checked the same way.

## 3. The provenance

As in [What a release produces](README.md#what-a-release-produces): the attestation must come
from the release workflow, at this tag, on a GitHub-hosted runner. Run it for every image of
step 2, with `IMAGE` set to that image's pushed reference.

```sh
gh attestation verify "oci://$IMAGE" --repo AlphaCompute/confidential-platform \
  --signer-workflow AlphaCompute/confidential-platform/.github/workflows/release.yml \
  --source-ref "refs/tags/$TAG" --deny-self-hosted-runners
```

## 4. The KMS nodes' init-data

Render it again as in [What a release produces](kata/README.md#what-a-release-produces), with
the production `alpha` built at the tag in the pinned image (the command in
[`signer-keys.md`](signer-keys.md) without `--features dev`), the
pushed `alpha-kms` digest and the three URLs the tag's `render` job used, which its log prints
in that step's environment (`gh run view "$RUN" -R AlphaCompute/confidential-platform --log`);
the repository variables may have changed since. Write the JSON `alpha coco render` prints to
`rendered.json`. Then:

```sh
jq -r .revision rendered.json                  # equals compose_hash in release/kata/manifest.json
jq -j .init_data rendered.json | cmp - release/kata/init-data.toml
```

## 5. The record

The tag, the commit, every image's id line and pushed reference, and the `compose_hash`.
Each custodian and signer runs an `alpha` built at the tag in the pinned image, as in
[`signer-keys.md`](signer-keys.md), with its SHA-256 equal to a second person's build of the same
tag; the record keeps it. A difference at any step stops the ceremony until it is explained.
