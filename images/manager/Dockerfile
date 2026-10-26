# syntax=docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# The alpha-runtime image: one binary on glibc and nothing else. Built from the repository root:
#   docker build --platform linux/amd64 --build-arg SOURCE_DATE_EPOCH=<unix seconds> \
#     [--build-arg FEATURES=dev] -f images/manager/Dockerfile .
# FEATURES is compiled in: `dev` gives the distinct alpha-runtime-dev image, which trusts the dev
# release key.
# The base image is pinned by digest, dependencies are fetched in a stage of their own, the
# stage that compiles has no network, and every timestamp comes from SOURCE_DATE_EPOCH, so two
# builds of one commit give one image digest (.github/workflows/release.yml checks that).
# glibc rather than static musl: in a GPU pod the runtime dlopens the libnvidia-ml the NVIDIA
# container toolkit injects, a glibc library that a static musl binary cannot load.

ARG SOURCE_DATE_EPOCH=0

FROM --platform=linux/amd64 rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS deps
# The image's toolchain is the pinned one; the override keeps rustup from reading
# rust-toolchain.toml and fetching components the build does not need.
ENV RUSTUP_TOOLCHAIN=1.95.0 CARGO_INCREMENTAL=0
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY services services
RUN cargo fetch --locked

FROM deps AS build
ARG SOURCE_DATE_EPOCH
ARG FEATURES=""
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH CARGO_PROFILE_RELEASE_STRIP=true
RUN --network=none cargo build --release --locked --offline -p alpha-runtime --features "$FEATURES" \
 && install -D -m 0755 target/release/alpha-runtime /out/alpha-runtime \
 && touch -h -d "@$SOURCE_DATE_EPOCH" /out/alpha-runtime /out

FROM --platform=linux/amd64 gcr.io/distroless/cc-debian12@sha256:e5d81ddde149641e2a9ba55be4545bc125c67de07508b03ba4c22e6eb0ded5aa
COPY --from=build /out/alpha-runtime /alpha-runtime
ENTRYPOINT ["/alpha-runtime"]
