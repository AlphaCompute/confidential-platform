# syntax=docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# The alpha-kms image: one static binary and nothing else. Built from the repository root:
#   docker build --platform linux/amd64 --build-arg SOURCE_DATE_EPOCH=<unix seconds> \
#     [--build-arg FEATURES=dev-root] -f images/kms/Dockerfile .
# Same shape as images/manager: base pinned by digest, dependencies fetched in their own stage,
# no network while compiling, every timestamp from SOURCE_DATE_EPOCH, so two builds of one
# commit give one image digest (.github/workflows/release.yml checks that). FEATURES is a
# compile-time cargo feature list: empty for production, `dev-root` for the dev App's image,
# which is a distinct image (alpha-kms-dev), never a runtime switch. `migrate` is this same
# binary with an argument.

ARG SOURCE_DATE_EPOCH=0

FROM --platform=linux/amd64 rust:1.95.0-alpine3.22@sha256:064dfc925d68d1a63f4fd2871bd7dc6e6ea56692989a487185855d62885d90aa AS deps
# The image's toolchain is the pinned one; the override keeps rustup from reading
# rust-toolchain.toml and fetching components the build does not need.
ENV RUSTUP_TOOLCHAIN=1.95.0 CARGO_INCREMENTAL=0
RUN apk add --no-cache musl-dev cmake make g++ perl linux-headers
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY services services
COPY .sqlx .sqlx
RUN cargo fetch --locked

FROM deps AS build
ARG SOURCE_DATE_EPOCH
ARG FEATURES=""
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH CARGO_PROFILE_RELEASE_STRIP=true \
    SQLX_OFFLINE=true SQLX_OFFLINE_DIR=/src/.sqlx
RUN --network=none cargo build --release --locked --offline -p alpha-kms --features "$FEATURES" \
 && install -D -m 0755 target/release/alpha-kms /out/alpha-kms \
 && touch -h -d "@$SOURCE_DATE_EPOCH" /out/alpha-kms /out

# Runs as root, no USER: the quote is taken by creating a directory under
# /sys/kernel/config/tsm/report, and that configfs tree is root-owned.
FROM scratch
COPY --from=build /out/alpha-kms /alpha-kms
ENTRYPOINT ["/alpha-kms"]
