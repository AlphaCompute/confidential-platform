# syntax=docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# The alpha-inference image: one static binary and nothing else, built the way images/manager
# builds alpha-runtime (pinned base, offline compile, timestamps from SOURCE_DATE_EPOCH). From
# the root:
#   docker build --platform linux/amd64 --build-arg SOURCE_DATE_EPOCH=<unix seconds> -f images/inference/Dockerfile .

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
RUN cargo fetch --locked

FROM deps AS build
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH CARGO_PROFILE_RELEASE_STRIP=true
RUN --network=none cargo build --release --locked --offline -p alpha-inference \
 && install -D -m 0755 target/release/alpha-inference /out/alpha-inference \
 && touch -h -d "@$SOURCE_DATE_EPOCH" /out/alpha-inference /out

# Runs as root, no USER: scratch has no /etc/passwd to name another user.
FROM scratch
# RedPill's attestation report and PCCS collateral are fetched over WebPKI, and reqwest's
# rustls verifier reads the system roots; scratch has none, so the pinned base image's bundle
# goes where rustls-native-certs looks for it — the same reason images/kms/Dockerfile copies it.
COPY --from=deps /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/alpha-inference /alpha-inference
ENTRYPOINT ["/alpha-inference"]
