# syntax=docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# The alpha-weights image: one static binary and nothing else, built the way images/inference
# builds alpha-inference. From the root:
#   docker build --platform linux/amd64 --build-arg SOURCE_DATE_EPOCH=<unix seconds> -f images/weights/Dockerfile .

ARG SOURCE_DATE_EPOCH=0

FROM --platform=linux/amd64 rust:1.95.0-alpine3.22@sha256:064dfc925d68d1a63f4fd2871bd7dc6e6ea56692989a487185855d62885d90aa AS deps
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
RUN --network=none cargo build --release --locked --offline -p alpha-weights \
 && install -D -m 0755 target/release/alpha-weights /out/alpha-weights \
 && touch -h -d "@$SOURCE_DATE_EPOCH" /out/alpha-weights /out

# No CA bundle: its only peer is the runtime socket, and the weights it reads and writes are files.
FROM scratch
COPY --from=build /out/alpha-weights /alpha-weights
ENTRYPOINT ["/alpha-weights"]
