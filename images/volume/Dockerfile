# syntax=docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# The alpha-volume image: the static alpha-volume binary beside cryptsetup, mkfs.ext4 and mount
# at the fixed paths it runs them from (/sbin/cryptsetup, /sbin/mkfs.ext4, /bin/mount). The pod's
# agent policy pins this image by digest, so the tools it opens volumes with are measured. From the
# root:
#   docker build --platform linux/amd64 --build-arg SOURCE_DATE_EPOCH=<unix seconds> -f images/volume/Dockerfile .

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
RUN --network=none cargo build --release --locked --offline -p alpha-volume \
 && install -D -m 0755 target/release/alpha-volume /out/alpha-volume

# ponytail: the tools come from Alpine 3.22's packages at build time; the image digest, which the
# policy pins, is what fixes them. Pin the package versions when the image is first published.
FROM --platform=linux/amd64 alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache cryptsetup e2fsprogs \
 && test -x /sbin/cryptsetup && test -x /sbin/mkfs.ext4 && test -x /bin/mount
COPY --from=build /out/alpha-volume /alpha-volume
ENTRYPOINT ["/alpha-volume"]
