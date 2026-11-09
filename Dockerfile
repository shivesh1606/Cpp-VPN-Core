FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libgtest-dev \
    libsodium-dev \
    libssl-dev \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*
# curl: nodes download the revocation list with it (design 03 section 6; auth.revocation_url)

WORKDIR /src
COPY . .

# Build, then run the GoogleTest suite: a failing test fails the image build.
# libsodium and OpenSSL are linked statically (libsodium.a, libcrypto.a). WITH_OPENSSL=ON builds
# the second AEAD implementation, so the cross-implementation tests run here (design 01, C5).
RUN mkdir -p build && cd build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release -DWITH_OPENSSL=ON \
    && make -j$(nproc) \
    && ctest --output-on-failure

# Output stage — just the binary
FROM scratch
COPY --from=builder /src/build/vpn_server /vpn_server
