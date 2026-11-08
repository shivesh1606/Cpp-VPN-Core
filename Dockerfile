FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libgtest-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build, then run the GoogleTest suite: a failing test fails the image build
RUN mkdir -p build && cd build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release \
    && make -j$(nproc) \
    && ctest --output-on-failure

# Output stage — just the binary
FROM scratch
COPY --from=builder /src/build/vpn_server /vpn_server
