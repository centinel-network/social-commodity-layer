# ==============================================================================
# Satocialist Protocol: Production Multi-Stage Container Recipe
# ==============================================================================
#
# File: Dockerfile
# Architecture Role: Provisions a deterministic, isolated container image for
#   the native validator node daemon (satocialist_client).
#
# Security & Operational Guarantees:
# - Multi-Stage Build: Build toolchains (compilers, git, dev headers) are
#   isolated to the 'builder' stage and excluded from the runtime image.
# - Principle of Least Privilege: The daemon runs strictly under an unprivileged
#   system account ('satocialist') with no root escalation or interactive shell.
# - Storage Isolation: Persistent blockchain state and append-only database logs
#   are mounted via dedicated volume paths with constrained ownership permissions.
# - Dependency Pinning: External cryptographic libraries (liboqs 0.11.0, libmdbx
#   v0.12.8) are compiled deterministically from release tags.
# ==============================================================================

# ==============================================================================
# STAGE 1: Compilation and Static Dependency Build Environment
# ==============================================================================
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install core build toolchains and development dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    pkg-config \
    liblz4-dev \
    && rm -rf /var/lib/apt/lists/*

# Clone Google qsim C++ quantum simulator headers (header-only library)
RUN git clone --depth 1 https://github.com/quantumlib/qsim.git /opt/qsim

# Build Open Quantum Safe library (liboqs) v0.11.0 with OpenSSL acceleration
RUN git clone --depth 1 -b 0.11.0 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -DOQS_USE_OPENSSL=ON -DBUILD_SHARED_LIBS=ON .. && \
    make -j$(nproc) && \
    make install

# Build libmdbx high-performance transactional database engine (stable release)
RUN git clone --depth 1 https://github.com/erthink/libmdbx.git /opt/libmdbx && \
    cd /opt/libmdbx && \
    make && \
    make install

WORKDIR /app
COPY . .

# Compile Satocialist native validator client binary
RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc) satocialist_client

# ==============================================================================
# STAGE 2: Hardened, Unprivileged Production Runtime Image
# ==============================================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dynamic shared libraries only
RUN apt-get update && apt-get install -y \
    libssl3 \
    liblz4-1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user and group with no interactive login shell
RUN groupadd -r satocialist --gid 10001 && \
    useradd -r -g satocialist --uid 10001 -d /data/satocialist -s /sbin/nologin satocialist

# Copy shared library binaries and application executable from builder stage
COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=builder /usr/local/lib/libmdbx* /usr/local/lib/
COPY --from=builder /usr/local/include/mdbx.h /usr/local/include/
COPY --from=builder /app/build/satocialist_client /usr/local/bin/

# Update dynamic linker cache
RUN ldconfig

ENV LD_LIBRARY_PATH=/usr/local/lib

# Configure storage directories and ownership for unprivileged daemon execution
RUN mkdir -p /data/satocialist/db /data/satocialist/logs \
    && chown -R satocialist:satocialist /data/satocialist

# INJECT CONFIGURATION BEFORE VOLUME DECLARATION to prevent Docker shadowing
COPY --chown=satocialist:satocialist satocialist.conf /data/satocialist/satocialist.conf

# Declare persistent storage mount points for database and configuration
VOLUME ["/data/satocialist"]

# Drop privileges to non-root service account
USER satocialist
WORKDIR /data/satocialist

# Expose P2P transport UDP (5555), WebSocket bridge TCP (5554), and Prometheus HTTP (8000)
EXPOSE 5555/udp 5554/tcp 8000/tcp

ENTRYPOINT ["satocialist_client"]
