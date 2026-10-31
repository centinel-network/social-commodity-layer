#!/bin/bash
# ==============================================================================
# Satocialist Protocol: Containerized WebAssembly Build & Deployment Script
# ==============================================================================
# File: build_wasm.sh
# Architecture Role: Builds the Dockerized WebAssembly toolchain image
#   (centinel-wasm-builder) from Dockerfile.wasm, extracts the compiled
#   WebAssembly artifacts (libscl_rpc.js, libscl_rpc.wasm), and stages them
#   into the browser UI distribution directory (client/ui/).
#
# Execution Environment: Linux / macOS host with Docker Engine active.
# Error Handling: Aborts immediately on nonzero exit code (set -e).
# ==============================================================================
set -e

echo "=> Building WebAssembly environment and Centinel dependencies (OpenSSL, LZ4, LibOQS)..."
echo "=> (This may take 2-4 minutes depending on your CPU)"
docker build -t centinel-wasm-builder -f Dockerfile.wasm .

echo "=> Extracting libscl_rpc.js and libscl_rpc.wasm to client/ui..."
docker create --name temp-wasm-container centinel-wasm-builder
docker cp temp-wasm-container:/app/build_wasm/libscl_rpc.js client/ui/
docker cp temp-wasm-container:/app/build_wasm/libscl_rpc.wasm client/ui/
docker rm temp-wasm-container

echo "=> Success! The frontend Localized Decryption WebWorker is now equipped."
