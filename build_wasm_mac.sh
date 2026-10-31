#!/bin/bash
# ==============================================================================
# Satocialist Protocol: Local macOS WebAssembly Build & Cross-Compilation Script
# ==============================================================================
# File: build_wasm_mac.sh
# Architecture Role: Manages native local compilation on macOS (Apple Silicon /
#   Intel x86_64) without requiring Docker daemon virtualization.
#
# Operational Sequence:
# 1. Installs or activates Emscripten SDK (emsdk) locally in .wasm_build/.
# 2. Configures unified installation prefix (.wasm_build/opt/wasm).
# 3. Cross-compiles OpenSSL 1.1.1w (no-asm, no-threads, linux-generic32).
# 4. Cross-compiles LZ4 static archive (liblz4.a).
# 5. Cross-compiles LibOQS v0.11.0 (generic target, OpenSSL integration).
# 6. Executes CMake Emscripten toolchain to output libscl_rpc.js and libscl_rpc.wasm.
# 7. Stages deployment artifacts into client/ui/.
# ==============================================================================
set -e

echo "=> Preparing Local WebAssembly Build Environment..."
mkdir -p .wasm_build
cd .wasm_build

# 1. Install or activate Emscripten SDK locally
if [ ! -d "emsdk" ]; then
    echo "=> Cloning Emscripten SDK..."
    git clone --depth 1 https://github.com/emscripten-core/emsdk.git
fi
cd emsdk
./emsdk install latest
./emsdk activate latest
source ./emsdk_env.sh
cd ..

WASM_PREFIX="$(pwd)/opt/wasm"
mkdir -p "$WASM_PREFIX/include" "$WASM_PREFIX/lib"

# 2. Cross-compile OpenSSL 1.1.1w for WebAssembly
echo "=> Cross-compiling OpenSSL..."
if [ ! -f "$WASM_PREFIX/lib/libcrypto.a" ] || [ ! -f "$WASM_PREFIX/lib/libssl.a" ]; then
    if [ ! -d "openssl" ]; then
        git clone --depth 1 --branch OpenSSL_1_1_1w https://github.com/openssl/openssl.git
    fi
    cd openssl
    make clean || true
    
    CC=emcc CXX=em++ AR=emar RANLIB=emranlib ./Configure linux-generic32 \
        no-asm no-threads no-engine no-dso no-hw no-shared --prefix="$WASM_PREFIX"
    
    make build_generated
    make libcrypto.a libssl.a -j$(sysctl -n hw.ncpu)
    make install_dev
    cd ..
fi

# 3. Cross-compile LZ4 for WebAssembly
echo "=> Cross-compiling LZ4..."
if [ ! -f "$WASM_PREFIX/lib/liblz4.a" ]; then
    if [ ! -d "lz4" ]; then
        git clone --depth 1 https://github.com/lz4/lz4.git
    fi
    cd lz4
    make clean || true
    CC=emcc CXX=em++ AR=emar make -j$(sysctl -n hw.ncpu) lib
    cp lib/lz4.h "$WASM_PREFIX/include/"
    cp lib/liblz4.a "$WASM_PREFIX/lib/"
    cd ..
fi

# 4. Cross-compile LibOQS for WebAssembly
echo "=> Cross-compiling LibOQS..."
if [ ! -f "$WASM_PREFIX/lib/liboqs.a" ]; then
    if [ ! -d "liboqs" ]; then
        git clone --depth 1 --branch 0.11.0 https://github.com/open-quantum-safe/liboqs.git
    fi
    cd liboqs
    rm -rf build
    mkdir -p build && cd build
    
    emcmake cmake -DOQS_USE_OPENSSL=ON \
        -DOPENSSL_ROOT_DIR="$WASM_PREFIX" \
        -DOPENSSL_INCLUDE_DIR="$WASM_PREFIX/include" \
        -DOPENSSL_CRYPTO_LIBRARY="$WASM_PREFIX/lib/libcrypto.a" \
        -DOPENSSL_SSL_LIBRARY="$WASM_PREFIX/lib/libssl.a" \
        -DBUILD_SHARED_LIBS=OFF \
        -DOQS_OPT_TARGET=generic \
        -DCMAKE_INSTALL_PREFIX="$WASM_PREFIX" ..
        
    emmake make -j$(sysctl -n hw.ncpu) install
    cd ../..
fi

# 5. Compile the Centinel Network WebAssembly Module
echo "=> Compiling the Centinel Network Wasm FFI Module..."
cd .. # Back to repository root
mkdir -p wasm/dummy_include
mkdir -p build_wasm && cd build_wasm

emcmake cmake .. \
    -DWASM_OPENSSL_INCLUDE_DIR="$WASM_PREFIX/include" \
    -DWASM_OPENSSL_LIB="$WASM_PREFIX/lib/libcrypto.a" \
    -DWASM_LZ4_INCLUDE_DIR="$WASM_PREFIX/include" \
    -DWASM_LZ4_LIB="$WASM_PREFIX/lib/liblz4.a" \
    -DWASM_OQS_INCLUDE_DIR="$WASM_PREFIX/include" \
    -DWASM_OQS_LIB="$WASM_PREFIX/lib/liboqs.a"

emmake make libscl_rpc -j$(sysctl -n hw.ncpu)

# 6. Extract results to client/ui/
echo "=> Staging libscl_rpc.js and libscl_rpc.wasm to client/ui..."
cp libscl_rpc.js ../client/ui/libscl_rpc.js
cp libscl_rpc.wasm ../client/ui/libscl_rpc.wasm

echo "=> Success! The frontend Localized Decryption WebWorker is now equipped."
