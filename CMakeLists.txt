# ==============================================================================
# Satocialist Protocol: Master CMake Build Configuration
# ==============================================================================
#
# File: CMakeLists.txt
# Architecture Role: Orchestrates cross-platform compilation of the native node
#   daemon (satocialist_client), shared RPC library (libscl_rpc), libFuzzer
#   testing harnesses, benchmark suites, and Emscripten WebAssembly modules.
#
# Toolchain Requirements:
# - C Compiler: C11 compliant (Clang 12+ or GCC 10+ recommended)
# - C++ Compiler: C++14 compliant (enabling Google qsim and TVD kernels)
# - Emscripten SDK: 3.1.50+ for WebAssembly targets
#
# Numerical Determinism Invariant:
# - Floating-point contraction (-ffp-contract=off) and fast-math (-fno-fast-math)
#   are strictly disabled to prevent architecture-dependent compiler reassociations
#   that would invalidate cross-platform consensus and quantum simulation results.
# ==============================================================================

cmake_minimum_required(VERSION 3.16)
project(satocialist C)

# ==============================================================================
# 1. Language Standards & Compiler Compatibility Validation
# ==============================================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable C++ support for native Google qsim quantum simulation integration
enable_language(CXX)

# Prevent linker crashes from compiler ABI mismatches when sanitizers/fuzzers are active
if((ENABLE_ASAN OR ENABLE_TSAN OR ENABLE_UBSAN OR ENABLE_FUZZER) AND (NOT CMAKE_C_COMPILER_ID STREQUAL CMAKE_CXX_COMPILER_ID OR NOT CMAKE_C_COMPILER_VERSION STREQUAL CMAKE_CXX_COMPILER_VERSION))
    message(FATAL_ERROR "Compiler mismatch detected: C compiler is ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}, but CXX compiler is ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}.\n"
                        "When using advanced features like sanitizers or fuzzers, you must explicitly specify both compilers to match.\n"
                        "Example: cmake -DCMAKE_C_COMPILER=/opt/local/bin/clang-mp-16 -DCMAKE_CXX_COMPILER=/opt/local/bin/clang++-mp-16 ..")
endif()

# ==============================================================================
# 2. Strict Compilation Warnings & Floating-Point Determinism Flags
# ==============================================================================
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC -Wno-format -D_GNU_SOURCE")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fPIC -fno-fast-math -ffp-contract=off -Wno-format -D_GNU_SOURCE")

# Pass GCC-specific truncation flags only when compiling with GCC (Linux)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-format-truncation -Wno-stringop-truncation")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-format-truncation -Wno-stringop-truncation")
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unknown-warning-option")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unknown-warning-option")
endif()

# Enforce SSE2 math on x86_64 architectures to maintain strict IEEE 754 parity with ARM64 NEON
if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64)")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse2 -mfpmath=sse")
endif()

# Configure Address, Thread, and Undefined Behavior Analyzers
option(ENABLE_ASAN  "Enable AddressSanitizer"             OFF)
option(ENABLE_TSAN  "Enable ThreadSanitizer"              OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer"   OFF)

if(ENABLE_ASAN AND ENABLE_TSAN)
    message(FATAL_ERROR "ENABLE_ASAN and ENABLE_TSAN are mutually exclusive and cannot be enabled simultaneously.")
endif()

if(ENABLE_UBSAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined -fno-sanitize-recover=undefined")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined -fno-sanitize-recover=undefined")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=undefined")
    message(STATUS "UndefinedBehaviorSanitizer enabled")
endif()

if(ENABLE_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
    message(STATUS "AddressSanitizer enabled")
elseif(ENABLE_TSAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
    message(STATUS "ThreadSanitizer enabled")
endif()

# Establish a sensible default build type that optimizes while maintaining symbols
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Choose build type" FORCE)
endif()

# Support compile-time configuration of structural memory limits
set(CRYPTO_ARENA_SIZE_VAL "134217728" CACHE STRING "Size of the crypto arena in bytes (default 128MB)")
set(MAX_MESSAGE_SIZE_VAL "8388608" CACHE STRING "Maximum message size in bytes (default 8MB)")
add_definitions(-DCONFIG_CRYPTO_ARENA_SIZE=${CRYPTO_ARENA_SIZE_VAL})
add_definitions(-DCONFIG_MAX_MESSAGE_SIZE=${MAX_MESSAGE_SIZE_VAL})

# Configure macOS RPATH settings for portability
if(APPLE)
    set(CMAKE_MACOSX_RPATH ON)
    # Tells the dynamic linker to look in the directory of the executable itself
    list(APPEND CMAKE_INSTALL_RPATH "@executable_path")
endif()

# Discover libbpf and libxdp for XDP Shim (Linux-only)
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(LIBBPF libbpf)
    pkg_check_modules(LIBXDP libxdp)

    if(LIBBPF_FOUND AND LIBXDP_FOUND AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
        find_program(CLANG_EXE clang)
        if(CLANG_EXE)
            file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/common/network/xdp_prog.c "
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SCL_CID_LEN 20

#define SIPROUND do { \\
    v0 += v1; v1 = (v1 << 13) | (v1 >> (64 - 13)); v1 ^= v0; v0 = (v0 << 32) | (v0 >> (64 - 32)); \\
    v2 += v3; v3 = (v3 << 16) | (v3 >> (64 - 16)); v3 ^= v2; \\
    v0 += v3; v3 = (v3 << 21) | (v3 >> (64 - 21)); v3 ^= v0; \\
    v2 += v1; v1 = (v1 << 17) | (v1 >> (64 - 17)); v1 ^= v2; v2 = (v2 << 32) | (v2 >> (64 - 32)); \\
} while(0)

static __always_inline __u64 siphash24(const __u8 *in, __u32 inlen, const __u8 *key) {
    __u64 k0 = *(__u64 *)(key);
    __u64 k1 = *(__u64 *)(key + 8);
    __u64 v0 = k0 ^ 0x736f6d6570736575ULL;
    __u64 v1 = k1 ^ 0x646f72616e646f6dULL;
    __u64 v2 = k0 ^ 0x6c7967656e657261ULL;
    __u64 v3 = k1 ^ 0x7465646279746573ULL;
    const __u8 *end = in + inlen - (inlen % 8);
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (in == end) break;
        __u64 m = *(__u64 *)in;
        v3 ^= m;
        SIPROUND; SIPROUND;
        v0 ^= m;
        in += 8;
    }
    __u64 b = ((__u64)inlen) << 56;
    switch (inlen % 8) {
        case 7: b |= ((__u64)in[6]) << 48;
        case 6: b |= ((__u64)in[5]) << 40;
        case 5: b |= ((__u64)in[4]) << 32;
        case 4: b |= ((__u64)in[3]) << 24;
        case 3: b |= ((__u64)in[2]) << 16;
        case 2: b |= ((__u64)in[1]) << 8;
        case 1: b |= ((__u64)in[0]);
        case 0: break;
    }
    v3 ^= b;
    SIPROUND; SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[16]);
} secret_map SEC(\".maps\");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} maglev_map SEC(\".maps\");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsk_map SEC(\".maps\");

SEC(\"xdp\")
int scl_xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    __u8 *payload = (__u8 *)(udp + 1);
    if ((void *)(payload + 1 + SCL_CID_LEN) > data_end) return XDP_PASS;

    __u8 flags = payload[0];
    if ((flags & 0xC0) != 0xC0 && (flags & 0xC0) != 0x40) return XDP_PASS;

    __u32 key_idx = 0;
    __u8 *secret = bpf_map_lookup_elem(&secret_map, &key_idx);
    if (!secret) return XDP_PASS;

    __u8 cid[SCL_CID_LEN];
    __builtin_memcpy(cid, payload + 1, SCL_CID_LEN);

    __u64 hash = siphash24(cid, SCL_CID_LEN, secret);
    __u32 bucket = hash % 4096;

    __u32 *queue_id = bpf_map_lookup_elem(&maglev_map, &bucket);
    if (!queue_id) return XDP_PASS;

    return bpf_redirect_map(&xsk_map, *queue_id, XDP_PASS);
}

char _license[] SEC(\"license\") = \"GPL\";
")
            add_custom_command(
                OUTPUT xdp_prog.o
                COMMAND ${CLANG_EXE} -O2 -g -target bpf -c ${CMAKE_CURRENT_SOURCE_DIR}/common/network/xdp_prog.c -o xdp_prog.o
                DEPENDS common/network/xdp_prog.c
            )
            add_custom_target(xdp_prog ALL DEPENDS xdp_prog.o)
            add_definitions(-DUSE_XDP)
            include_directories(${LIBBPF_INCLUDE_DIRS} ${LIBXDP_INCLUDE_DIRS})
            link_directories(${LIBBPF_LIBRARY_DIRS} ${LIBXDP_LIBRARY_DIRS})
            message(STATUS "XDP Shim Enabled (libbpf and libxdp found)")
        endif()
    endif()
endif()

# ============================================================================
# Native Dependencies & Targets (Bypassed during WebAssembly compilation)
# ============================================================================
if(NOT EMSCRIPTEN)
    # Discover OpenSSL
    if(APPLE)
        # Hint paths for Homebrew installations (Intel and Apple Silicon)
        list(APPEND CMAKE_PREFIX_PATH
            "/usr/local/opt/openssl@1.1"
            "/opt/homebrew/opt/openssl@1.1"
            "/usr/local/opt/openssl@3"
            "/opt/homebrew/opt/openssl@3"
        )
    endif()
    find_package(OpenSSL REQUIRED)

    # Discover liboqs headers via standard pkg-config or standard system paths
    find_package(PkgConfig)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(OQS liboqs)
    endif()

    find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h
        PATHS
        ${OQS_INCLUDE_DIRS}
        /usr/local/include
        /opt/homebrew/include
        /usr/include
    )

    # Force CMake to find the static archive for liboqs to ensure portability
    find_library(OQS_LIB NAMES liboqs.a oqs liboqs liboqs.dylib liboqs.so
        PATHS
        ${OQS_LIBRARY_DIRS}
        /usr/local/lib
        /opt/homebrew/lib
        /usr/lib
    )

    # Discover libmdbx for persistent database engine
    find_path(MDBX_INCLUDE_DIR NAMES mdbx.h PATHS /usr/local/include /usr/include /opt/homebrew/include)
    # Force CMake to find the static archive for libmdbx to ensure portability
    find_library(MDBX_LIB NAMES libmdbx.a mdbx libmdbx.dylib libmdbx.so PATHS /usr/local/lib /usr/lib /opt/homebrew/lib)
    if(MDBX_INCLUDE_DIR AND MDBX_LIB)
        add_definitions(-DUSE_MDBX)
        message(STATUS "Found libmdbx at: ${MDBX_LIB}")
        # If dynamic linking was fallback-selected, append the library directory to RPATH
        if(APPLE)
            get_filename_component(MDBX_LIB_DIR "${MDBX_LIB}" DIRECTORY)
            list(APPEND CMAKE_INSTALL_RPATH "${MDBX_LIB_DIR}")
        endif()
    else()
        message(WARNING "libmdbx not found. Falling back to embedded file-backed storage engine.")
    endif()

    # Auto-locate qsim/simulator.h inside the project or system directories
    unset(QSIM_INCLUDE_DIR CACHE)
    set(QSIM_INCLUDE_DIR "")
    
    # 1. Scan the project folder recursively
    file(GLOB_RECURSE QSIM_HEADER_FILES "${CMAKE_SOURCE_DIR}/*simulator.h")
    if(QSIM_HEADER_FILES)
        list(GET QSIM_HEADER_FILES 0 FIRST_QSIM_HEADER)
        get_filename_component(QSIM_HEADER_DIR "${FIRST_QSIM_HEADER}" DIRECTORY)
        if(QSIM_HEADER_DIR MATCHES ".*/qsim$")
            get_filename_component(QSIM_INCLUDE_DIR "${QSIM_HEADER_DIR}/.." ABSOLUTE)
        else()
            set(QSIM_INCLUDE_DIR "${QSIM_HEADER_DIR}")
        endif()
    endif()

    # 2. Fallback to system search paths if not found in project
    if(NOT QSIM_INCLUDE_DIR)
        find_path(QSIM_INCLUDE_DIR NAMES qsim/simulator.h simulator.h
            PATHS
            /satocialistv4
            /opt/qsim
            /opt/local/include
            /opt/local
            /usr/local/include
            /opt/homebrew/include
            PATH_SUFFIXES qsim
        )
    endif()

    if(QSIM_INCLUDE_DIR)
        message(STATUS "Found Google qsim C++ headers at: ${QSIM_INCLUDE_DIR}")
        include_directories(${QSIM_INCLUDE_DIR} ${QSIM_INCLUDE_DIR}/qsim)
        add_definitions(-DHAS_QSIM_LIB)
    else()
        message(WARNING "Google qsim headers not found. Compiling with strict IEEE 754 C++ deterministic fallback.")
    endif()

    # Discover liblz4 with strong preference for static archive to ensure portability
    find_path(LZ4_INCLUDE_DIR NAMES lz4.h PATHS /usr/local/include /usr/include /opt/homebrew/include)
    # Prioritize static archive (.a) before dynamic libraries
    find_library(LZ4_LIB NAMES liblz4.a lz4 liblz4 PATHS /usr/local/lib /usr/lib /opt/homebrew/lib)
    if(NOT LZ4_LIB OR NOT LZ4_INCLUDE_DIR)
        message(FATAL_ERROR "liblz4 is missing. Please install the lz4 library.")
    endif()
    
    # Check if we found a dynamic library and warn about portability
    if(LZ4_LIB MATCHES "\\.(dylib|so)$")
        message(WARNING "Found dynamic LZ4 library at ${LZ4_LIB}. For portability, consider installing static liblz4.a")
        if(APPLE)
            get_filename_component(LZ4_LIB_DIR "${LZ4_LIB}" DIRECTORY)
            list(APPEND CMAKE_INSTALL_RPATH "${LZ4_LIB_DIR}")
        endif()
    endif()
    message(STATUS "Found liblz4 at: ${LZ4_LIB}")

    # Validate liboqs was found
    if(NOT OQS_LIB OR NOT OQS_INCLUDE_DIR)
        message(FATAL_ERROR "liboqs is missing. Please compile and install the open-quantum-safe library.")
    endif()

    # Check if we found a dynamic liboqs and warn about portability
    if(OQS_LIB MATCHES "\\.(dylib|so)$")
        message(WARNING "Found dynamic liboqs library at ${OQS_LIB}. For portability, consider installing static liboqs.a")
        if(APPLE)
            get_filename_component(OQS_LIB_DIR "${OQS_LIB}" DIRECTORY)
            list(APPEND CMAKE_INSTALL_RPATH "${OQS_LIB_DIR}")
        endif()
    endif()

    # Log which library format was resolved
    message(STATUS "Resolved liboqs library at: ${OQS_LIB}")

    include_directories(
        common
        common/user
        common/blockchain
        common/network
        common/crypto
        common/consensus
        client/core
        client/ui
        client/network
        client/state
        ${OPENSSL_INCLUDE_DIR}
        ${OQS_INCLUDE_DIR}
        ${LZ4_INCLUDE_DIR}
    )

    set(COMMON_SRCS
        common/utils.c
        common/user/user.c
        common/blockchain/blockchain.c
        common/blockchain/hash_table.c
        common/blockchain/mmr.c
        common/blockchain/database.c
        common/network/protocol.c
        common/network/queue.c
        common/network/network.c
        common/network/websocket_bridge.c
        common/crypto/crypto.c
        common/crypto/quantum_qsim.cpp
        common/crypto/quantum_tvd.cpp
        common/network/quantum_tvd_rpc.c
        common/consensus/consensus.c
    )

    # Enable AVX2 vectorization for x86_64 architectures for TVD Kernel
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64)")
        set_source_files_properties(common/crypto/quantum_tvd.cpp PROPERTIES COMPILE_FLAGS "-mavx2 -mfma")
    endif()

    set(CLIENT_SRCS
        client/ui/client_aux.c
        client/network/client_network.c
        client/state/client_state.c
        client/client.c
        client/core/game_state.c
    )

    set(RPC_SRCS
        common/network/rpc.c
    )

    add_executable(satocialist_client ${COMMON_SRCS} ${CLIENT_SRCS} ${RPC_SRCS})

    option(ENABLE_FUZZER "Build libFuzzer harnesses" OFF)
    if(ENABLE_FUZZER)
        if(APPLE)
            execute_process(COMMAND ${CMAKE_C_COMPILER} -print-file-name=libclang_rt.fuzzer_osx.a OUTPUT_VARIABLE FUZZER_LIB_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)
            if(NOT EXISTS "${FUZZER_LIB_PATH}")
                message(WARNING "libFuzzer runtime not found at ${FUZZER_LIB_PATH}. Apple strips this from Xcode. Disabling ENABLE_FUZZER.")
                set(ENABLE_FUZZER OFF CACHE BOOL "Build libFuzzer harnesses" FORCE)
                set(ENABLE_FUZZER OFF)
            endif()
        endif()
    endif()

    if(ENABLE_FUZZER)
        if(ENABLE_TSAN)
            set(FUZZER_SAN "thread")
        else()
            set(FUZZER_SAN "address")
        endif()

        # Instrument all common objects with fuzzer coverage, but do not link the fuzzer entrypoint globally
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=fuzzer-no-link,${FUZZER_SAN} -g -O3 -fno-omit-frame-pointer")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=fuzzer-no-link,${FUZZER_SAN} -g -O3 -fno-omit-frame-pointer")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=fuzzer-no-link,${FUZZER_SAN}")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=fuzzer-no-link,${FUZZER_SAN}")
        
        # Added common/network/scl_rpc_ffi.c to provide FFI parser calls and resolve unresolved common stubs
        add_executable(rpc_fuzzer tests/rpc_fuzzer.c common/network/scl_rpc_ffi.c ${CLIENT_SRCS} ${COMMON_SRCS} ${RPC_SRCS})
        target_compile_definitions(rpc_fuzzer PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        target_link_options(rpc_fuzzer PRIVATE -fsanitize=fuzzer,${FUZZER_SAN})
        target_link_libraries(rpc_fuzzer
            ${OPENSSL_CRYPTO_LIBRARY}
            ${OPENSSL_SSL_LIBRARY}
            ${OQS_LIB}
            ${MDBX_LIB}
            ${LZ4_LIB}
            pthread
            m
        )

        add_executable(network_fuzzer
            tests/network_fuzzer.c
            common/network/scl_rpc_ffi.c
            ${CLIENT_SRCS}
            ${COMMON_SRCS}
            ${RPC_SRCS}
        )
        
        target_compile_definitions(network_fuzzer PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        target_link_options(network_fuzzer PRIVATE -fsanitize=fuzzer,${FUZZER_SAN})
        target_link_libraries(network_fuzzer
            ${OPENSSL_CRYPTO_LIBRARY}
            ${OPENSSL_SSL_LIBRARY}
            ${OQS_LIB}
            ${MDBX_LIB}
            ${LZ4_LIB}
            pthread
            m
        )

        add_executable(consensus_fuzzer
            tests/consensus_fuzzer.c
            common/network/scl_rpc_ffi.c
            ${CLIENT_SRCS}
            ${COMMON_SRCS}
            ${RPC_SRCS}
        )
        
        target_compile_definitions(consensus_fuzzer PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        target_link_options(consensus_fuzzer PRIVATE -fsanitize=fuzzer,${FUZZER_SAN})
        target_link_libraries(consensus_fuzzer
            ${OPENSSL_CRYPTO_LIBRARY}
            ${OPENSSL_SSL_LIBRARY}
            ${OQS_LIB}
            ${MDBX_LIB}
            ${LZ4_LIB}
            pthread
            m
        )

        add_executable(crypto_zk_fuzzer
            tests/crypto_zk_fuzzer.c
            common/network/scl_rpc_ffi.c
            ${CLIENT_SRCS}
            ${COMMON_SRCS}
            ${RPC_SRCS}
        )

        target_compile_definitions(crypto_zk_fuzzer PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION CRYPTO_ZK_FUZZER)
        target_link_options(crypto_zk_fuzzer PRIVATE -fsanitize=fuzzer,${FUZZER_SAN})
        target_link_libraries(crypto_zk_fuzzer
            ${OPENSSL_CRYPTO_LIBRARY}
            ${OPENSSL_SSL_LIBRARY}
            ${OQS_LIB}
            ${MDBX_LIB}
            ${LZ4_LIB}
            pthread
            m
        )

        add_executable(quantum_tvd_fuzzer
            tests/quantum_tvd_fuzzer.c
            common/network/scl_rpc_ffi.c
            ${CLIENT_SRCS}
            ${COMMON_SRCS}
            ${RPC_SRCS}
        )
        
        target_compile_definitions(quantum_tvd_fuzzer PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        target_link_options(quantum_tvd_fuzzer PRIVATE -fsanitize=fuzzer,${FUZZER_SAN})
        target_link_libraries(quantum_tvd_fuzzer
            ${OPENSSL_CRYPTO_LIBRARY}
            ${OPENSSL_SSL_LIBRARY}
            ${OQS_LIB}
            ${MDBX_LIB}
            ${LZ4_LIB}
            pthread
            m
        )
    endif()

    # Build libscl_rpc.so FFI
    add_library(scl_rpc SHARED common/network/scl_rpc_ffi.c ${COMMON_SRCS})
    target_link_libraries(scl_rpc
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
        ${OQS_LIB}
        ${MDBX_LIB}
        ${LZ4_LIB}
        pthread
        m
    )
    if(APPLE)
        target_link_options(scl_rpc PRIVATE "-Wl,-rpath,@executable_path")
    endif()

    target_link_libraries(satocialist_client
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
        ${OQS_LIB}
        ${MDBX_LIB}
        ${LZ4_LIB}
        pthread
        m
    )

    if(USE_XDP)
        target_link_libraries(satocialist_client ${LIBBPF_LIBRARIES} ${LIBXDP_LIBRARIES})
        add_dependencies(satocialist_client xdp_prog)
    endif()

    # Add runpath option for macOS dynamic fallback linking
    if(APPLE)
        target_link_options(satocialist_client PRIVATE "-Wl,-rpath,@executable_path")
    endif()

    # Add the RPC integration test executable
    add_executable(test_rpc_pipelines tests/test_rpc_pipelines.c)

    # Link against the FFI shared library target and required dependencies (including LZ4)
    target_link_libraries(test_rpc_pipelines
        scl_rpc
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OQS_LIB}
        ${MDBX_LIB}
        ${LZ4_LIB}
        pthread
        m
    )

    # Enforce the runtime path for dynamic linking on macOS
    if(APPLE)
        target_link_options(test_rpc_pipelines PRIVATE "-Wl,-rpath,@executable_path")
    endif()

    # ============================================================================
    # Unit and Integration Test Runner Configuration
    # ============================================================================
    # Added common/network/scl_rpc_ffi.c, client/state/client_state.c and client/core/game_state.c
    # to satisfy FFI bindings, state management, and simulation triggers.
    add_executable(unit_tests
        tests/unit_tests.c
        common/network/scl_rpc_ffi.c
        ${CLIENT_SRCS}
        ${COMMON_SRCS}
        ${RPC_SRCS}
    )

    # Pin the fuzzer macro to safely bypass dynamic mock-linking stubs inside scl_rpc_ffi.c
    target_compile_definitions(unit_tests PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION SCL_UNIT_TEST)

    target_link_libraries(unit_tests
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
        ${OQS_LIB}
        ${MDBX_LIB}
        ${LZ4_LIB}
        pthread
        m
    )

    # Handle dynamic fallback lookups on macOS
    if(APPLE)
        target_link_options(unit_tests PRIVATE "-Wl,-rpath,@executable_path")
    endif()

    # ============================================================================
    # Benchmark Test Target
    # ============================================================================
    add_executable(benchmark_tests
        tests/benchmark_tests.c
        common/network/scl_rpc_ffi.c
        ${CLIENT_SRCS}
        ${COMMON_SRCS}
        ${RPC_SRCS}
    )

    target_compile_definitions(benchmark_tests PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION SCL_UNIT_TEST)

    target_link_libraries(benchmark_tests
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
        ${OQS_LIB}
        ${MDBX_LIB}
        ${LZ4_LIB}
        pthread
        m
    )

    if(APPLE)
        target_link_options(benchmark_tests PRIVATE "-Wl,-rpath,@executable_path")
    endif()

    # ============================================================================
    # Quantum TVD Verification Engine Unit Test Target
    # ============================================================================
    add_executable(test_quantum_tvd
        tests/test_quantum_tvd.c
        common/network/scl_rpc_ffi.c
        ${CLIENT_SRCS}
        ${COMMON_SRCS}
        ${RPC_SRCS}
    )

    target_compile_definitions(test_quantum_tvd PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION SCL_UNIT_TEST)

    target_link_libraries(test_quantum_tvd
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
        ${OQS_LIB}
        ${MDBX_LIB}
        ${LZ4_LIB}
        pthread
        m
    )

    if(APPLE)
        target_link_options(test_quantum_tvd PRIVATE "-Wl,-rpath,@executable_path")
    endif()

    # ============================================================================
    # Coalition Resistance & Quantum Simulation Unit Test Target
    # ============================================================================
    add_executable(test_coalition_resistance
        tests/test_coalition_resistance.c
        common/network/scl_rpc_ffi.c
        ${CLIENT_SRCS}
        ${COMMON_SRCS}
        ${RPC_SRCS}
    )

    target_compile_definitions(test_coalition_resistance PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION SCL_UNIT_TEST)

    target_link_libraries(test_coalition_resistance
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
        ${OQS_LIB}
        ${MDBX_LIB}
        ${LZ4_LIB}
        pthread
        m
    )

    if(APPLE)
        target_link_options(test_coalition_resistance PRIVATE "-Wl,-rpath,@executable_path")
    endif()

else()
    # ============================================================================
    # Emscripten / WebAssembly Compilation Target
    # ============================================================================
    message(STATUS "Configuring WebAssembly target for libscl_rpc")

    set(WASM_OPENSSL_INCLUDE_DIR "" CACHE PATH "Path to Wasm-compiled OpenSSL include directory")
    set(WASM_OPENSSL_LIB "" CACHE FILEPATH "Path to Wasm-compiled libcrypto.a")
    set(WASM_OQS_INCLUDE_DIR "" CACHE PATH "Path to Wasm-compiled liboqs include directory")
    set(WASM_OQS_LIB "" CACHE FILEPATH "Path to Wasm-compiled liboqs.a")
    set(WASM_LZ4_INCLUDE_DIR "" CACHE PATH "Path to Wasm-compiled liblz4 include directory")
    set(WASM_LZ4_LIB "" CACHE FILEPATH "Path to Wasm-compiled liblz4.a")

    include_directories(
        common
        common/user
        common/blockchain
        common/network
        common/crypto
        common/consensus
        client/core
        client/ui
        client/network
        client/state
        ${CMAKE_SOURCE_DIR}/wasm/dummy_include
        ${WASM_OPENSSL_INCLUDE_DIR}
        ${WASM_OQS_INCLUDE_DIR}
        ${WASM_LZ4_INCLUDE_DIR}
    )

    add_executable(libscl_rpc
        client/ui/wasm_bindings.c
        common/network/scl_rpc_ffi.c
        common/network/protocol.c
        common/utils.c
        common/crypto/crypto.c
        common/blockchain/mmr.c
    )

    target_link_libraries(libscl_rpc
        ${WASM_OPENSSL_LIB}
        ${WASM_OQS_LIB}
        ${WASM_LZ4_LIB}
    )

    target_compile_options(libscl_rpc PRIVATE "-O3")
        target_link_options(libscl_rpc PRIVATE
        "-O3"
        "-D__linux__"
        "-D__EMCC__"
        "-sALLOW_MEMORY_GROWTH=1"
        "-sWASM_BIGINT=1"
        "-sMODULARIZE=1"
        "-sEXPORT_NAME='Module'"
        "-sERROR_ON_UNDEFINED_SYMBOLS=0"
        "-sSTACK_SIZE=5242880"
        "-sEXPORTED_RUNTIME_METHODS=['ccall','cwrap','HEAP8','HEAPU8']"
        "-sEXPORTED_FUNCTIONS=['_wasm_malloc','_wasm_free','_wasm_secure_wipe','_wasm_parse_frame','_wasm_destroy_parser','_wasm_prf_evaluate','_wasm_match_transaction','_wasm_decrypt_payload','_wasm_parser_get_flags','_wasm_parser_get_method_id','_wasm_parser_get_payload_ref','_wasm_parser_get_error','_wasm_extract_block_commitments','_wasm_verify_checksum','_wasm_parser_get_version','_wasm_parser_get_status','_wasm_parser_get_cursor','_wasm_parser_get_request_id','_wasm_bdlop_commit','_wasm_bdlop_decrypt','_wasm_sha256','_wasm_builder_create','_wasm_builder_set_flags','_wasm_builder_set_cursor','_wasm_builder_append_args','_wasm_builder_sign','_wasm_builder_finalize','_wasm_builder_destroy','_wasm_frame_balance_query','_wasm_frame_recent_txs','_wasm_frame_get_tx','_wasm_frame_chain_info','_wasm_frame_valuations_query','_wasm_frame_audit_query','_wasm_frame_block_query','_wasm_frame_quantum_tvd_audit','_wasm_frame_autopilot','_wasm_dilithium_generate_keypair','_wasm_dilithium_sign','_wasm_prf_keygen','_wasm_verify_mmr_proof','_wasm_generate_zk_prf_proof','_wasm_generate_centinel_proof','_wasm_compute_threshold_pubkey']"
        "-o" "${CMAKE_BINARY_DIR}/libscl_rpc.js"
    )
endif()
