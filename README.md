# Centinel Network Node

Welcome to the **Centinel Network** project! This repository contains the core node client (`satocialist_client`), advanced cryptographic fuzzers and a proprietary UDP-based peer-to-peer transport layer.

> **⚠️ Platform Support Notice:**
> The Centinel Network codebase is written in highly portable C/C++ and is inherently designed to be cross-platform (supporting Linux, Windows, etc.). However, due to current limited testing resources, this repository and deployment guide are **designed and tested exclusively for macOS**. If you are on Linux or Windows, the code should compile, but your mileage may vary. We highly welcome community contributions to validate and document execution on other operating systems!

---

## 📋 Table of Contents
1. [Prerequisites & Dependencies](#-prerequisites--dependencies)
2. [Quick Start: Docker (Easiest)](#-quick-start-docker-easiest)
3. [Quick Start: Native macOS Build](#-quick-start-native-macos-build)
4. [Running the Node](#-running-the-node)
5. [Where Data is Stored](#-where-data-is-stored)
6. [Testing & Advanced Fuzzing](#-testing--advanced-fuzzing)

---

## 📦 Prerequisites & Dependencies

To build the project natively, your system requires several foundational build tools and cryptographic libraries.

### 1. System Packages (macOS via Homebrew)
Open your terminal and install the base development dependencies:
```bash
brew update
brew install cmake openssl lz4 pkg-config llvm
```
*(Note: If you are attempting this on Ubuntu/Debian, the equivalent is `sudo apt install build-essential cmake git libssl-dev pkg-config liblz4-dev`)*

### 2. External Cryptography & Database Libraries
The Centinel node relies on three specific libraries that must be compiled from source to ensure optimal vectorization and performance:

#### A. Quantum Safe Cryptography (`liboqs`)
We use `liboqs` (v0.11.0) for Post-Quantum cryptographic primitives.
```bash
git clone --depth 1 -b 0.11.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DOQS_USE_OPENSSL=ON -DBUILD_SHARED_LIBS=ON ..
make -j$(sysctl -n hw.ncpu)
sudo make install
```

#### B. Google Quantum Simulator (`qsim`)
The node executes quantum statevector simulations directly on the CPU using Google's native `qsim` C++ library to guarantee ultra-low latency.
```bash
# Clone the header-only repository to your local machine
sudo git clone --depth 1 https://github.com/quantumlib/qsim.git /opt/qsim
```
*(Note: If CMake does not find these headers in `/opt/qsim` during the build process, the node will gracefully compile using a strictly standardized IEEE 754 deterministic C++ fallback).*

#### C. Lightning Memory-Mapped Database (`libmdbx`)
We use `libmdbx` for blazing-fast, ACID-compliant on-disk storage.
```bash
git clone --depth 1 https://github.com/erthink/libmdbx.git
cd libmdbx
make
sudo make install
```

---

## 🐳 Quick Start: Docker (Easiest)

If you prefer not to manage dependencies on your host machine, you can build and run the node seamlessly inside an isolated Docker container. The included Dockerfile automatically compiles all the dependencies listed above.

### 1. Build the Docker Image
From the project root directory (where the `Dockerfile` is located), execute:
```bash
docker build -t satocialist-node .
```

### 2. Run the Container
The transport protocol operates heavily over UDP, so you must expose the configured port as a UDP port.

```bash
docker run -d \
  --name satocialist-bootstrap \
  -p 5555:5555/udp \
  -p 8000:8000/tcp \
  -v satocialist_data:/data/satocialist \
  satocialist-node -i 0.0.0.0 -p 5555 -l info
```

### 3. Tuning Host OS UDP Buffers (Crucial for Docker)
To prevent silent packet drops during dense Distributed Key Generation (DKG) phases, ensure your host OS allows large socket buffers.

**On macOS:**
```bash
sudo sysctl -w kern.ipc.maxsockbuf=16777216
```
**On Linux (if applicable):**
```bash
sudo sysctl -w net.core.rmem_max=33554432
sudo sysctl -w net.core.wmem_max=33554432
```

---

## 🖥️ Quick Start: Native macOS Build

Once you have installed the [Prerequisites & Dependencies](#-prerequisites--dependencies), you can compile the client natively.

Ensure your project directory looks like this:
```text
project_root/
├── CMakeLists.txt
├── Dockerfile
├── Dockerfile.wasm
├── build_wasm.sh
├── build_wasm_mac.sh
├── satocialist.conf
│
├── tests/
│   ├── benchmark_tests.c
│   ├── test_rpc_pipelines.c
│   ├── test_coalition_resistance.c
│   ├── unit_tests.c
│   ├── test_quantum_tvd.c
│
├── common/
│   ├── constants.h
│   ├── types.h
│   ├── utils.h
│   ├── utils.c
│   │
│   ├── user/
│   │   ├── user.c
│   │   └── user.h
│   │
│   ├── blockchain/
│   │   ├── database.c
│   │   ├── database.h
│   │   ├── blockchain.c
│   │   ├── blockchain.h
│   │   ├── hash_table.c
│   │   ├── hash_table.h
│   │   ├── mmr.c
│   │   └── mmr.h
│   │
│   ├── network/
│   │   ├── protocol.c
│   │   ├── protocol.h
│   │   ├── queue.c
│   │   ├── queue.h
│   │   ├── network.c
│   │   ├── network.h
│   │   ├── rpc.h
│   │   ├── rpc.c
│   │   ├── scl_rpc_ffi.c
│   │   ├── scl_rpc_ffi_export.h
│   │   ├── websocket_bridge.c
│   │   ├── websocket_bridge.h
│   │   └── quantum_tvd_rpc.c
│   │
│   ├── crypto/
│   │   ├── crypto.c
│   │   ├── crypto.h
│   │   ├── quantum_qsim.cpp
│   │   ├── quantum_qsim.h
│   │   ├── quantum_tvd.h
│   │   └── quantum_tvd.cpp
│   │
│   └── consensus/
│       ├── consensus.c
│       └── consensus.h
│
└── client/
    ├── client.c
    │
    ├── ui/
    │   ├── client_aux.c
    │   ├── client_aux.h
    │   ├── wasm_bindings.c
    │   ├── auditor.worker.js
    │   ├── auditor_client.js
    │   ├── mmr_canvas_renderer.js
    │   ├── explorer_app.js
    │   ├── index.html
    │   ├── SCL_Architecture_Validation_Report.html
    │   └── SCL_Simulation_Specification.html
    │
    ├── network/
    │   ├── client_network.c
    │   └── client_network.h
    │
    ├── state/
    │   ├── client_state.c
    │   └── client_state.h
    │
    └── core/
        ├── game_state.c
        └── game_state.h
```

### Build Steps:
```bash
# 1. Create a build directory to keep the source tree clean
mkdir -p build && cd build

# 2. Generate build files (Release optimization)
cmake -DCMAKE_BUILD_TYPE=Release ..

# Note: If you want to use the specific MacPorts clang-16 compiler:
# cmake -DCMAKE_C_COMPILER=/opt/local/bin/clang-mp-16 -DCMAKE_CXX_COMPILER=/opt/local/bin/clang++-mp-16 -DCMAKE_BUILD_TYPE=Release ..

# 3. Compile the target binary utilizing all available CPU cores
make -j$(sysctl -n hw.ncpu) satocialist_client
```

---

## 🚀 Running the Node

Once compiled, the binary `satocialist_client` will be generated inside the `build` directory (or `/usr/local/bin/` if installed via Docker).

You can execute it using CLI arguments parsed by `getopt`:

**Using the default configuration file:**
*(Ensure `satocialist.conf` is in your working directory)*
```bash
./satocialist_client -c ../satocialist.conf
```

**Overriding parameters via command-line:**
```bash
# Run with debug logging level on localhost port 5555
./satocialist_client -i 127.0.0.1 -p 5555 -l debug
```

---

## 🗄️ Where Data is Stored

When compiled with `libmdbx` enabled (`-DUSE_MDBX`), all data is stored inside the database directory specified by `db_path` in `scl_db_init()`.
* **Docker default:** `/data/satocialist/db`
* **Local default:** `./db/`

`libmdbx` uses a single memory-mapped environment containing two files:
1. `mdbx.dat`: The unified memory-mapped binary file containing all tables, indexes, blocks, UTXOs, and state trees.
2. `mdbx.lck`: The lockfile used for multi-process/multi-thread POSIX synchronization.

> *Fallback Note: If `libmdbx` is not found during CMake configuration, the system safely falls back to standard flat files (e.g., `_coins.bin`, `_blocks.bin`, etc.).*

---

## 🧪 Testing & Advanced Fuzzing

The repository includes a suite of integrated libFuzzer targets to ensure the node is completely watertight under extreme bounds. To build the fuzzers, enable the `-DENABLE_FUZZER=ON` flag during the `cmake` step.

### Unit Tests
A successful run prints the test lifecycle and exits gracefully with `0`. Failures print the exact file/line number and `exit(1)`.
```bash
./unit_tests
```

### 1. RPC Fuzzer
Tests the RPC parser against random inputs. The initialization automatically seeds the corpus with seed frames (decompression, uncompressed payloads, etc.).
```bash
mkdir -p ../rpc_fuzzer_corpus
./rpc_fuzzer ../rpc_fuzzer_corpus -dict=../tests/rpc_fuzzer.dict -runs=1000000 -max_len=65536 -rss_limit_mb=4096 -timeout=25
```

### 2. Network Fuzzer
Tests execution path discovery for network payloads. Continuous fuzzing can be spanned across all CPU cores:
```bash
mkdir -p ../network_fuzzer_corpus
./network_fuzzer ../network_fuzzer_corpus \
    -workers=$(sysctl -n hw.ncpu) \
    -jobs=$(sysctl -n hw.ncpu) \
    -dict=../tests/network_fuzzer.dict -max_len=4096
```

### 3. Consensus Fuzzer
Validates Genesis block formations and Mint Gossips. Requires high RSS RAM limits to sustain Ledger Malloc sweeps.
```bash
mkdir -p ../consensus_fuzzer_corpus
./consensus_fuzzer ../consensus_fuzzer_corpus -dict=../tests/consensus_fuzzer.dict -max_len=26546 -runs=10000000 -rss_limit_mb=4096 -timeout=25
```

### 4. Crypto ZK Fuzzer
Ensures zero-knowledge proofs and cryptographic boundaries hold.
```bash
mkdir -p ../crypto_zk_fuzzer_corpus
./crypto_zk_fuzzer ../crypto_zk_fuzzer_corpus -dict=../tests/crypto_zk_fuzzer.dict -max_len=24576 -runs=10000000 -rss_limit_mb=4096 -timeout=25
```

### 5. Quantum TVD Fuzzer
Ensures AVX2/NEON vectorization boundaries and `qsim` statevector memory allocations are fully safe.

Because `libFuzzer` must handle oversized files here, you need to generate a baseline seed first:
```bash
mkdir -p ../quantum_tvd_fuzzer_corpus

# Generate a baseline OpenQASM seed
python3 -c '
import struct
mode = 2
shots = 15000
seed = b"\x42" * 32
circuit = b"OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\ncreg c[7];\nh q[0];\ncx q[0], q[1]; \nmeasure q -> c;\n"
data = struct.pack("<B I 32s", mode, shots, seed) + circuit
open("../quantum_tvd_fuzzer_corpus/seed_bell_state.bin", "wb").write(data)
'

# Run the fuzzer
./quantum_tvd_fuzzer ../quantum_tvd_fuzzer_corpus -dict=../tests/quantum_tvd_fuzzer.dict -runs=10000000 -max_len=65536 -rss_limit_mb=4096 -timeout=25
```

**Corpus Condensation Tip:** To fix iteration bottlenecks caused by oversized files, merge and condense your corpus periodically:
```bash
mkdir -p ../quantum_tvd_fuzzer_corpus_min
./quantum_tvd_fuzzer -merge=1 ../quantum_tvd_fuzzer_corpus_min ../quantum_tvd_fuzzer_corpus
rm -rf ../quantum_tvd_fuzzer_corpus
mv ../quantum_tvd_fuzzer_corpus_min ../quantum_tvd_fuzzer_corpus
find ../quantum_tvd_fuzzer_corpus -size +64k -delete
```

---
*For support or to report bugs, please open an issue on GitHub. Pull requests targeting multi-platform support are highly encouraged!*
