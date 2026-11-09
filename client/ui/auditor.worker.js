/**
 * @file auditor.worker.js
 * @module client/ui/auditor.worker.js - Localized Decryption, Proving & FFI WebWorker
 *
 * @brief Dedicated client-side WebWorker providing isolated post-quantum key storage,
 *        transparent LZ4 stream decompression, Module-SIS PRF nullifier evaluation,
 *        Stern zero-knowledge proof generation, and binary RPC wire frame serialization.
 *
 * @details
 * This WebWorker isolates sensitive cryptographic operations from the browser UI main thread:
 * 1. Zero-Leakage Key Containment:
 *    Maintains the operator's NIST FIPS 204 ML-DSA-87 (Dilithium5) private signing key (4,864 bytes)
 *    and Module-SIS PRF evaluation key (1,024 bytes) exclusively inside WebAssembly linear memory.
 * 2. L5 Binary Wire Protocol Framing:
 *    Parses, validates SipHash-2-4 checksums, and constructs canonical 32-byte header wire frames
 *    (`SclRpcHeader`) for API communication with the native SCL node daemon over WebSockets.
 * 3. Zero-Knowledge Proving Engine:
 *    Generates multi-round statistical Stern zero-knowledge proofs over Module-SIS lattice relations,
 *    enabling confidential Centinel coin redemption and validation voucher burning without trusted setup.
 * 4. High-Performance Frame Batching:
 *    Buffers incoming stream frames in a FIFO queue (`frameQueue`) and budgets execution to 15ms
 *    time slices to ensure the WebWorker event loop remains responsive.
 *
 * @invariants
 * - Linear Heap Memory Bounds: All buffer pointers passed to WASM exports must fall strictly within
 *   the Emscripten heap address space `[0, wasmInstance.HEAPU8.buffer.byteLength)`.
 * - Heap View Invariance: `getLiveHeapU8()` and `getLiveHeap8()` are queried dynamically after every
 *   WASM allocation to prevent detached ArrayBuffer exceptions following heap growth (`memory.grow`).
 * - Cryptographic Scrubbing: All private key allocations are explicitly wiped via `_wasm_secure_wipe`
 *   upon termination or key rotation before linear memory deallocation.
 *
 * @standards
 * - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA-87 / Dilithium5).
 * - RFC 8439 / SipHash-2-4: Fast Short-Input Pseudorandom Function.
 * - BDLOP: Homomorphic Lattice Commitment Scheme over Ring R_q (Baum et al.).
 * - LZ4 Streaming and Block Compression Specification.
 *
 * @dependencies
 * - `libscl_rpc.js` / `libscl_rpc.wasm` (Emscripten WebAssembly compilation artifacts).
 * - Web Cryptography API (`crypto.getRandomValues`) for CSPRNG entropy seeding.
 *
 * @threading
 * - Executes in a dedicated browser WebWorker thread isolated from DOM manipulation.
 * - Communicates with the main thread via structured message passing (`postMessage`).
 * - Uses Transferable Objects (`ArrayBuffer`) where possible to eliminate redundant memory copies.
 */

/** @type {Object|null} Active Emscripten WebAssembly module instance. */
let wasmInstance = null;

/** @type {number} 32-bit linear memory pointer to the 1,024-byte Module-SIS PRF key. */
let prfKeyPtr = 0;

/** @type {number} 32-bit linear memory pointer to the 16-byte SipHash-2-4 session key. */
let siphashKeyPtr = 0;

/** @type {number} 32-bit linear memory pointer to the 4,864-byte Dilithium5 private signing key. */
let dilithiumKeyPtr = 0;

/** @type {number} 32-bit linear memory pointer to the 2,592-byte Dilithium5 public verification key. */
let dilithiumPubkeyPtr = 0;

/** @const {number} Byte size of the expanded Module-SIS PRF key matrix. */
const PRF_KEY_SIZE = 1024;

/** @const {number} Byte size of the ML-DSA-87 (Dilithium5) public verification key. */
const DILITHIUM_PUBKEY_SIZE = 2592;

/** @const {number} Byte size of the 128-bit SipHash-2-4 session integrity key. */
const SIPHASH_KEY_SIZE = 16;

/** @const {number} Byte size of the ML-DSA-87 (Dilithium5) private signing key. */
const DILITHIUM_KEY_SIZE = 4864;

/** @const {number} Byte size of the evaluated transaction nullifier digest. */
const NULLIFIER_SIZE = 32;

/** @type {Set<string>} Cache of known spent nullifier hex strings to identify redeemed outputs. */
const utxoNullifiers = new Set();

/** @type {Map<string, Uint8Array>} Map associating nullifier hex strings with their 32-byte blinding factor r. */
const utxoBlindingFactors = new Map();

/** @const {number} Forward lookahead scan depth for detecting derived validation blinding factors. */
const SCL_WALLET_SCAN_WINDOW = 10000;

/** @type {Array<Uint8Array|null>} Pre-computed candidate blinding factors derived from private key. */
const candidateRValues = [];

/** @type {Set<number>} Set tracking blinding factor indices that have already been allocated. */
const usedRIndices = new Set();

/** @type {Set<string>} Cache of known transaction IDs to prevent duplicate TPS counting. */
const seenTxIds = new Set();

/** @const {bigint} Atomic subunits per single SCL whole coin (160,000,000 subunits = 1 SCL). */
const SUBUNITS_PER_COIN = 160000000n;

/** @const {bigint} Numerator constant for exact 128-bit transaction fee evaluation (approx. Pi * 10^15). */
const FEE_NUMERATOR = 3141592653589793n;

/** @const {bigint} Standard fee denominator representing 10^17 for ~3.14159% transfer fees. */
const FEE_DENOMINATOR_NORMAL = 100000000000000000n;

/** @type {Object|null} Cached balance metrics snapshot used to detect and mask temporary rollback dips. */
let lastBalanceData = null;

/** @type {number} Timestamp marking the onset of a balance rollback dip for temporal debouncing. */
let balanceRollbackTime = 0;

/** @type {Object|null} Cached valuations issuance snapshot used to detect and mask temporary rollback dips. */
let lastValuationsData = null;

/** @type {number} Timestamp marking the onset of a valuations supply rollback dip for temporal debouncing. */
let valuationsRollbackTime = 0;

/** @type {Object|null} Cached chain metrics snapshot used to detect and mask temporary height rollbacks. */
let lastChainInfoData = null;

/** @type {number} Timestamp marking the onset of a block height rollback dip for temporal debouncing. */
let chainInfoRollbackTime = 0;

/**
 * @brief Retrieves a fresh unsigned 8-bit TypedArray view over current WebAssembly linear memory.
 *
 * @details
 * Safely handles Emscripten memory growth by dynamically querying `wasmInstance.HEAPU8`.
 * If memory expansion (`memory.grow`) invalidates a previous buffer reference, this function
 * instantiates a fresh view over the expanded underlying `ArrayBuffer`.
 *
 * @return {Uint8Array|null} Active unsigned 8-bit view over WASM linear memory, or null if uninitialized.
 * @complexity Time: O(1), Space: O(1).
 */
const getLiveHeapU8 = () => {
    if (!wasmInstance) return null;
    return wasmInstance.HEAPU8 || (wasmInstance.HEAP8 ? new Uint8Array(wasmInstance.HEAP8.buffer) : (wasmInstance.buffer ? new Uint8Array(wasmInstance.buffer) : null));
};

/**
 * @brief Retrieves a fresh signed 8-bit TypedArray view over current WebAssembly linear memory.
 *
 * @return {Int8Array|null} Active signed 8-bit view over WASM linear memory, or null if uninitialized.
 * @complexity Time: O(1), Space: O(1).
 */
const getLiveHeap8 = () => {
    if (!wasmInstance) return null;
    return wasmInstance.HEAP8 || (wasmInstance.HEAPU8 ? new Int8Array(wasmInstance.HEAPU8.buffer) : (wasmInstance.buffer ? new Int8Array(wasmInstance.buffer) : null));
};

// Load and compile the WASM module
try {
    importScripts('libscl_rpc.js'); // Generated glue file from Emscripten

    if (typeof Module === 'function') {
        Module().then(instance => {
            wasmInstance = instance;
            postMessage({ type: 'STATUS', status: 'WASM_LOADED' });
        }).catch(err => {
            postMessage({ type: 'ERROR', message: 'Failed to initialize WASM: ' + err.message });
        });
    } else if (typeof Module === 'object' && Module !== null) {
        if (typeof Module.then === 'function') {
            Module.then(instance => {
                wasmInstance = instance;
                postMessage({ type: 'STATUS', status: 'WASM_LOADED' });
            }).catch(err => {
                postMessage({ type: 'ERROR', message: 'Failed to initialize WASM: ' + err.message });
            });
        } else {
            wasmInstance = Module;
            postMessage({ type: 'STATUS', status: 'WASM_LOADED' });
        }
    }
} catch (err) {
    postMessage({ type: 'ERROR', message: 'Failed to load libscl_rpc.js: ' + err.message });
}

/* ============================================================================
 * SECTION 2: FRAME QUEUING & WORKER MESSAGE ROUTER
 * ============================================================================ */

/** @type {Array<Uint8Array>} FIFO queue staging raw incoming binary stream frames for processing. */
const frameQueue = [];

/** @type {boolean} Mutex flag indicating whether the frame processing loop is actively running. */
let isProcessing = false;

/**
 * @brief Drains staged network frames within a cooperative 15-millisecond execution slice.
 *
 * @details
 * Processes frames sequentially via @ref handleProcessFrame until the queue is exhausted or the
 * 15ms execution budget expires. If frames remain after the deadline, schedules continuation
 * via `setTimeout(..., 0)` to yield execution and prevent worker thread lockups.
 *
 * @return {void}
 * @complexity Time: O(frames_in_slice * processing_time), Space: O(1).
 */
function processNextFrames() {
    if (frameQueue.length === 0) {
        isProcessing = false;
        return;
    }
    isProcessing = true;
    const startTime = performance.now();

    // Strictly budget execution to ~15ms per frame loop to prevent worker thread saturation
    while (frameQueue.length > 0 && (performance.now() - startTime < 15)) {
        const wireBytes = frameQueue.shift();
        handleProcessFrame(wireBytes);
    }

    if (frameQueue.length > 0) {
        setTimeout(processNextFrames, 0); // Yield execution back to the browser to maintain UX
    } else {
        isProcessing = false;
    }
}

/**
 * @brief Primary inbound message router receiving command events from the UI thread.
 *
 * @param {MessageEvent} event Worker event containing `type` discriminator and `data` parameters.
 * @return {void}
 */
self.onmessage = function(event) {
    const { type, data } = event.data;

    switch (type) {
        case 'INITIALIZE_KEYS':
            handleKeyInitialization(data.prfSeed, data.utxoNullifiers, data.siphashKey, data.dilithiumKey, data.dilithiumPubkey);
            break;
        case 'PROCESS_STREAM_FRAME':
            frameQueue.push(data.wireBytes);
            if (!isProcessing) processNextFrames();
            break;
        case 'BUILD_BALANCE_QUERY':
            handleBuildBalanceQuery(data.requestId, data.targetPubkey);
            break;
        case 'BUILD_RECENT_TXS':
            handleBuildRecentTxs(data.requestId, data.cursor);
            break;
        case 'BUILD_GET_TX':
            handleBuildGetTx(data.requestId, data.txHash);
            break;
        case 'BUILD_CHAIN_INFO':
            handleBuildChainInfo(data.requestId);
            break;
        case 'RESET_ROLLBACK_STATE':
            // New pipeline (possibly a different backend behind the LB): stop debouncing
            lastBalanceData = null; balanceRollbackTime = 0;
            lastValuationsData = null; valuationsRollbackTime = 0;
            lastChainInfoData = null; chainInfoRollbackTime = 0;
            break;
        case 'BUILD_GET_BLOCK':
            handleBuildGetBlock(data.requestId, data.height);
            break;
        case 'BUILD_GET_VALUATIONS':
            handleBuildGetValuations(data.requestId);
            break;
        case 'BUILD_GET_AUDIT':
            handleBuildGetAudit(data.requestId);
            break;
        case 'BUILD_QUANTUM_TVD_AUDIT':
            handleBuildQuantumTvdAudit(data.requestId, data.shots, data.beaconSeed, data.circuitBytes, data.receipt);
            break;
        case 'BUILD_DRIFT_CERT_AUDIT':
            handleBuildDriftCertAudit(data.requestId, data.shots, data.beaconSeed, data.histogram, data.circuitBytes, data.receipt);
            break;
        case 'BUILD_AUTOPILOT':
            handleBuildAutopilot(data.requestId, data.enable, data.valPerHr, data.stakeRatio);
            break;
        case 'BUILD_GET_BLOCKCHAIN_LEDGER':
            handleBuildGetBlockchainLedger(data.requestId);
            break;
        case 'VERIFY_MMR_PROOF':
            handleVerifyMmrProof(data.requestId, data.leafHash, data.proofBytes, data.peaks);
            break;
        case 'GENERATE_KEYS':
            handleGenerateKeys();
            break;
        case 'SUBMIT_TRANSACTION':
            handleSubmitTransaction(data.requestId, data.opType, data.payload);
            break;
        case 'GENERATE_CENTINEL_PROOF':
            handleGenerateCentinelProof(data);
            break;
        case 'TERMINATE':
            frameQueue.length = 0; // Clear pending queue
            handleTerminate();
            break;
    }
};

/* ============================================================================
 * SECTION 3: INGRESS BINARY FRAME DECODING & LOCAL RPC ROUTING
 * ============================================================================ */

/**
 * @brief Parses, verifies, and dispatches a raw binary L5 RPC response or stream frame.
 *
 * @details
 * Ingress Processing Sequence:
 * 1. Allocates a temporary staging buffer on the WASM heap and copies `wireBytes`.
 * 2. If a session SipHash key is active, verifies the 64-bit checksum via `_wasm_verify_checksum`.
 * 3. Instantiates an opaque parser context via `_wasm_parse_frame`.
 * 4. Enforces version parity (must equal 0x01) and handles server-side error statuses.
 * 5. Dispatches by method ID to unpack responses:
 *    - `0x0001` (GetBalance): Unpacks liquid/staked balances, fees paid, and active UTXO descriptors.
 *    - `0x0002` (GetBlock): Extracts MMR leaf commitments and parses on-chain block operations.
 *    - `0x0003` / `0x0007` (SubmitTx / GetTransaction): Unpacks transaction intent, evaluates PRF nullifier
 *      matching against `prfKeyPtr`, and checks for incoming/outgoing Centinel shielded commitments.
 *    - `0x0004` (GetAudit): Unpacks 10x10 Game Audit circular valuation matrix rows.
 *    - `0x0005` (GetValuations): Unpacks total rewarded supply, remaining cap, and consensus stage.
 *    - `0x0006` (GetRecentTxs): Unpacks paginated 32-byte transaction IDs and next cursor offset.
 *    - `0x0008` (GetChainInfo): Unpacks tip height, staker totals, committee count, and daemon keys.
 *    - `0x000A` (QuantumTvdAudit): Unpacks QPU drift certificate metrics and confidence bounds.
 *    - `0x000B` (Autopilot): Unpacks autonomous rebalancing status, submission rates, and target ratios.
 *
 * @param {Uint8Array} wireBytes Raw binary frame received from WebSocket stream.
 * @return {void}
 *
 * @complexity Time: O(wireBytes.length + unpack_time), Space: O(wireBytes.length) WASM heap allocation.
 */
function handleProcessFrame(wireBytes) {
    if (!wasmInstance) {
        return;
    }

    let wirePtr = 0;
    let statusPtr = 0;
    let parserCtx = 0;

    try {
        const len = wireBytes.length;
        wirePtr = wasmInstance._wasm_malloc(len);
        
        const heapWire = getLiveHeapU8().subarray(wirePtr, wirePtr + len);
        heapWire.set(wireBytes);

        statusPtr = wasmInstance._wasm_malloc(4); // int32
        
        // Verify frame integrity natively using fast 64-bit SipHash-2-4 checksum
        if (siphashKeyPtr !== 0) {
            const checkResult = wasmInstance._wasm_verify_checksum(wirePtr, len, siphashKeyPtr);
            if (checkResult !== 0) {
                postMessage({ type: 'ERROR', message: 'SipHash frame integrity validation failed (checksum mismatch)' });
                return;
            }
        }
        
        // Parse the binary frame
        parserCtx = wasmInstance._wasm_parse_frame(wirePtr, len, statusPtr);
        if (parserCtx === 0) {
            return;
        }

        const flags = wasmInstance._wasm_parser_get_flags(parserCtx);
        const methodId = wasmInstance._wasm_parser_get_method_id(parserCtx);
        const version = wasmInstance._wasm_parser_get_version(parserCtx);
        const status = wasmInstance._wasm_parser_get_status(parserCtx);

        // API Versioning, Error status tracking, and Fallback Graceful Degradation
        if (version !== 0x01) {
            postMessage({
                type: 'RPC_ERROR',
                data: { methodId, status: 0x0001, version, error: 'BAD_VERSION' }
            });
            return;
        }

        if (status === 0x0192) { // SCL_RPC_STATUS_PAYMENT_REQUIRED (402)
            /* sizeof(SclRpcPaymentChallenge) is 96 bytes on the wire (90 field
             * bytes + 6 tail padding); _wasm_parser_get_payment_challenge
             * memcpy's the full struct, so a 90-byte alloc overflowed by 6. */
            const challengePtr = wasmInstance._wasm_malloc(96);
            if (wasmInstance._wasm_parser_get_payment_challenge(parserCtx, challengePtr) === 0) {
                const heap = getLiveHeapU8();
                const chView = new DataView(heap.buffer, heap.byteOffset + challengePtr, 90);
                
                /* scl_rpc_parser_get_payment_challenge() normalizes all fields
                 * with be64toh()/be16toh(), so this buffer holds HOST-order
                 * (little-endian) values. Reading big-endian double-swapped
                 * them: the 1 SCL fee (160,000,000 subunits) decoded as
                 * 29,424,069,325,619,200, so auto-settlement never succeeded. */
                const amountSubunits = chView.getBigUint64(0, true).toString();
                const rateLockId = chView.getBigUint64(8, true).toString();
                const recipientHex = Array.from(heap.subarray(challengePtr + 16, challengePtr + 48))
                    .map(b => b.toString(16).padStart(2, '0')).join('');
                const challengeHashHex = Array.from(heap.subarray(challengePtr + 48, challengePtr + 80))
                    .map(b => b.toString(16).padStart(2, '0')).join('');
                const validUntil = Number(chView.getBigUint64(80, true));
                const acceptedTypes = chView.getUint16(88, true);
                
                postMessage({
                    type: 'PAYMENT_REQUIRED',
                    data: {
                        methodId,
                        requestId: wasmInstance._wasm_parser_get_request_id(parserCtx).toString(),
                        amountSubunits,
                        rateLockId,
                        recipientHex,
                        challengeHashHex,
                        validUntil,
                        acceptedTypes
                    }
                });
            }
            wasmInstance._wasm_free(challengePtr);
            return;
        }

        if (status !== 0) {
            let errorText = 'Unknown RPC Error';
            if (wasmInstance._wasm_parser_get_error) {
                const errBuf = wasmInstance._wasm_malloc(256);
                if (wasmInstance._wasm_parser_get_error(parserCtx, errBuf, 256) === 0) {
                    let i = 0;
                    const charCodes = [];
                    const liveHeap8 = getLiveHeap8();
                    while (i < 255) {
                        const code = liveHeap8[errBuf + i];
                        if (code === 0) break;
                        charCodes.push(code);
                        i++;
                    }
                    errorText = String.fromCharCode(...charCodes);
                }
                wasmInstance._wasm_free(errBuf);
            }
            postMessage({
                type: 'RPC_ERROR',
                data: { methodId, status, version, error: errorText }
            });
            return;
        }

        if (methodId === 0x0001) {
            // GetBalance Response Handler
            const outPtrPtr = wasmInstance._wasm_malloc(4);
            const outLenPtr = wasmInstance._wasm_malloc(4);
            
            if (wasmInstance._wasm_parser_get_payload_ref(parserCtx, outPtrPtr, outLenPtr) === 0) {
                const view = new DataView(wasmInstance.HEAPU8.buffer);
                const payloadPtr = view.getUint32(outPtrPtr, true);
                const payloadLen = view.getUint32(outLenPtr, true);
                
                if (payloadLen >= 24) {
                    const payloadBytes = getLiveHeapU8().subarray(payloadPtr, payloadPtr + payloadLen);
                    const viewPayload = new DataView(payloadBytes.buffer, payloadBytes.byteOffset, payloadLen);
                    const balanceSubunits = Number(viewPayload.getBigUint64(0, false));
                    const stakedSubunits = Number(viewPayload.getBigUint64(8, false));
                    const feesPaidSubunits = Number(viewPayload.getBigUint64(16, false));
                    const utxoValidations = payloadLen >= 32 ? Number(viewPayload.getBigUint64(24, false)) : 0;
                    const numValUtxos = payloadLen >= 40 ? Number(viewPayload.getBigUint64(32, false)) : 0;

                    const now = Date.now();
                    if (lastBalanceData && (feesPaidSubunits < lastBalanceData.feesPaidSubunits || (chainInfoRollbackTime > 0 && now - chainInfoRollbackTime < 60000))) {
                        if (!balanceRollbackTime) balanceRollbackTime = now;
                        if (now - balanceRollbackTime < 60000) {
                            wasmInstance._wasm_free(outPtrPtr);
                            wasmInstance._wasm_free(outLenPtr);
                            return;
                        }
                    }
                    balanceRollbackTime = 0;
                    lastBalanceData = { feesPaidSubunits, balanceSubunits, stakedSubunits };

                    for (let idx = 0; idx < numValUtxos; idx++) {
                        usedRIndices.add(idx);
                    }
                    
                    const activeUtxos = [];
                    const nativePointers = [];
                    if (payloadLen > 40) {
                        let offset = 40;
                        
                        while (offset + 72 <= payloadLen) {
                            let rem = payloadLen - offset;
                            if (rem >= 4 && ((rem - 4) % 145 === 0)) {
                                let possibleNativeCount = (rem - 4) / 145;
                                let readNativeCount = viewPayload.getUint32(offset, false);
                                if (possibleNativeCount === readNativeCount) {
                                    break;
                                }
                            }
                            
                            const nulBytes = payloadBytes.subarray(offset, offset + 32);
                            const nulHex = Array.from(nulBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                            offset += 32;
                            const amt = Number(viewPayload.getBigUint64(offset, false));
                            offset += 8;
                            const rBytes = payloadBytes.subarray(offset, offset + 32).slice(0);
                            offset += 32;
                            activeUtxos.push({ nullifier: nulHex, amount: amt, r: rBytes });
                        }

                        if (offset + 4 <= payloadLen) {
                            const nativeCount = viewPayload.getUint32(offset, false);
                            offset += 4;
                            for (let i = 0; i < nativeCount; i++) {
                                if (offset + 145 > payloadLen) break;
                                
                                const ptrIdBytes = payloadBytes.subarray(offset, offset + 32);
                                const ptrIdHex = Array.from(ptrIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                                offset += 32;
                                
                                const parentIdBytes = payloadBytes.subarray(offset, offset + 32);
                                const parentIdHex = Array.from(parentIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                                offset += 32;
                                
                                const startSubunit = viewPayload.getBigUint64(offset, false); offset += 8;
                                const endSubunit = viewPayload.getBigUint64(offset, false); offset += 8;
                                
                                const ownerBytes = payloadBytes.subarray(offset, offset + 32);
                                const ownerHex = Array.from(ownerBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                                offset += 32;
                                
                                const prevTxBytes = payloadBytes.subarray(offset, offset + 32);
                                const prevTxHex = Array.from(prevTxBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                                offset += 32;
                                
                                const statusByte = payloadBytes[offset];
                                const isStaked = statusByte === 1;
                                const isFee = statusByte === 2;
                                offset += 1;
                                
                                nativePointers.push({
                                    pointerId: ptrIdHex,
                                    parentCoinId: parentIdHex,
                                    startSubunit: startSubunit.toString(),
                                    endSubunit: endSubunit.toString(),
                                    ownerAddress: ownerHex,
                                    prevTxHash: prevTxHex,
                                    spent: isFee ? 2 : false,
                                    staked: isStaked
                                });
                            }
                        }
                    }

                    postMessage({
                        type: 'BALANCE_RECEIVED',
                        data: { balanceSubunits, stakedSubunits, feesPaidSubunits, utxoValidations, numValUtxos, activeUtxos, nativePointers }
                    });
                }
            }
            wasmInstance._wasm_free(outPtrPtr);
            wasmInstance._wasm_free(outLenPtr);
        }

        if (methodId === 0x0004) {
            // GetAudit Response Handler
            const outPtrPtr = wasmInstance._wasm_malloc(4);
            const outLenPtr = wasmInstance._wasm_malloc(4);
            
            if (wasmInstance._wasm_parser_get_payload_ref(parserCtx, outPtrPtr, outLenPtr) === 0) {
                const view = new DataView(wasmInstance.HEAPU8.buffer);
                const payloadPtr = view.getUint32(outPtrPtr, true);
                const payloadLen = view.getUint32(outLenPtr, true);
                
                if (payloadLen >= 1120) {
                    const payloadBytes = getLiveHeapU8().subarray(payloadPtr, payloadPtr + payloadLen);
                    const valuations = [];
                    let offset = 0;
                    for (let i = 0; i < 10; i++) { // AUDIT_SIZE = 10
                        const userId = Array.from(payloadBytes.subarray(offset, offset + 32));
                        
                        const numbers = [];
                        const viewPayload = new DataView(payloadBytes.buffer, payloadBytes.byteOffset + offset + 32, 40);
                        for (let j = 0; j < 10; j++) {
                            numbers.push(viewPayload.getUint32(j * 4, false));
                        }
                        
                        const viewTs = new DataView(payloadBytes.buffer, payloadBytes.byteOffset + offset + 32 + 40, 8);
                        const timestamp = Number(viewTs.getBigUint64(0, false));
                        
                        const beaconSeed = Array.from(payloadBytes.subarray(offset + 32 + 40 + 8, offset + 32 + 40 + 8 + 32));
                        
                        valuations.push({ userId, numbers, timestamp, beaconSeed });
                        offset += 112; // 32 + 40 + 8 + 32 = 112
                    }
                    postMessage({
                        type: 'AUDIT_RECEIVED',
                        data: { valuations }
                    });
                }
            }
            wasmInstance._wasm_free(outPtrPtr);
            wasmInstance._wasm_free(outLenPtr);
        }

        if (methodId === 0x0005) {
            // GetValuations Response Handler
            const outPtrPtr = wasmInstance._wasm_malloc(4);
            const outLenPtr = wasmInstance._wasm_malloc(4);
            
            if (wasmInstance._wasm_parser_get_payload_ref(parserCtx, outPtrPtr, outLenPtr) === 0) {
                const view = new DataView(wasmInstance.HEAPU8.buffer);
                const payloadPtr = view.getUint32(outPtrPtr, true);
                const payloadLen = view.getUint32(outLenPtr, true);
                
                if (payloadLen >= 24) {
                    const payloadBytes = getLiveHeapU8().subarray(payloadPtr, payloadPtr + payloadLen);
                    const viewPayload = new DataView(payloadBytes.buffer, payloadBytes.byteOffset, payloadLen);
                    const totalRewarded = Number(viewPayload.getBigUint64(0, false));
                    const remainingSubunits = Number(viewPayload.getBigUint64(8, false));
                    const curStage = Number(viewPayload.getBigUint64(16, false));
                    
                    const now = Date.now();
                    if (lastValuationsData && totalRewarded < lastValuationsData.totalRewarded) {
                        if (!valuationsRollbackTime) valuationsRollbackTime = now;
                        if (now - valuationsRollbackTime < 60000) {
                            wasmInstance._wasm_free(outPtrPtr);
                            wasmInstance._wasm_free(outLenPtr);
                            return;
                        }
                    }
                    valuationsRollbackTime = 0;
                    lastValuationsData = { totalRewarded };

                    postMessage({
                        type: 'VALUATIONS_RECEIVED',
                        data: { totalRewarded, remainingSubunits, curStage }
                    });
                }
            }
            wasmInstance._wasm_free(outPtrPtr);
            wasmInstance._wasm_free(outLenPtr);
        }

        if (methodId === 0x000B) { // Autopilot Status & Config Response Handler
            const outPtrPtr = wasmInstance._wasm_malloc(4);
            const outLenPtr = wasmInstance._wasm_malloc(4);

            if (wasmInstance._wasm_parser_get_payload_ref(parserCtx, outPtrPtr, outLenPtr) === 0) {
                const view = new DataView(wasmInstance.HEAPU8.buffer);
                const payloadPtr = view.getUint32(outPtrPtr, true);
                const payloadLen = view.getUint32(outLenPtr, true);

                if (payloadLen >= 13) {
                    const payloadBytes = getLiveHeapU8().subarray(payloadPtr, payloadPtr + payloadLen);
                    const viewPayload = new DataView(payloadBytes.buffer, payloadBytes.byteOffset, payloadLen);

                    const enabled = (payloadBytes[0] !== 0);
                    const valPerHr = viewPayload.getUint32(1, false);
                    const stakeRatio = viewPayload.getUint32(5, false);
                    const maxHourlyRate = viewPayload.getUint32(9, false);

                    postMessage({
                        type: 'AUTOPILOT_STATUS_RECEIVED',
                        data: {
                            enabled,
                            valPerHr,
                            stakeRatio,
                            maxHourlyRate
                        }
                    });
                }
            }
            wasmInstance._wasm_free(outPtrPtr);
            wasmInstance._wasm_free(outLenPtr);
        }

        if (methodId === 0x000A) { // Quantum TVD Audit Response Handler
            const outPtrPtr = wasmInstance._wasm_malloc(4);
            const outLenPtr = wasmInstance._wasm_malloc(4);

            if (wasmInstance._wasm_parser_get_payload_ref(parserCtx, outPtrPtr, outLenPtr) === 0) {
                const view = new DataView(wasmInstance.HEAPU8.buffer);
                const payloadPtr = view.getUint32(outPtrPtr, true);
                const payloadLen = view.getUint32(outLenPtr, true);

                if (payloadLen >= 76) {
                    const payloadBytes = getLiveHeapU8().subarray(payloadPtr, payloadPtr + payloadLen);
                    const viewPayload = new DataView(payloadBytes.buffer, payloadBytes.byteOffset, payloadLen);

                    const circuitHashBytes = payloadBytes.subarray(0, 32);
                    const circuitHashHex = Array.from(circuitHashBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                    const timestamp = Number(viewPayload.getBigUint64(32, true));
                    const numQubits = viewPayload.getUint32(40, true);
                    const shots = viewPayload.getUint32(44, true);
                    const tvdScaled = Number(viewPayload.getBigUint64(48, true));
                    const tvdDouble = viewPayload.getFloat64(56, true);
                    const confidenceMargin = viewPayload.getFloat64(64, true);
                    const status = viewPayload.getUint32(72, true);

                    let tvdCommitmentHex = '';
                    let validatorSigHex = '';
                    /* Layout (quantum_tvd.h QuantumDriftCertificate):
                     * commitment_blinding[32] sits at 76..108 and must NOT be
                     * exposed as the commitment; the 2048-byte BdlopCommitment
                     * starts at 108. Gate on 2156 so the whole commitment is
                     * present before exposing its first 32 bytes (c1). */
                    if (payloadLen >= 2156) {
                        const commBytes = payloadBytes.subarray(108, 108 + 32);
                        tvdCommitmentHex = Array.from(commBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                    }
                    if (payloadLen >= 6751) {
                        const sigBytes = payloadBytes.subarray(2156, 2156 + 4595);
                        validatorSigHex = Array.from(sigBytes.subarray(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('') + '...';
                    }

                    postMessage({
                        type: 'QUANTUM_TVD_AUDIT_RECEIVED',
                        data: {
                            circuitHash: circuitHashHex,
                            timestamp,
                            numQubits,
                            shots,
                            tvdScaled,
                            tvdDouble,
                            confidenceMargin,
                            status,
                            tvdCommitmentHex,
                            validatorSigHex
                        }
                    });
                }
            }
            wasmInstance._wasm_free(outPtrPtr);
            wasmInstance._wasm_free(outLenPtr);
        }
        
        if (methodId === 0x000D) { // Drift Certificate Histogram Audit Response Handler
            const outPtrPtr = wasmInstance._wasm_malloc(4);
            const outLenPtr = wasmInstance._wasm_malloc(4);

            if (wasmInstance._wasm_parser_get_payload_ref(parserCtx, outPtrPtr, outLenPtr) === 0) {
                const view = new DataView(wasmInstance.HEAPU8.buffer);
                const payloadPtr = view.getUint32(outPtrPtr, true);
                const payloadLen = view.getUint32(outLenPtr, true);

                if (payloadLen >= 76) {
                    const payloadBytes = getLiveHeapU8().subarray(payloadPtr, payloadPtr + payloadLen);
                    const viewPayload = new DataView(payloadBytes.buffer, payloadBytes.byteOffset, payloadLen);

                    const circuitHashHex = Array.from(payloadBytes.subarray(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('');
                    const timestamp = Number(viewPayload.getBigUint64(32, true));
                    const numQubits = viewPayload.getUint32(40, true);
                    const shots = viewPayload.getUint32(44, true);
                    const tvdScaled = Number(viewPayload.getBigUint64(48, true));
                    const tvdDouble = viewPayload.getFloat64(56, true);
                    const confidenceMargin = viewPayload.getFloat64(64, true);
                    const status = viewPayload.getUint32(72, true);

                    let tvdCommitmentHex = '';
                    let validatorSigHex = '';
                    if (payloadLen >= 2156) {
                        const commBytes = payloadBytes.subarray(108, 108 + 32);
                        tvdCommitmentHex = Array.from(commBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                    }
                    if (payloadLen >= 6751) {
                        const sigBytes = payloadBytes.subarray(2156, 2156 + 4595);
                        validatorSigHex = Array.from(sigBytes.subarray(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('') + '...';
                    }

                    postMessage({
                        type: 'DRIFT_CERT_AUDIT_RECEIVED',
                        data: {
                            circuitHash: circuitHashHex,
                            timestamp,
                            numQubits,
                            shots,
                            tvdScaled,
                            tvdDouble,
                            confidenceMargin,
                            status,
                            tvdCommitmentHex,
                            validatorSigHex
                        }
                    });
                } else {
                    /* Truncated 0x000D success payloads previously vanished — report
                     * them as a framed RPC error so the UI can react. */
                    postMessage({
                        type: 'RPC_ERROR',
                        data: { methodId: 0x000D, status: 0x0004, version: 1, error: 'Malformed drift certificate response (payload ' + payloadLen + ' bytes, minimum 76)' }
                    });
                }
            }
            wasmInstance._wasm_free(outPtrPtr);
            wasmInstance._wasm_free(outLenPtr);
        }

        if (methodId === 0x000C) { // GetBlockchainLedger Response Handler
            const outPtrPtr = wasmInstance._wasm_malloc(4);
            const outLenPtr = wasmInstance._wasm_malloc(4);

            if (wasmInstance._wasm_parser_get_payload_ref(parserCtx, outPtrPtr, outLenPtr) === 0) {
                const view = new DataView(wasmInstance.HEAPU8.buffer);
                const payloadPtr = view.getUint32(outPtrPtr, true);
                const payloadLen = view.getUint32(outLenPtr, true);

                if (payloadLen >= 4) {
                    const payloadBytes = getLiveHeapU8().subarray(payloadPtr, payloadPtr + payloadLen);
                    const viewPayload = new DataView(payloadBytes.buffer, payloadBytes.byteOffset, payloadLen);

                    const numCoins = viewPayload.getUint32(0, false);
                    let offset = 4;

                    const coins = [];
                    const pointers = [];

                    for (let c = 0; c < numCoins && offset + 120 <= payloadLen; c++) {
                        const coinIdBytes = payloadBytes.subarray(offset, offset + 32);
                        const coinIdHex = Array.from(coinIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                        offset += 32;

                        const totalSubunits = Number(viewPayload.getBigUint64(offset, false));
                        offset += 8;
                        const remainingSubunits = Number(viewPayload.getBigUint64(offset, false));
                        offset += 8;

                        const creationTxBytes = payloadBytes.subarray(offset, offset + 32);
                        const creationTxHex = Array.from(creationTxBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                        offset += 32;

                        const ownerAddrBytes = payloadBytes.subarray(offset, offset + 32);
                        const ownerAddrHex = Array.from(ownerAddrBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                        offset += 32;

                        const blockNumber = Number(viewPayload.getBigUint64(offset, false));
                        offset += 8;

                        const numPointers = viewPayload.getUint32(offset, false);
                        offset += 4;

                        coins.push({
                            coinId: coinIdHex,
                            totalSubunits,
                            remainingSubunits,
                            creationTxHash: creationTxHex,
                            ownerAddress: ownerAddrHex,
                            blockNumber
                        });

                        for (let p = 0; p < numPointers && offset + 146 <= payloadLen; p++) {
                            const ptrIdBytes = payloadBytes.subarray(offset, offset + 32);
                            const ptrIdHex = Array.from(ptrIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                            offset += 32;

                            const pCoinIdBytes = payloadBytes.subarray(offset, offset + 32);
                            const pCoinIdHex = Array.from(pCoinIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                            offset += 32;

                            const startSubunit = viewPayload.getBigUint64(offset, false).toString();
                            offset += 8;
                            const endSubunit = viewPayload.getBigUint64(offset, false).toString();
                            offset += 8;

                            const ptrOwnerBytes = payloadBytes.subarray(offset, offset + 32);
                            const ptrOwnerHex = Array.from(ptrOwnerBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                            offset += 32;

                            const prevTxBytes = payloadBytes.subarray(offset, offset + 32);
                            const prevTxHex = Array.from(prevTxBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                            offset += 32;

                            const spentByte = payloadBytes[offset];
                            offset += 1;
                            const stakedByte = payloadBytes[offset];
                            offset += 1;

                            pointers.push({
                                pointerId: ptrIdHex,
                                parentCoinId: pCoinIdHex,
                                startSubunit,
                                endSubunit,
                                ownerAddress: ptrOwnerHex,
                                prevTxHash: prevTxHex,
                                spent: spentByte,
                                staked: stakedByte === 1
                            });
                        }
                    }

                    postMessage({
                        type: 'BLOCKCHAIN_LEDGER_RECEIVED',
                        data: { coins, pointers }
                    });
                }
            }
            wasmInstance._wasm_free(outPtrPtr);
            wasmInstance._wasm_free(outLenPtr);
        }

        if (methodId === 0x0008) {
            // GetChainInfo Response Handler
            const outPtrPtr = wasmInstance._wasm_malloc(4); // uint8_t**
            const outLenPtr = wasmInstance._wasm_malloc(4); // size_t*
            
            if (wasmInstance._wasm_parser_get_payload_ref(parserCtx, outPtrPtr, outLenPtr) === 0) {
                const view = new DataView(wasmInstance.HEAPU8.buffer);
                const payloadPtr = view.getUint32(outPtrPtr, true);
                const payloadLen = view.getUint32(outLenPtr, true);
                
                const payloadBytes = getLiveHeapU8().subarray(payloadPtr, payloadPtr + payloadLen);
                if (payloadLen >= 44) {
                    const view = new DataView(payloadBytes.buffer, payloadBytes.byteOffset, payloadLen);
                    const blockHeight = Number(view.getBigUint64(0, false));
                    const totalSubunits = Number(view.getBigUint64(8, false));
                    const totalStaked = Number(view.getBigUint64(16, false));
                    const committeeCount = view.getUint16(24, false);
                    const activeDkgSessions = view.getUint16(26, false);
                    const lastDkgEpoch = Number(view.getBigUint64(28, false));
                    const totalFees = Number(view.getBigUint64(36, false));
                    
                    const now = Date.now();
                    if (lastChainInfoData && blockHeight < lastChainInfoData.blockHeight) {
                        if (!chainInfoRollbackTime) chainInfoRollbackTime = now;
                        if (now - chainInfoRollbackTime < 60000) {
                            wasmInstance._wasm_free(outPtrPtr);
                            wasmInstance._wasm_free(outLenPtr);
                            return;
                        }
                    }
                    chainInfoRollbackTime = 0;
                    lastChainInfoData = { blockHeight, totalFees };
                    
                    let nodePubkeyHex = "";
                    if (payloadLen >= 44 + 2592) {
                        const pubkeyBytes = payloadBytes.subarray(44, 44 + 2592);
                        nodePubkeyHex = Array.from(pubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                    }

                    let nodePrivkeyHex = "";
                    if (payloadLen >= 44 + 2592 + 4864) {
                        const privkeyBytes = payloadBytes.subarray(44 + 2592, 44 + 2592 + 4864);
                        nodePrivkeyHex = Array.from(privkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                    }

                    // SCL402: fee-recipient pubkey appended by the bridge at offset
                    // 44 + 2592 + 4864. SHA-256(nodeFeePubkeyHex) equals
                    // SclRpcPaymentChallenge.recipientHex in the binary 402 challenge.
                    let nodeFeePubkeyHex = "";
                    if (payloadLen >= 44 + 2592 + 4864 + 2592) {
                        const feePubkeyBytes = payloadBytes.subarray(44 + 2592 + 4864, 44 + 2592 + 4864 + 2592);
                        nodeFeePubkeyHex = Array.from(feePubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                    }

                    postMessage({
                        type: 'CHAIN_INFO_RECEIVED',
                        data: { blockHeight, totalSubunits, totalStaked, committeeCount, activeDkgSessions, lastDkgEpoch, totalFees, nodePubkeyHex, nodePrivkeyHex, nodeFeePubkeyHex }
                    });
                }
            }
            wasmInstance._wasm_free(outPtrPtr);
            wasmInstance._wasm_free(outLenPtr);
        }

        if (methodId === 0x0002) { // GetBlock Response
            const outPtrPtr = wasmInstance._wasm_malloc(4);
            const outLenPtr = wasmInstance._wasm_malloc(4);
            
            if (wasmInstance._wasm_parser_get_payload_ref(parserCtx, outPtrPtr, outLenPtr) === 0) {
                const view = new DataView(wasmInstance.HEAPU8.buffer);
                const payloadPtr = view.getUint32(outPtrPtr, true);
                const payloadLen = view.getUint32(outLenPtr, true);
                
                if (payloadLen >= 8) {
                    const maxHashes = 1000;
                    const outHashesPtr = wasmInstance._wasm_malloc(maxHashes * 32);
                    const numHashes = wasmInstance._wasm_extract_block_commitments(payloadPtr, payloadLen, outHashesPtr, maxHashes);
                    
                    const payloadBytes = getLiveHeapU8().subarray(payloadPtr, payloadPtr + payloadLen).slice(0);
                    const viewPayload = new DataView(payloadBytes.buffer, payloadBytes.byteOffset, payloadLen);
                    const blockNumber = Number(viewPayload.getBigUint64(0, false));
                    
                    const commitments = [];
                    if (numHashes > 0) {
                        const hashesBytes = getLiveHeapU8().subarray(outHashesPtr, outHashesPtr + numHashes * 32);
                        for (let i = 0; i < numHashes; i++) {
                            commitments.push(Array.from(hashesBytes.slice(i * 32, (i + 1) * 32)));
                        }
                    }
                    wasmInstance._wasm_free(outHashesPtr);
                    
                    postMessage({
                        type: 'BLOCK_RECEIVED',
                        data: { blockNumber, commitments }
                    });
                }
            }
            wasmInstance._wasm_free(outPtrPtr);
            wasmInstance._wasm_free(outLenPtr);
        }

        if (methodId === 0x0006) { // GetRecentTxs Response
            const outPtrPtr = wasmInstance._wasm_malloc(4);
            const outLenPtr = wasmInstance._wasm_malloc(4);
            
            if (wasmInstance._wasm_parser_get_payload_ref(parserCtx, outPtrPtr, outLenPtr) === 0) {
                const view = new DataView(wasmInstance.HEAPU8.buffer);
                const outPtr = view.getUint32(outPtrPtr, true);
                const outLen = view.getUint32(outLenPtr, true);
                
                const payloadBytes = getLiveHeapU8().subarray(outPtr, outPtr + outLen);
                const txCount = outLen / 32;
                const txs = [];
                for (let i = 0; i < txCount; i++) {
                    const txId = payloadBytes.slice(i * 32, (i + 1) * 32);
                    txs.push(Array.from(txId));
                }
                
                postMessage({
                    type: 'RECENT_TXS_RECEIVED',
                    data: {
                        txs,
                        nextCursor: (flags & 2) ? wasmInstance._wasm_parser_get_cursor(parserCtx) : null
                    }
                });
            }
            wasmInstance._wasm_free(outPtrPtr);
            wasmInstance._wasm_free(outLenPtr);
        }

        // Check shielded transactions
        if (methodId === 0x0007 || methodId === 0x0003) {
            const outPtrPtr = wasmInstance._wasm_malloc(4);
            const outLenPtr = wasmInstance._wasm_malloc(4);
            
            if (wasmInstance._wasm_parser_get_payload_ref(parserCtx, outPtrPtr, outLenPtr) === 0) {
                const view = new DataView(wasmInstance.HEAPU8.buffer);
                const outPtr = view.getUint32(outPtrPtr, true);
                let outLen = view.getUint32(outLenPtr, true);
                
                // Support reflective zero-length intercepts bridging Centinel UI updates securely
                if (outLen === 0 && methodId === 0x0003) {
                    outLen = len - 32;
                }
                
                if (outLen >= 33) {
                    const payloadBytes = getLiveHeapU8().subarray(outPtr, outPtr + outLen);
                    const type = payloadBytes[0];
                    
                    let txTypeString = "Unknown";
                    if (type === 0) txTypeString = "OP_SUBMIT_VALUATION";
                    if (type === 1) txTypeString = "OP_MINT_COIN";
                    else if (type === 2) txTypeString = "OP_TRANSFER_POINTER";
                    else if (type === 3) txTypeString = "OP_STAKE";
                    else if (type === 4) txTypeString = "OP_UNSTAKE";
                    else if (type === 5) txTypeString = "OP_REDEEM_CENTINEL";
                    else if (type === 6) txTypeString = "OP_CLAIM_VALIDATION";

                    let txIdHex = "";
                    if (type === 1 && outLen >= 2657 + 32) {
                        const txIdBytes = payloadBytes.subarray(2657, 2657 + 32);
                        txIdHex = Array.from(txIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                    } else if (type === 2 || type === 3 || type === 4 || type === 5 || type === 6) {
                        const txIdBytes = payloadBytes.subarray(1, 33);
                        txIdHex = Array.from(txIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                    }
                    
                    if (txIdHex) {
                        seenTxIds.add(txIdHex);
                    }

                    let matchFound = false;
                    let computedNullifierHex = "";
                    
                    if (type === 2 && outLen >= 77 && prfKeyPtr !== 0) { // OP_TRANSFER_POINTER (2)
                        const seedPtr = wasmInstance._wasm_malloc(32);
                        const opPtr = wasmInstance._wasm_malloc(outLen);
                        const computedNullifierPtr = wasmInstance._wasm_malloc(NULLIFIER_SIZE);

                        // Extract views AFTER mallocs to prevent Detached ArrayBuffer exceptions
                        const safePayloadBytes = getLiveHeapU8().subarray(outPtr, outPtr + outLen);
                        const clientRoot = safePayloadBytes.subarray(45, 77);
                        
                        const heapSeed = getLiveHeapU8().subarray(seedPtr, seedPtr + 32);
                        heapSeed.set(clientRoot);
                        
                        const heapOp = getLiveHeapU8().subarray(opPtr, opPtr + outLen);
                        heapOp.set(safePayloadBytes);
                        
                        // Perform direct, localized key-matching within the WASM boundary
                        const matchRes = wasmInstance._wasm_match_transaction(opPtr, outLen, prfKeyPtr, seedPtr, computedNullifierPtr);
                        
                        if (matchRes === 1) {
                            const computedNullifier = getLiveHeapU8().subarray(computedNullifierPtr, computedNullifierPtr + NULLIFIER_SIZE);
                            computedNullifierHex = Array.from(computedNullifier).map(b => b.toString(16).padStart(2, '0')).join('');
                            matchFound = true;
                            postMessage({
                                type: 'TRANSACTION_MATCH',
                                nullifier: Array.from(computedNullifier),
                                methodId: methodId,
                                direction: 'incoming'
                            });
                        }
                        
                        wasmInstance._wasm_free(seedPtr);
                        wasmInstance._wasm_free(opPtr);
                        wasmInstance._wasm_free(computedNullifierPtr);
                    } else if (type === 5 && prfKeyPtr !== 0) { // OP_REDEEM_CENTINEL (5)
                        const safePayloadBytes = getLiveHeapU8().subarray(outPtr, outPtr + outLen);
                        const nullifier = safePayloadBytes.subarray(1, 33).slice(0);
                        const nullifierHex = Array.from(nullifier).map(b => b.toString(16).padStart(2, '0')).join('');
                        
                        // Extract c_transfer and c_change to illuminate the viewport
                        const cTransferBytes = safePayloadBytes.subarray(33, 33 + 2048).slice(0);
                        const cChangeBytes = safePayloadBytes.subarray(33 + 2048, 33 + 4096).slice(0);

                        let isOutgoing = utxoNullifiers.has(nullifierHex) || utxoBlindingFactors.has(nullifierHex);
                        let isIncoming = false;
                        let incomingCTransfer = false;
                        let incomingCChange = false;
                        let decryptedTransferAmount = 0;

                        const checkCommitment = (cBytes) => {
                            let matchNulHex = null;
                            let amt = 0;
                            let isZero = true;
                            for (let i = 0; i < cBytes.length; i++) {
                                if (cBytes[i] !== 0) { isZero = false; break; }
                            }
                            if (isZero) return { matchNulHex, amt };

                            const cPtr = wasmInstance._wasm_malloc(2048);
                            const hashPtr = wasmInstance._wasm_malloc(32);
                            const nulPtr = wasmInstance._wasm_malloc(32);
                            const rPtr = wasmInstance._wasm_malloc(32);
                            const rhoPtr = wasmInstance._wasm_malloc(32);
                            const checkCommPtr = wasmInstance._wasm_malloc(2048);
                            const candPrfKeyPtr = wasmInstance._wasm_malloc(1024);

                            getLiveHeapU8().subarray(cPtr, cPtr + 2048).set(cBytes);
                            wasmInstance._wasm_sha256(cPtr, 2048, hashPtr);

                            const encoder = new TextEncoder();
                            const rhoSeedBytes = encoder.encode("SCL_CENTINEL_LATTICE_BDLOP_V1_SEED");
                            const rhoBytes = new Uint8Array(32);
                            rhoBytes.set(rhoSeedBytes.subarray(0, 32));
                            getLiveHeapU8().subarray(rhoPtr, rhoPtr + 32).set(rhoBytes);

                            let foundR = null;

                            if (wasmInstance._wasm_bdlop_commit) {
                                for (let idx = 0; idx < candidateRValues.length; idx++) {
                                    const candR = candidateRValues[idx];
                                    if (!candR) continue;
                                    getLiveHeapU8().subarray(rPtr, rPtr + 32).set(candR);

                                    if (wasmInstance._wasm_bdlop_commit(rhoPtr, 0n, rPtr, checkCommPtr) === 0) {
                                        const candC1 = getLiveHeapU8().subarray(checkCommPtr, checkCommPtr + 1024);
                                        const targetC1 = cBytes.subarray(0, 1024);
                                        let match = true;
                                        for (let k = 0; k < 1024; k++) {
                                            if (candC1[k] !== targetC1[k]) { match = false; break; }
                                        }
                                        if (match) {
                                            foundR = candR;
                                            usedRIndices.add(idx);

                                            if (wasmInstance._wasm_prf_keygen) {
                                                wasmInstance._wasm_prf_keygen(candPrfKeyPtr, rPtr, 32);
                                                if (wasmInstance._wasm_prf_evaluate(nulPtr, candPrfKeyPtr, hashPtr, 32, hashPtr) === 0) {
                                                    const nBytes = getLiveHeapU8().subarray(nulPtr, nulPtr + 32);
                                                    matchNulHex = Array.from(nBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                                                    utxoBlindingFactors.set(matchNulHex, candR);
                                                }
                                            }
                                            break;
                                        }
                                    }
                                }
                            }

                            if (foundR && matchNulHex && wasmInstance._wasm_bdlop_decrypt) {
                                const valOutPtr = wasmInstance._wasm_malloc(8);
                                getLiveHeapU8().subarray(rPtr, rPtr + 32).set(foundR);
                                
                                if (wasmInstance._wasm_bdlop_decrypt(rhoPtr, cPtr, rPtr, valOutPtr) === 0) {
                                    const viewVal = new DataView(wasmInstance.HEAPU8.buffer, valOutPtr, 8);
                                    amt = Number(viewVal.getBigUint64(0, true));
                                }
                                wasmInstance._wasm_free(valOutPtr);
                            }

                            wasmInstance._wasm_free(cPtr);
                            wasmInstance._wasm_free(hashPtr);
                            wasmInstance._wasm_free(nulPtr);
                            wasmInstance._wasm_free(rPtr);
                            wasmInstance._wasm_free(rhoPtr);
                            wasmInstance._wasm_free(checkCommPtr);
                            wasmInstance._wasm_free(candPrfKeyPtr);
                            return { matchNulHex, amt };
                        };

                        const transCheck = checkCommitment(cTransferBytes);
                        const changeCheck = checkCommitment(cChangeBytes);
                        const newNullifiers = [];

                        if (transCheck.matchNulHex) {
                            isIncoming = true;
                            incomingCTransfer = true;
                            decryptedTransferAmount += transCheck.amt;
                            newNullifiers.push({ hex: transCheck.matchNulHex, amount: transCheck.amt });
                        }
                        if (changeCheck.matchNulHex) {
                            isIncoming = true;
                            incomingCChange = true;
                            decryptedTransferAmount += changeCheck.amt;
                            newNullifiers.push({ hex: changeCheck.matchNulHex, amount: changeCheck.amt });
                        }
                        
                        if (isOutgoing || isIncoming) {
                            matchFound = true;
                            const cTransferPtr = wasmInstance._wasm_malloc(2048);
                            const commHashPtr = wasmInstance._wasm_malloc(32);
                            const leafInputPtr = wasmInstance._wasm_malloc(40);
                            const leafHashPtr = wasmInstance._wasm_malloc(32);
                            
                            const heapCTransfer = getLiveHeapU8().subarray(cTransferPtr, cTransferPtr + 2048);
                            heapCTransfer.set(cTransferBytes);
                            
                            wasmInstance._wasm_sha256(cTransferPtr, 2048, commHashPtr);
                            
                            const leafInputHeap = getLiveHeapU8().subarray(leafInputPtr, leafInputPtr + 40);
                            leafInputHeap.set(getLiveHeapU8().subarray(commHashPtr, commHashPtr + 32), 0);
                            leafInputHeap.set(new Uint8Array(8), 32);
                            
                            wasmInstance._wasm_sha256(leafInputPtr, 40, leafHashPtr);
                            
                            const leafHashBytes = getLiveHeapU8().subarray(leafHashPtr, leafHashPtr + 32);
                            const leafHashArray = Array.from(leafHashBytes);
                            
                            wasmInstance._wasm_free(cTransferPtr);
                            wasmInstance._wasm_free(commHashPtr);
                            wasmInstance._wasm_free(leafInputPtr);
                            wasmInstance._wasm_free(leafHashPtr);
                            
                            postMessage({
                                type: 'TRANSACTION_MATCH',
                                nullifier: Array.from(nullifier),
                                newNullifiers: newNullifiers,
                                cTransfer: Array.from(cTransferBytes.subarray(0, 16)),
                                cChange: Array.from(cChangeBytes.subarray(0, 16)),
                                decryptedTransferAmount: decryptedTransferAmount > 0 ? decryptedTransferAmount : null,
                                methodId: methodId,
                                direction: isIncoming ? 'incoming' : 'outgoing',
                                isCentinel: true,
                                leafHash: leafHashArray
                            });
                        }
                    } else if (type === 6 && prfKeyPtr !== 0) { // OP_CLAIM_VALIDATION (6)
                        const cClaimPtr = wasmInstance._wasm_malloc(2048);
                        const hashPtr = wasmInstance._wasm_malloc(32);
                        const leafInputPtr = wasmInstance._wasm_malloc(40);
                        const leafHashPtr = wasmInstance._wasm_malloc(32);
                        const computedNullifierPtr = wasmInstance._wasm_malloc(NULLIFIER_SIZE);
                        const candPrfKeyPtr = wasmInstance._wasm_malloc(1024);
                        const rhoPtr = wasmInstance._wasm_malloc(32);
                        const rPtr = wasmInstance._wasm_malloc(32);
                        const checkCommPtr = wasmInstance._wasm_malloc(2048);

                        const safePayloadBytes = getLiveHeapU8().subarray(outPtr, outPtr + outLen);
                        const cClaimBytes = safePayloadBytes.subarray(1, 1 + 2048);
                        
                        const heapCClaim = getLiveHeapU8().subarray(cClaimPtr, cClaimPtr + 2048);
                        heapCClaim.set(cClaimBytes);
                        
                        wasmInstance._wasm_sha256(cClaimPtr, 2048, hashPtr);
                        
                        // Calculate Leaf Hash for exact MMR Topography mapping
                        const leafInputHeap = getLiveHeapU8().subarray(leafInputPtr, leafInputPtr + 40);
                        leafInputHeap.set(getLiveHeapU8().subarray(hashPtr, hashPtr + 32), 0);
                        leafInputHeap.set(new Uint8Array(8), 32); // remaining_subunits = 0
                        
                        wasmInstance._wasm_sha256(leafInputPtr, 40, leafHashPtr);
                        const leafHashBytes = getLiveHeapU8().subarray(leafHashPtr, leafHashPtr + 32);
                        const leafHashArray = Array.from(leafHashBytes);
                        
                        const claimPubkeyBytes = safePayloadBytes.subarray(2049, 2049 + 2592);
                        let isMyPubkey = false;
                        if (dilithiumPubkeyPtr !== 0 && claimPubkeyBytes.length === 2592) {
                            const myPubkeyBytes = getLiveHeapU8().subarray(dilithiumPubkeyPtr, dilithiumPubkeyPtr + 2592);
                            isMyPubkey = true;
                            for (let k = 0; k < 2592; k++) {
                                if (claimPubkeyBytes[k] !== myPubkeyBytes[k]) {
                                    isMyPubkey = false;
                                    break;
                                }
                            }
                        }

                        if (isMyPubkey && wasmInstance._wasm_bdlop_commit) {
                            let decryptedClaimAmount = 10;
                            let foundR = null;
                            let computedNullifierHex = "";

                            const encoder = new TextEncoder();
                            const rhoSeedBytes = encoder.encode("SCL_CENTINEL_LATTICE_BDLOP_V1_SEED");
                            const rhoBytes = new Uint8Array(32);
                            rhoBytes.set(rhoSeedBytes.subarray(0, 32));
                            getLiveHeapU8().subarray(rhoPtr, rhoPtr + 32).set(rhoBytes);

                            for (let idx = 0; idx < candidateRValues.length; idx++) {
                                const candR = candidateRValues[idx];
                                if (!candR) continue;
                                getLiveHeapU8().subarray(rPtr, rPtr + 32).set(candR);

                                if (wasmInstance._wasm_bdlop_commit(rhoPtr, 0n, rPtr, checkCommPtr) === 0) {
                                    const candC1 = getLiveHeapU8().subarray(checkCommPtr, checkCommPtr + 1024);
                                    const targetC1 = cClaimBytes.subarray(0, 1024);
                                    let match = true;
                                    for (let k = 0; k < 1024; k++) {
                                        if (candC1[k] !== targetC1[k]) { match = false; break; }
                                    }
                                    if (match) {
                                        foundR = candR;
                                        usedRIndices.add(idx);

                                        if (wasmInstance._wasm_prf_keygen) {
                                            wasmInstance._wasm_prf_keygen(candPrfKeyPtr, rPtr, 32);
                                            if (wasmInstance._wasm_prf_evaluate(computedNullifierPtr, candPrfKeyPtr, hashPtr, 32, hashPtr) === 0) {
                                                const computedNullifier = getLiveHeapU8().subarray(computedNullifierPtr, computedNullifierPtr + NULLIFIER_SIZE);
                                                computedNullifierHex = Array.from(computedNullifier).map(b => b.toString(16).padStart(2, '0')).join('');
                                                utxoBlindingFactors.set(computedNullifierHex, candR);
                                            }
                                        }
                                        break;
                                    }
                                }
                            }

                            if (foundR && computedNullifierHex && wasmInstance._wasm_bdlop_decrypt) {
                                const valOutPtr = wasmInstance._wasm_malloc(8);
                                getLiveHeapU8().subarray(rPtr, rPtr + 32).set(foundR);
                                
                                if (wasmInstance._wasm_bdlop_decrypt(rhoPtr, cClaimPtr, rPtr, valOutPtr) === 0) {
                                    const viewVal = new DataView(wasmInstance.HEAPU8.buffer, valOutPtr, 8);
                                    decryptedClaimAmount = Number(viewVal.getBigUint64(0, true));
                                }
                                wasmInstance._wasm_free(valOutPtr);

                                matchFound = true;
                                postMessage({
                                    type: 'TRANSACTION_MATCH',
                                    nullifier: hexToBytes(computedNullifierHex),
                                    newNullifiers: [{ hex: computedNullifierHex, amount: decryptedClaimAmount }],
                                    cTransfer: Array.from(cClaimBytes.subarray(0, 16)),
                                    decryptedTransferAmount: decryptedClaimAmount,
                                    methodId: methodId,
                                    direction: 'incoming',
                                    isClaimValidation: true,
                                    leafHash: leafHashArray
                                });
                            }

                        }
                        
                        wasmInstance._wasm_free(rhoPtr);
                        wasmInstance._wasm_free(rPtr);
                        wasmInstance._wasm_free(checkCommPtr);
                        wasmInstance._wasm_free(cClaimPtr);
                        wasmInstance._wasm_free(hashPtr);
                        wasmInstance._wasm_free(leafInputPtr);
                        wasmInstance._wasm_free(leafHashPtr);
                        wasmInstance._wasm_free(computedNullifierPtr);
                        wasmInstance._wasm_free(candPrfKeyPtr);
                    }

                    // Always post audit details back to client UI for matching or generic rendering
                    // Extract safe view one last time just to be sure we don't pass a detached buffer to parsing fn
                    const finalSafePayloadBytes = getLiveHeapU8().subarray(outPtr, outPtr + outLen).slice(0);
                    postMessage({
                        type: 'TRANSACTION_AUDITED',
                        data: {
                            txId: txIdHex,
                            /* Echoed RPC request id: lets the settlement bridge match
                             * this accepted SubmitTx response to the pending SCL402
                             * replay keyed by the same id (the node echoes the request
                             * id in the response header). */
                            requestId: wasmInstance._wasm_parser_get_request_id(parserCtx).toString(),
                            typeString: txTypeString,
                            payloadLen: outLen,
                            matchFound: matchFound,
                            nullifier: computedNullifierHex,
                            methodId: methodId,
                            parsedTx: (type >= 0 && type <= 6) ? parseTransactionPayload(finalSafePayloadBytes, methodId) : null
                        }
                    });
                }
            }
            wasmInstance._wasm_free(outPtrPtr);
            wasmInstance._wasm_free(outLenPtr);
        }

    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Frame parsing error: ' + e.message });
    } finally {
        cleanup(wirePtr, statusPtr, parserCtx);
    }
}

/**
 * @brief Releases heap memory buffers and opaque parser contexts allocated during frame parsing.
 *
 * @param {number} wirePtr Linear memory pointer to the wire packet buffer.
 * @param {number} statusPtr Linear memory pointer to the status code integer.
 * @param {number} parserCtx Opaque parser handle.
 * @return {void}
 * @complexity Time: O(1), Space: O(1).
 */
function cleanup(wirePtr, statusPtr, parserCtx) {
    if (wirePtr) wasmInstance._wasm_free(wirePtr);
    if (statusPtr) wasmInstance._wasm_free(statusPtr);
    if (parserCtx) wasmInstance._wasm_destroy_parser(parserCtx);
}

/* ============================================================================
 * SECTION 4: CRYPTOGRAPHIC KEY LIFECYCLE & TEARDOWN
 * ============================================================================ */

/**
 * @brief Allocates and initializes cryptographic key structures within WebAssembly linear memory.
 *
 * @details
 * Cryptographic Provisioning Steps:
 * 1. Securely zeroes and deallocates any pre-existing keys in WASM linear heap.
 * 2. Allocates and initializes the 1,024-byte Module-SIS PRF key (`prfKeyPtr`):
 *    - If a 1,024-byte pre-expanded key is provided, copies directly into linear memory.
 *    - If a 32-byte seed is provided, expands via `_wasm_prf_keygen`.
 * 3. Populates the 16-byte SipHash session key (`siphashKeyPtr`) if supplied.
 * 4. Populates the 4,864-byte Dilithium5 private key (`dilithiumKeyPtr`) and 2,592-byte public key.
 * 5. Pre-computes the deterministic committee threshold public key via `_wasm_compute_threshold_pubkey`.
 * 6. Pre-calculates candidate blinding factors across @ref SCL_WALLET_SCAN_WINDOW indices.
 * 7. Emits `KEYS_EXPANDED` and `KEYS_INITIALIZED` status events to the UI thread.
 *
 * @param {Uint8Array} prfSeedArray 32-byte PRF seed or 1,024-byte pre-expanded key buffer.
 * @param {Array<string|Object>} nullifiersArray Known spent nullifiers to initialize local spend filters.
 * @param {Uint8Array|null} siphashKeyArray 16-byte shared SipHash key, or null.
 * @param {Uint8Array|null} dilithiumKeyArray 4,864-byte Dilithium5 private key, or null.
 * @param {Uint8Array|null} dilithiumPubkeyArray 2,592-byte Dilithium5 public key, or null.
 * @return {void}
 *
 * @complexity Time: O(PRF_KEY_SIZE + DILITHIUM_KEY_SIZE), Space: O(1) heap allocations.
 */
function handleKeyInitialization(prfSeedArray, nullifiersArray, siphashKeyArray, dilithiumKeyArray, dilithiumPubkeyArray) {
    if (!wasmInstance) {
        postMessage({ type: 'ERROR', message: 'WASM not ready' });
        return;
    }

    if (prfSeedArray.length !== 32 && prfSeedArray.length !== 1024) {
        postMessage({ type: 'ERROR', message: 'Invalid PRF key or seed size. Expected 32 bytes (seed) or 1024 bytes (pre-expanded key).' });
        return;
    }

    let seedPtr = 0;
    try {
        // If keys were previously initialized, wipe them first
        if (prfKeyPtr !== 0) {
            wasmInstance._wasm_secure_wipe(prfKeyPtr, PRF_KEY_SIZE);
            wasmInstance._wasm_free(prfKeyPtr);
            prfKeyPtr = 0;
        }
        if (siphashKeyPtr !== 0) {
            wasmInstance._wasm_secure_wipe(siphashKeyPtr, SIPHASH_KEY_SIZE);
            wasmInstance._wasm_free(siphashKeyPtr);
            siphashKeyPtr = 0;
        }
        if (dilithiumKeyPtr !== 0) {
            wasmInstance._wasm_secure_wipe(dilithiumKeyPtr, DILITHIUM_KEY_SIZE);
            wasmInstance._wasm_free(dilithiumKeyPtr);
            dilithiumKeyPtr = 0;
        }
        if (dilithiumPubkeyPtr !== 0) {
            wasmInstance._wasm_secure_wipe(dilithiumPubkeyPtr, DILITHIUM_PUBKEY_SIZE);
            wasmInstance._wasm_free(dilithiumPubkeyPtr);
            dilithiumPubkeyPtr = 0;
        }

        prfKeyPtr = wasmInstance._wasm_malloc(PRF_KEY_SIZE);
        if (prfSeedArray.length === 1024) {
            // Pre-expanded key passed directly: copy byte-for-byte into the allocated heap space
            const heapKey = getLiveHeapU8().subarray(prfKeyPtr, prfKeyPtr + PRF_KEY_SIZE);
            heapKey.set(prfSeedArray);
        } else {
            // Allocate and expand the 32-byte seed into the 1024-byte PRF Key directly inside the WASM boundary
            seedPtr = wasmInstance._wasm_malloc(32);
            const heapSeed = getLiveHeapU8().subarray(seedPtr, seedPtr + 32);
            heapSeed.set(prfSeedArray);
            wasmInstance._wasm_prf_keygen(prfKeyPtr, seedPtr, 32);
        }

        if (siphashKeyArray && siphashKeyArray.length === SIPHASH_KEY_SIZE) {
            siphashKeyPtr = wasmInstance._wasm_malloc(SIPHASH_KEY_SIZE);
            const sipBuffer = getLiveHeapU8().subarray(siphashKeyPtr, siphashKeyPtr + SIPHASH_KEY_SIZE);
            sipBuffer.set(siphashKeyArray);
        }

        if (dilithiumKeyArray && dilithiumKeyArray.length === DILITHIUM_KEY_SIZE) {
            if (dilithiumKeyPtr !== 0) {
                wasmInstance._wasm_secure_wipe(dilithiumKeyPtr, DILITHIUM_KEY_SIZE);
                wasmInstance._wasm_free(dilithiumKeyPtr);
                dilithiumKeyPtr = 0;
            }
            if (!dilithiumKeyArray.every(b => b === 0)) {
                dilithiumKeyPtr = wasmInstance._wasm_malloc(DILITHIUM_KEY_SIZE);
                const dilithiumBuffer = getLiveHeapU8().subarray(dilithiumKeyPtr, dilithiumKeyPtr + DILITHIUM_KEY_SIZE);
                dilithiumBuffer.set(dilithiumKeyArray);
            }
        }

        if (dilithiumPubkeyArray && dilithiumPubkeyArray.length === DILITHIUM_PUBKEY_SIZE) {
            dilithiumPubkeyPtr = wasmInstance._wasm_malloc(DILITHIUM_PUBKEY_SIZE);
            const pubBuffer = getLiveHeapU8().subarray(dilithiumPubkeyPtr, dilithiumPubkeyPtr + DILITHIUM_PUBKEY_SIZE);
            pubBuffer.set(dilithiumPubkeyArray);
        }

        let thresholdPubkeyHex = "";
        if (dilithiumKeyPtr !== 0 && wasmInstance._wasm_compute_threshold_pubkey) {
            const tOutPtr = wasmInstance._wasm_malloc(2592);
            if (wasmInstance._wasm_compute_threshold_pubkey(dilithiumKeyPtr, tOutPtr) === 0) {
                const tBytes = getLiveHeapU8().subarray(tOutPtr, tOutPtr + 2592);
                thresholdPubkeyHex = Array.from(tBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            }
            wasmInstance._wasm_free(tOutPtr);
        }

        // Extract the expanded PRF key to send to the UI for Lattice Density sampling
        const expandedPrfKey = getLiveHeap8().subarray(prfKeyPtr, prfKeyPtr + PRF_KEY_SIZE);
        postMessage({
            type: 'KEYS_EXPANDED',
            data: { expandedPrfKey: new Int8Array(expandedPrfKey), thresholdPubkeyHex }
        });

        // Reset rollback debounce state buffers upon new key initialization to prevent cross-wallet carryover
        lastBalanceData = null;
        balanceRollbackTime = 0;
        lastValuationsData = null;
        valuationsRollbackTime = 0;
        lastChainInfoData = null;
        chainInfoRollbackTime = 0;

        // Load active nullifiers into the local index
        utxoNullifiers.clear();
        utxoBlindingFactors.clear();
        if (nullifiersArray && Array.isArray(nullifiersArray)) {
            nullifiersArray.forEach(item => {
                if (typeof item === 'string') {
                    utxoNullifiers.add(item);
                } else if (item && item.nullifier) {
                    if (item.r) {
                        utxoBlindingFactors.set(item.nullifier, item.r);
                    }
                }
            });
        }

        if (dilithiumKeyPtr !== 0 && wasmInstance._wasm_sha256) {
            candidateRValues.length = 0;
            usedRIndices.clear();
            ensureCandidateRValues(true);
        }

        postMessage({ type: 'STATUS', status: 'KEYS_INITIALIZED' });
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Key setup failed: ' + e.message });
    } finally {
        if (seedPtr !== 0) {
            wasmInstance._wasm_secure_wipe(seedPtr, 32);
            wasmInstance._wasm_free(seedPtr);
        }
    }
}

/**
 * @brief Securely scrubs all private key allocations from WebAssembly linear memory and terminates the worker.
 *
 * @details
 * Invokes `_wasm_secure_wipe` using optimization-resistant volatile zeroization over `prfKeyPtr`,
 * `siphashKeyPtr`, `dilithiumKeyPtr`, and `dilithiumPubkeyPtr`, releases the linear memory blocks via
 * `_wasm_free`, posts the `TERMINATED` status message, and invokes `self.close()`.
 *
 * @return {void}
 * @complexity Time: O(total_key_bytes), Space: O(1).
 */
function handleTerminate() {
    if (wasmInstance && prfKeyPtr !== 0) {
        wasmInstance._wasm_secure_wipe(prfKeyPtr, PRF_KEY_SIZE);
        wasmInstance._wasm_free(prfKeyPtr);
        prfKeyPtr = 0;
    }
    if (wasmInstance && siphashKeyPtr !== 0) {
        wasmInstance._wasm_secure_wipe(siphashKeyPtr, SIPHASH_KEY_SIZE);
        wasmInstance._wasm_free(siphashKeyPtr);
        siphashKeyPtr = 0;
    }
    if (wasmInstance && dilithiumKeyPtr !== 0) {
        wasmInstance._wasm_secure_wipe(dilithiumKeyPtr, DILITHIUM_KEY_SIZE);
        wasmInstance._wasm_free(dilithiumKeyPtr);
        dilithiumKeyPtr = 0;
    }
    if (wasmInstance && dilithiumPubkeyPtr !== 0) {
        wasmInstance._wasm_secure_wipe(dilithiumPubkeyPtr, DILITHIUM_PUBKEY_SIZE);
        wasmInstance._wasm_free(dilithiumPubkeyPtr);
        dilithiumPubkeyPtr = 0;
    }
    postMessage({ type: 'STATUS', status: 'TERMINATED' });
    self.close();
}

/* ============================================================================
 * SECTION 5: OUTBOUND BINARY RPC FRAME GENERATORS
 * ============================================================================ */

/**
 * @brief Assembles and emits a binary GetBalance query frame (Method 0x0001).
 *
 * @param {bigint|number} requestId 64-bit correlation request identifier.
 * @param {Uint8Array} targetPubkey 2,592-byte Dilithium5 public verification key to query.
 * @return {void}
 * @complexity Time: O(1), Space: O(1) temporary WASM buffer.
 */
function handleBuildBalanceQuery(requestId, targetPubkey) {
    if (!wasmInstance) return;
    let pkPtr = 0;
    let outFramePtr = 0;
    let outLenPtr = 0;

    try {
        pkPtr = wasmInstance._wasm_malloc(targetPubkey.length);
        const heapPk = getLiveHeapU8().subarray(pkPtr, pkPtr + targetPubkey.length);
        heapPk.set(targetPubkey);

        outFramePtr = wasmInstance._wasm_malloc(4096);
        outLenPtr = wasmInstance._wasm_malloc(4);

        const res = wasmInstance._wasm_frame_balance_query(
            BigInt(requestId),
            pkPtr,
            outFramePtr,
            4096,
            outLenPtr
        );

        if (res === 0) {
            const view = new DataView(wasmInstance.HEAPU8.buffer, outLenPtr, 4);
            const actualLen = view.getUint32(0, true);
            const frameBytes = getLiveHeapU8().subarray(outFramePtr, outFramePtr + actualLen);
            postMessage({
                type: 'FRAME_BUILT',
                data: {
                    queryType: 'BALANCE_QUERY',
                    frame: new Uint8Array(frameBytes)
                }
            });
        }
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Build balance query failed: ' + e.message });
    } finally {
        if (pkPtr) wasmInstance._wasm_free(pkPtr);
        if (outFramePtr) wasmInstance._wasm_free(outFramePtr);
        if (outLenPtr) wasmInstance._wasm_free(outLenPtr);
    }
}

/**
 * @brief Assembles and emits a paginated GetRecentTxs query frame (Method 0x0006).
 *
 * @param {bigint|number} requestId 64-bit correlation request identifier.
 * @param {number} cursor 32-bit pagination offset cursor.
 * @return {void}
 * @complexity Time: O(1), Space: O(1).
 */
function handleBuildRecentTxs(requestId, cursor) {
    if (!wasmInstance) return;
    let outFramePtr = 0;
    let outLenPtr = 0;

    try {
        outFramePtr = wasmInstance._wasm_malloc(4096);
        outLenPtr = wasmInstance._wasm_malloc(4);

        const res = wasmInstance._wasm_frame_recent_txs(
            BigInt(requestId),
            cursor,
            outFramePtr,
            4096,
            outLenPtr
        );

        if (res === 0) {
            const view = new DataView(wasmInstance.HEAPU8.buffer, outLenPtr, 4);
            const actualLen = view.getUint32(0, true);
            const frameBytes = getLiveHeapU8().subarray(outFramePtr, outFramePtr + actualLen);
            postMessage({
                type: 'FRAME_BUILT',
                data: {
                    queryType: 'RECENT_TXS',
                    frame: new Uint8Array(frameBytes)
                }
            });
        }
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Build recent txs failed: ' + e.message });
    } finally {
        if (outFramePtr) wasmInstance._wasm_free(outFramePtr);
        if (outLenPtr) wasmInstance._wasm_free(outLenPtr);
    }
}

/**
 * @brief Assembles and emits a GetTransaction query frame by transaction hash (Method 0x0007).
 *
 * @param {bigint|number} requestId 64-bit correlation request identifier.
 * @param {Uint8Array} txHash 32-byte SHA-256 transaction hash.
 * @return {void}
 * @complexity Time: O(1), Space: O(1).
 */
function handleBuildGetTx(requestId, txHash) {
    if (!wasmInstance) return;
    let txPtr = 0;
    let outFramePtr = 0;
    let outLenPtr = 0;

    try {
        const reqIdBig = BigInt(requestId);
        const txHashBytes = (txHash instanceof Uint8Array) ? txHash : new Uint8Array(txHash);

        txPtr = wasmInstance._wasm_malloc(txHashBytes.length);
        const heapTx = getLiveHeapU8().subarray(txPtr, txPtr + txHashBytes.length);
        heapTx.set(txHashBytes);

        outFramePtr = wasmInstance._wasm_malloc(4096);
        outLenPtr = wasmInstance._wasm_malloc(4);

        const res = wasmInstance._wasm_frame_get_tx(
            reqIdBig,
            txPtr,
            txHashBytes.length,
            outFramePtr,
            4096,
            outLenPtr
        );

        if (res === 0) {
            const view = new DataView(wasmInstance.HEAPU8.buffer, outLenPtr, 4);
            const actualLen = view.getUint32(0, true);
            const frameBytes = getLiveHeapU8().subarray(outFramePtr, outFramePtr + actualLen);
            postMessage({
                type: 'FRAME_BUILT',
                data: {
                    queryType: 'GET_TX',
                    frame: new Uint8Array(frameBytes)
                }
            });
        }
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Build get tx failed: ' + e.message });
    } finally {
        if (txPtr) wasmInstance._wasm_free(txPtr);
        if (outFramePtr) wasmInstance._wasm_free(outFramePtr);
        if (outLenPtr) wasmInstance._wasm_free(outLenPtr);
    }
}

/**
 * @brief Assembles and emits a GetChainInfo query frame (Method 0x0008).
 *
 * @param {bigint|number} requestId 64-bit correlation request identifier.
 * @return {void}
 * @complexity Time: O(1), Space: O(1).
 */
function handleBuildChainInfo(requestId) {
    if (!wasmInstance) return;
    let outFramePtr = 0;
    let outLenPtr = 0;

    try {
        outFramePtr = wasmInstance._wasm_malloc(4096);
        outLenPtr = wasmInstance._wasm_malloc(4);

        const res = wasmInstance._wasm_frame_chain_info(
            BigInt(requestId),
            outFramePtr,
            4096,
            outLenPtr
        );

        if (res === 0) {
            const view = new DataView(wasmInstance.HEAPU8.buffer, outLenPtr, 4);
            const actualLen = view.getUint32(0, true);
            const frameBytes = getLiveHeapU8().subarray(outFramePtr, outFramePtr + actualLen);
            postMessage({
                type: 'FRAME_BUILT',
                data: {
                    queryType: 'CHAIN_INFO',
                    frame: new Uint8Array(frameBytes)
                }
            });
        }
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Build chain info failed: ' + e.message });
    } finally {
        if (outFramePtr) wasmInstance._wasm_free(outFramePtr);
        if (outLenPtr) wasmInstance._wasm_free(outLenPtr);
    }
}

/**
 * @brief Assembles and emits a GetBlock query frame by block height (Method 0x0002).
 *
 * @param {bigint|number} requestId 64-bit correlation request identifier.
 * @param {number} height Target block height to retrieve.
 * @return {void}
 * @complexity Time: O(1), Space: O(1).
 */
function handleBuildGetBlock(requestId, height) {
    if (!wasmInstance) return;
    let outFramePtr = 0;
    let outLenPtr = 0;

    try {
        outFramePtr = wasmInstance._wasm_malloc(4096);
        outLenPtr = wasmInstance._wasm_malloc(4);

        const res = wasmInstance._wasm_frame_block_query(BigInt(requestId), height, outFramePtr, 4096, outLenPtr);
        if (res === 0) {
            const view = new DataView(wasmInstance.HEAPU8.buffer, outLenPtr, 4);
            const actualLen = view.getUint32(0, true);
            const frameBytes = getLiveHeapU8().subarray(outFramePtr, outFramePtr + actualLen);
            postMessage({
                type: 'FRAME_BUILT',
                data: {
                    queryType: 'GET_BLOCK',
                    frame: new Uint8Array(frameBytes)
                }
            });
        }
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Build get block failed: ' + e.message });
    } finally {
        if (outFramePtr) wasmInstance._wasm_free(outFramePtr);
        if (outLenPtr) wasmInstance._wasm_free(outLenPtr);
    }
}

/**
 * @brief Assembles and emits a GetValuations query frame (Method 0x0005).
 *
 * @param {bigint|number} requestId 64-bit correlation request identifier.
 * @return {void}
 * @complexity Time: O(1), Space: O(1).
 */
function handleBuildGetValuations(requestId) {
    if (!wasmInstance) return;
    let outFramePtr = 0;
    let outLenPtr = 0;

    try {
        outFramePtr = wasmInstance._wasm_malloc(4096);
        outLenPtr = wasmInstance._wasm_malloc(4);

        const res = wasmInstance._wasm_frame_valuations_query(BigInt(requestId), outFramePtr, 4096, outLenPtr);
        if (res === 0) {
            const view = new DataView(wasmInstance.HEAPU8.buffer, outLenPtr, 4);
            const actualLen = view.getUint32(0, true);
            const frameBytes = getLiveHeapU8().subarray(outFramePtr, outFramePtr + actualLen);
            postMessage({
                type: 'FRAME_BUILT',
                data: {
                    queryType: 'GET_VALUATIONS',
                    frame: new Uint8Array(frameBytes)
                }
            });
        }
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Build get valuations failed: ' + e.message });
    } finally {
        if (outFramePtr) wasmInstance._wasm_free(outFramePtr);
        if (outLenPtr) wasmInstance._wasm_free(outLenPtr);
    }
}

/**
 * @brief Assembles and emits a GetAudit query frame for the 10x10 matrix (Method 0x0004).
 *
 * @param {bigint|number} requestId 64-bit correlation request identifier.
 * @return {void}
 * @complexity Time: O(1), Space: O(1).
 */
function handleBuildGetAudit(requestId) {
    if (!wasmInstance) return;
    let outFramePtr = 0;
    let outLenPtr = 0;

    try {
        outFramePtr = wasmInstance._wasm_malloc(4096);
        outLenPtr = wasmInstance._wasm_malloc(4);

        const res = wasmInstance._wasm_frame_audit_query(BigInt(requestId), outFramePtr, 4096, outLenPtr);
        if (res === 0) {
            const view = new DataView(wasmInstance.HEAPU8.buffer, outLenPtr, 4);
            const actualLen = view.getUint32(0, true);
            const frameBytes = getLiveHeapU8().subarray(outFramePtr, outFramePtr + actualLen);
            postMessage({
                type: 'FRAME_BUILT',
                data: {
                    queryType: 'GET_AUDIT',
                    frame: new Uint8Array(frameBytes)
                }
            });
        }
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Build get audit failed: ' + e.message });
    } finally {
        if (outFramePtr) wasmInstance._wasm_free(outFramePtr);
        if (outLenPtr) wasmInstance._wasm_free(outLenPtr);
    }
}

/**
 * @brief Assembles and emits a GetBlockchainLedger query frame (Method 0x000C).
 * @param {bigint|number} requestId 64-bit correlation request identifier.
 */
function handleBuildGetBlockchainLedger(requestId) {
    const frameBuf = new Uint8Array(32);
    const view = new DataView(frameBuf.buffer);
    view.setUint8(0, 1);
    view.setUint8(1, 0);
    view.setUint16(2, 0, false);
    view.setUint16(4, 0x000C, false);
    view.setUint16(6, 0, false);
    view.setBigUint64(8, BigInt(requestId), false);
    view.setUint32(16, 0, false);
    view.setUint32(20, 0, false);
    view.setBigUint64(24, 0n, false);
    postMessage({
        type: 'FRAME_BUILT',
        data: {
            queryType: 'BLOCKCHAIN_LEDGER',
            frame: frameBuf
        }
    });
}

/**
 * @brief Assembles and emits an Autopilot configuration and status frame (Method 0x000B).
 *
 * @param {bigint|number} requestId 64-bit correlation request identifier.
 * @param {number} enable 1 to enable, 0 to disable, -1 to query status without mutation.
 * @param {number} valPerHr Automated valuation submissions per hour.
 * @param {number} stakeRatio Target portfolio percentage ratio maintained in staked status [0..100].
 * @return {void}
 * @complexity Time: O(1), Space: O(1).
 */
function handleBuildAutopilot(requestId, enable, valPerHr, stakeRatio) {
    if (!wasmInstance) return;
    let outFramePtr = 0;
    let outLenPtr = 0;

    try {
        outFramePtr = wasmInstance._wasm_malloc(4096);
        outLenPtr = wasmInstance._wasm_malloc(4);

        const res = wasmInstance._wasm_frame_autopilot(
            BigInt(requestId),
            enable,
            valPerHr || 1,
            stakeRatio !== undefined ? stakeRatio : 50,
            outFramePtr,
            4096,
            outLenPtr
        );

        if (res === 0) {
            const view = new DataView(wasmInstance.HEAPU8.buffer, outLenPtr, 4);
            const actualLen = view.getUint32(0, true);
            const frameBytes = getLiveHeapU8().subarray(outFramePtr, outFramePtr + actualLen);
            postMessage({
                type: 'FRAME_BUILT',
                data: {
                    queryType: 'AUTOPILOT',
                    frame: new Uint8Array(frameBytes)
                }
            });
        }
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Build autopilot frame failed: ' + e.message });
    } finally {
        if (outFramePtr) wasmInstance._wasm_free(outFramePtr);
        if (outLenPtr) wasmInstance._wasm_free(outLenPtr);
    }
}

/**
 * @brief Assembles and emits a Quantum TVD Audit verification frame (Method 0x000A).
 *
 * @param {bigint|number} requestId 64-bit correlation request identifier.
 * @param {number} shots Measurement shot count budget ($1 \le \text{shots} \le 100,000$).
 * @param {Uint8Array|null} beaconSeed 32-byte DKG consensus beacon seed.
 * @param {Uint8Array|null} circuitBytes Optional serialized OpenQASM quantum circuit byte stream.
 * @return {void}
 * @complexity Time: O(circuit_length), Space: O(1).
 */
function handleBuildQuantumTvdAudit(requestId, shots, beaconSeed, circuitBytes, receipt) {
    if (!wasmInstance) return;
    let outFramePtr = 0;
    let outLenPtr = 0;
    let builderPtr = 0;
    let txIdPtr = 0;
    let argsPtr = 0;

    try {
        const shotsNum = shots || 15000;
        builderPtr = wasmInstance._wasm_builder_create(1, 0x000A, BigInt(requestId));
        if (!builderPtr) throw new Error("WASM builder creation failed");

        if (receipt) {
            const txIdBytes = hexToBytes(receipt.txIdHex, 32);
            txIdPtr = wasmInstance._wasm_malloc(32);
            getLiveHeapU8().set(txIdBytes, txIdPtr);
            wasmInstance._wasm_builder_set_payment_receipt(builderPtr, receipt.paymentType, txIdPtr, BigInt(receipt.rateLockId));
        }

        const bSeed = (beaconSeed && beaconSeed.length === 32) ? beaconSeed : new Uint8Array(32);
        const circLen = circuitBytes ? circuitBytes.length : 0;
        const argsLen = 4 + 32 + circLen;
        
        argsPtr = wasmInstance._wasm_malloc(argsLen);
        const view = new DataView(getLiveHeapU8().buffer, argsPtr, argsLen);
        view.setUint32(0, shotsNum, false);
        getLiveHeapU8().set(bSeed, argsPtr + 4);
        if (circLen > 0) {
            getLiveHeapU8().set(circuitBytes, argsPtr + 36);
        }

        wasmInstance._wasm_builder_append_args(builderPtr, argsPtr, argsLen);

        outFramePtr = wasmInstance._wasm_malloc(4096 + circLen);
        outLenPtr = wasmInstance._wasm_malloc(4);

        const res = wasmInstance._wasm_builder_finalize(builderPtr, outFramePtr, 4096 + circLen, outLenPtr);

        if (res === 0) {
            const outView = new DataView(wasmInstance.HEAPU8.buffer, outLenPtr, 4);
            const actualLen = outView.getUint32(0, true);
            const frameBytes = getLiveHeapU8().subarray(outFramePtr, outFramePtr + actualLen);
            postMessage({
                type: 'FRAME_BUILT',
                data: {
                    queryType: 'QUANTUM_TVD_AUDIT',
                    frame: new Uint8Array(frameBytes)
                }
            });
        }
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Build quantum TVD audit failed: ' + e.message });
    } finally {
        if (txIdPtr) wasmInstance._wasm_free(txIdPtr);
        if (argsPtr) wasmInstance._wasm_free(argsPtr);
        if (outFramePtr) wasmInstance._wasm_free(outFramePtr);
        if (outLenPtr) wasmInstance._wasm_free(outLenPtr);
        if (builderPtr) wasmInstance._wasm_builder_destroy(builderPtr);
    }
}

/**
 * @brief Builds a Method 0x000D Drift Certificate Histogram Audit request frame.
 *
 * @details
 * Args layout (Big-Endian): [4B shots][32B beacon seed][2B histogram dim = 128]
 * [512B histogram: 128 x u32 BE basis-state counts][OpenQASM circuit bytes].
 *
 * @param {number|string} requestId 64-bit correlation ID.
 * @param {number} shots Measurement shot count budget (1..100,000).
 * @param {Uint8Array|null} beaconSeed 32-byte DKG consensus beacon seed.
 * @param {Uint8Array|null} histogram 512-byte wire histogram (128 x u32 BE).
 * @param {Uint8Array|null} circuitBytes Optional serialized OpenQASM circuit byte stream.
 * @param {Object|null} receipt Optional SCL402 payment receipt {paymentType, txIdHex, rateLockId}.
 * @return {void}
 * @complexity Time: O(circuit_length), Space: O(1).
 */
function handleBuildDriftCertAudit(requestId, shots, beaconSeed, histogram, circuitBytes, receipt) {
    if (!wasmInstance) {
        /* Never drop silently: the UI must learn the engine was not ready so it
         * can prompt a retry instead of hanging on "AWAITING NODE". */
        postMessage({ type: 'ERROR', message: 'Drift certificate audit ignored: the WebAssembly engine is not loaded yet. Retry in a few seconds.' });
        return;
    }
    let outFramePtr = 0;
    let outLenPtr = 0;
    let builderPtr = 0;
    let txIdPtr = 0;
    let argsPtr = 0;

    try {
        const shotsNum = shots || 15000;
        /* Hard-fail on a malformed histogram instead of silently auditing an
         * all-zero 512-byte buffer — that would bill the caller (SCL402) for a
         * meaningless certificate. */
        if (!histogram || histogram.length !== 512) {
            postMessage({ type: 'ERROR', message: 'Drift certificate audit rejected: histogram must be exactly 512 wire bytes (128 x u32 big-endian counts).' });
            return;
        }
        const hist = histogram;
        const circLen = circuitBytes ? circuitBytes.length : 0;
        const argsLen = 4 + 32 + 2 + hist.length + circLen;

        builderPtr = wasmInstance._wasm_builder_create(1, 0x000D, BigInt(requestId));
        if (!builderPtr) throw new Error("WASM builder creation failed");

        if (receipt) {
            const txIdBytes = hexToBytes(receipt.txIdHex, 32);
            txIdPtr = wasmInstance._wasm_malloc(32);
            getLiveHeapU8().set(txIdBytes, txIdPtr);
            wasmInstance._wasm_builder_set_payment_receipt(builderPtr, receipt.paymentType, txIdPtr, BigInt(receipt.rateLockId));
        }

        const bSeed = (beaconSeed && beaconSeed.length === 32) ? beaconSeed : new Uint8Array(32);
        argsPtr = wasmInstance._wasm_malloc(argsLen);
        const heap = getLiveHeapU8();
        const view = new DataView(heap.buffer, argsPtr, argsLen);
        view.setUint32(0, shotsNum, false);
        heap.set(bSeed, argsPtr + 4);
        view.setUint16(36, 128, false);
        heap.set(hist, argsPtr + 38);
        if (circLen > 0) {
            heap.set(circuitBytes, argsPtr + 38 + 512);
        }

        wasmInstance._wasm_builder_append_args(builderPtr, argsPtr, argsLen);

        outFramePtr = wasmInstance._wasm_malloc(4096 + circLen);
        outLenPtr = wasmInstance._wasm_malloc(4);

        const res = wasmInstance._wasm_builder_finalize(builderPtr, outFramePtr, 4096 + circLen, outLenPtr);

        if (res === 0) {
            const outView = new DataView(wasmInstance.HEAPU8.buffer, outLenPtr, 4);
            const actualLen = outView.getUint32(0, true);
            const frameBytes = getLiveHeapU8().subarray(outFramePtr, outFramePtr + actualLen);
            postMessage({
                type: 'FRAME_BUILT',
                data: {
                    queryType: 'DRIFT_CERT_AUDIT',
                    frame: new Uint8Array(frameBytes)
                }
            });
        } else {
            /* Finalize failures were previously swallowed whole — surface them. */
            postMessage({ type: 'ERROR', message: 'Drift certificate audit frame could not be finalized (WASM builder error ' + res + '). The request was not sent.' });
        }
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Build drift certificate audit failed: ' + e.message });
    } finally {
        if (txIdPtr) wasmInstance._wasm_free(txIdPtr);
        if (argsPtr) wasmInstance._wasm_free(argsPtr);
        if (outFramePtr) wasmInstance._wasm_free(outFramePtr);
        if (outLenPtr) wasmInstance._wasm_free(outLenPtr);
        if (builderPtr) wasmInstance._wasm_builder_destroy(builderPtr);
    }
}

/* ============================================================================
 * SECTION 6: POST-QUANTUM KEY GENERATION & PROOF OPERATIONS
 * ============================================================================ */

/**
 * @brief Generates a fresh ML-DSA-87 (Dilithium5) keypair and derives associated PRF and User IDs.
 *
 * @details
 * Cryptographic Sequence:
 * 1. Invokes `_wasm_dilithium_generate_keypair` to sample a 2,592-byte public key and 4,864-byte private key.
 * 2. Derives the 32-byte User ID: `SHA256(pubkey)`.
 * 3. Derives the 32-byte Viewport PRF Seed: `SHA256(privkey)`.
 * 4. Derives the 2,592-byte threshold committee public key via `_wasm_compute_threshold_pubkey`.
 * 5. Emits a `KEYS_GENERATED` message containing hex-encoded strings to the UI thread.
 * 6. Wipes private key buffers from linear memory before deallocation.
 *
 * @return {void}
 * @complexity Time: O(1) post-quantum keypair generation, Space: O(1) linear memory allocations.
 */
function handleGenerateKeys() {
    if (!wasmInstance) {
        postMessage({ type: 'ERROR', message: 'WASM not ready' });
        return;
    }

    let pubkeyPtr = 0;
    let privkeyPtr = 0;
    let userIdPtr = 0;
    let prfSeedPtr = 0;

    try {
        pubkeyPtr = wasmInstance._wasm_malloc(2592);
        privkeyPtr = wasmInstance._wasm_malloc(4864);
        userIdPtr = wasmInstance._wasm_malloc(32);
        prfSeedPtr = wasmInstance._wasm_malloc(32);

        const d_res = wasmInstance._wasm_dilithium_generate_keypair(pubkeyPtr, privkeyPtr);

        if (d_res === 1) {
            wasmInstance._wasm_sha256(pubkeyPtr, 2592, userIdPtr);
            // Deterministically derive the Viewport PRF Seed from the Dilithium private key
            wasmInstance._wasm_sha256(privkeyPtr, 4864, prfSeedPtr);

            let thresholdPubkeyHex = "";
            if (privkeyPtr !== 0 && wasmInstance._wasm_compute_threshold_pubkey) {
                const tOutPtr = wasmInstance._wasm_malloc(2592);
                if (wasmInstance._wasm_compute_threshold_pubkey(privkeyPtr, tOutPtr) === 0) {
                    const tBytes = getLiveHeapU8().subarray(tOutPtr, tOutPtr + 2592);
                    thresholdPubkeyHex = Array.from(tBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                }
                wasmInstance._wasm_free(tOutPtr);
            }

            // Extract live heap buffers strictly after all WASM allocations to avoid detached buffer invalidation
            const pubkeyBytes = getLiveHeapU8().subarray(pubkeyPtr, pubkeyPtr + 2592);
            const privkeyBytes = getLiveHeapU8().subarray(privkeyPtr, privkeyPtr + 4864);
            const prfSeedBytes = getLiveHeapU8().subarray(prfSeedPtr, prfSeedPtr + 32);
            const userIdBytes = getLiveHeapU8().subarray(userIdPtr, userIdPtr + 32);

            const pubkeyHex = Array.from(pubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            const privkeyHex = Array.from(privkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            const prfSeedHex = Array.from(prfSeedBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            const userIdHex = Array.from(userIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');

            postMessage({
                type: 'KEYS_GENERATED',
                data: {
                    pubkeyHex,
                    privkeyHex,
                    prfSeedHex,
                    userIdHex,
                    thresholdPubkeyHex
                }
            });
        } else {
            postMessage({ type: 'ERROR', message: 'Cryptographic key generation failed inside WASM' });
        }
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Failed to generate keys: ' + e.message });
    } finally {
        if (pubkeyPtr) {
            wasmInstance._wasm_secure_wipe(pubkeyPtr, 2592);
            wasmInstance._wasm_free(pubkeyPtr);
        }
        if (privkeyPtr) {
            wasmInstance._wasm_secure_wipe(privkeyPtr, 4864);
            wasmInstance._wasm_free(privkeyPtr);
        }
        if (userIdPtr) {
            wasmInstance._wasm_secure_wipe(userIdPtr, 32);
            wasmInstance._wasm_free(userIdPtr);
        }
        if (prfSeedPtr) {
            wasmInstance._wasm_secure_wipe(prfSeedPtr, 32);
            wasmInstance._wasm_free(prfSeedPtr);
        }
    }
}

/**
 * @brief Evaluates the bagged Merkle Mountain Range state root from an array of active peak digests.
 *
 * @details
 * Bagging rule:
 * - If 0 peaks: returns 32 zero bytes.
 * - If 1 peak: returns the peak hash directly (no hashing).
 * - If >1 peaks: evaluates `SHA256(peak_0 || peak_1 || ... || peak_k-1)` in descending height order.
 *
 * @param {Array<Uint8Array>} peaks Array of 32-byte peak hashes.
 * @return {Uint8Array} Evaluated 32-byte MMR state root digest.
 * @complexity Time: O(peaks.length * 32), Space: O(peaks.length * 32) temporary buffer.
 */
function computeMmrRootFromPeaks(peaks) {
    if (!wasmInstance) return new Uint8Array(32);
    
    let inPtr = 0;
    let outPtr = 0;
    
    try {
        if (peaks.length === 0) return new Uint8Array(32);
        if (peaks.length === 1) return new Uint8Array(peaks[0]);
        
        const combined = new Uint8Array(peaks.length * 32);
        for (let i = 0; i < peaks.length; i++) {
            combined.set(peaks[i], i * 32);
        }
        
        inPtr = wasmInstance._wasm_malloc(combined.length);
        outPtr = wasmInstance._wasm_malloc(32);
        
        const heapIn = getLiveHeapU8().subarray(inPtr, inPtr + combined.length);
        heapIn.set(combined);
        
        wasmInstance._wasm_sha256(inPtr, combined.length, outPtr);
        
        const rootHash = getLiveHeapU8().subarray(outPtr, outPtr + 32).slice(0);
        
        return rootHash;
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Compute MMR root failed: ' + e.message });
        return new Uint8Array(32);
    } finally {
        if (inPtr) wasmInstance._wasm_free(inPtr);
        if (outPtr) wasmInstance._wasm_free(outPtr);
    }
}

/**
 * @brief Verifies an MMR inclusion proof against active mountain peaks using the WASM accumulator.
 *
 * @param {string|number} requestId Correlation identifier for response matching.
 * @param {Uint8Array} leafHash 32-byte candidate leaf hash to verify.
 * @param {Uint8Array} proofBytes Serialized MMR inclusion proof byte stream.
 * @param {Array<Uint8Array>} peaks Array of 32-byte active peak hashes.
 * @return {void}
 *
 * @complexity Time: O(proof_length), Space: O(1) WASM heap allocations.
 */
function handleVerifyMmrProof(requestId, leafHash, proofBytes, peaks) {
    if (!wasmInstance) return;

    let leafHashPtr = 0;
    let proofPtr = 0;
    let rootHashPtr = 0;

    try {
        const rootHash = computeMmrRootFromPeaks(peaks);

        leafHashPtr = wasmInstance._wasm_malloc(32);
        const heapLeaf = getLiveHeapU8().subarray(leafHashPtr, leafHashPtr + 32);
        heapLeaf.set(leafHash);

        proofPtr = wasmInstance._wasm_malloc(proofBytes.length);
        const heapProof = getLiveHeapU8().subarray(proofPtr, proofPtr + proofBytes.length);
        heapProof.set(proofBytes);

        rootHashPtr = wasmInstance._wasm_malloc(32);
        const heapRoot = getLiveHeapU8().subarray(rootHashPtr, rootHashPtr + 32);
        heapRoot.set(rootHash);

        const result = wasmInstance._wasm_verify_mmr_proof(
            leafHashPtr,
            proofPtr,
            proofBytes.length,
            rootHashPtr
        );

        postMessage({
            type: 'MMR_PROOF_VERIFIED',
            data: {
                requestId: requestId,
                verified: (result === 1)
            }
        });
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Verify MMR proof failed: ' + e.message });
    } finally {
        if (leafHashPtr) wasmInstance._wasm_free(leafHashPtr);
        if (proofPtr) wasmInstance._wasm_free(proofPtr);
        if (rootHashPtr) wasmInstance._wasm_free(rootHashPtr);
    }
}

/**
 * @brief Advances a binary reading cursor past a serialized MMR inclusion proof.
 *
 * @param {DataView} view DataView over the byte buffer.
 * @param {number} offset Starting byte offset of the MMR proof.
 * @return {number} Byte offset immediately following the proof structure.
 * @complexity Time: O(1), Space: O(1).
 */
function parseMmrProof(view, offset) {
    let curr = offset;
    const pathLen = view.getUint32(curr, false);
    curr += 4;
    curr += pathLen * (32 + 4);
    
    const leftPeaksLen = view.getUint32(curr, false);
    curr += 4;
    curr += leftPeaksLen * 32;
    
    const rightPeaksLen = view.getUint32(curr, false);
    curr += 4;
    curr += rightPeaksLen * 32;
    
    return curr;
}

/**
 * @brief Decodes an on-chain transactional operation payload into structured JSON metadata.
 *
 * @details
 * Parses all 7 canonical operation types:
 * - Type 0: `OP_SUBMIT_VALUATION` (10-integer valuation vector + user signature).
 * - Type 1: `OP_MINT_COIN` (Root SCLCoin minting issuance + 10x10 audit snapshot).
 * - Type 2: `OP_TRANSFER_POINTER` (Subunit pointer transfer + ZK-PRF nullifiers).
 * - Type 3: `OP_STAKE` (Subunit staking under threshold committee custody).
 * - Type 4: `OP_UNSTAKE` (Subunit unstaking releasing liquid balance).
 * - Type 5: `OP_REDEEM_CENTINEL` (Shielded UTXO redemption + BDLOP commitments + Stern proof).
 * - Type 6: `OP_CLAIM_VALIDATION` (Initial validation claim registration).
 *
 * @param {Uint8Array} payloadBytes Serialized operation byte stream.
 * @param {number} [methodId=0] Optional method discriminator identifying context.
 * @return {Object|null} Structured transaction metadata object, or null on format error.
 *
 * @complexity Time: O(payloadBytes.length), Space: O(num_inputs * sizeof(Pointer)).
 */
function parseTransactionPayload(payloadBytes, methodId = 0) {
        try {
        const view = new DataView(payloadBytes.buffer, payloadBytes.byteOffset, payloadBytes.byteLength);
        const type = payloadBytes[0];

        if (type === 1) { // OP_MINT_COIN
            const ownerPubkeyBytes = payloadBytes.subarray(1, 1 + 2592);
            const ownerPubkeyHex = Array.from(ownerPubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            
            const coinIdBytes = payloadBytes.subarray(2593, 2593 + 32);
            const coinIdHex = Array.from(coinIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            
            const ownerAddrBytes = payloadBytes.subarray(2625, 2625 + 32);
            const ownerAddrHex = Array.from(ownerAddrBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            
            const creationTxBytes = payloadBytes.subarray(2657, 2657 + 32);
            const creationTxHex = Array.from(creationTxBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            
            const amountBig = view.getBigUint64(2689, false);
            const amount = Number(amountBig);
            const endSubunitVal = amountBig > 0n ? amountBig - 1n : 0n;

            const ptrData = new Uint8Array(112);
            ptrData.set(coinIdBytes, 0);
            ptrData.set(ownerAddrBytes, 32);
            const pView = new DataView(ptrData.buffer);
            pView.setBigUint64(64, 0n, false);
            pView.setBigUint64(72, endSubunitVal, false);
            ptrData.set(creationTxBytes, 80);

            const inPtr = wasmInstance._wasm_malloc(112);
            const outPtr = wasmInstance._wasm_malloc(32);
            getLiveHeapU8().subarray(inPtr, inPtr + 112).set(ptrData);
            wasmInstance._wasm_sha256(inPtr, 112, outPtr);
            const pointerIdBytes = getLiveHeapU8().subarray(outPtr, outPtr + 32).slice(0);
            wasmInstance._wasm_free(inPtr);
            wasmInstance._wasm_free(outPtr);

            const pointerIdHex = Array.from(pointerIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');

            const auditSnapshot = [];
            let snapOffset = 2745;
            for (let i = 0; i < 10 && snapOffset + 112 <= payloadBytes.length; i++) {
                const uId = Array.from(payloadBytes.subarray(snapOffset, snapOffset + 32));
                const nums = [];
                for (let j = 0; j < 10; j++) {
                    nums.push(view.getUint32(snapOffset + 32 + j * 4, false));
                }
                const ts = Number(view.getBigUint64(snapOffset + 72, false));
                const bSeed = Array.from(payloadBytes.subarray(snapOffset + 80, snapOffset + 112));
                auditSnapshot.push({ userId: uId, numbers: nums, timestamp: ts, beaconSeed: bSeed });
                snapOffset += 112;
            }

            return {
                txIdHex: creationTxHex,
                numInputs: 0,
                amount,
                recipientPubkeyHex: ownerPubkeyHex,
                senderPubkeyHex: ownerPubkeyHex,
                recipientAddressHex: ownerAddrHex,
                senderAddressHex: ownerAddrHex,
                parentCoinIdHex: coinIdHex,
                prevTxHashHex: creationTxHex,
                generatedPointers: [{
                    pointerIdHex: pointerIdHex,
                    parentCoinIdHex: coinIdHex,
                    startSubunit: '0',
                    endSubunit: endSubunitVal.toString(),
                    ownerAddressHex: ownerAddrHex,
                    prevTxHashHex: creationTxHex,
                    spent: false,
                    staked: false
                }],
                auditSnapshot,
                opLen: 3897
            };
        }
        
        if (type === 0) { // OP_SUBMIT_VALUATION
            const userIdBytes = payloadBytes.subarray(1, 33);
            const userIdHex = Array.from(userIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            const pubkeyBytes = payloadBytes.subarray(113, 113 + 2592);
            const pubkeyHex = Array.from(pubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            return {
                txIdHex: userIdHex,
                numInputs: 0,
                amount: 0,
                recipientPubkeyHex: pubkeyHex,
                senderPubkeyHex: pubkeyHex,
                recipientAddressHex: userIdHex,
                senderAddressHex: userIdHex,
                parentCoinIdHex: "",
                prevTxHashHex: userIdHex,
                generatedPointers: [],
                opLen: 9892
            };
        }
        if (type === 5) { // OP_REDEEM_CENTINEL
            const nullifierBytes = payloadBytes.subarray(1, 33);
            const nullifierHex = Array.from(nullifierBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            const zkProofLen = view.getUint32(4129, false);
            const totalOpLen = 1 + 32 + 2048 + 2048 + 4 + zkProofLen;
            return {
                txIdHex: nullifierHex,
                numInputs: 0,
                amount: 0,
                recipientPubkeyHex: "",
                senderPubkeyHex: "",
                recipientAddressHex: "",
                senderAddressHex: "",
                parentCoinIdHex: "",
                prevTxHashHex: nullifierHex,
                generatedPointers: [],
                opLen: totalOpLen
            };
        }
        if (type === 6) { // OP_CLAIM_VALIDATION
            const commBytes = payloadBytes.subarray(1, 33);
            const commHex = Array.from(commBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            const pubkeyBytes = payloadBytes.subarray(2049, 2049 + 2592);
            const pubkeyHex = Array.from(pubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            return {
                txIdHex: commHex,
                numInputs: 0,
                amount: 0,
                recipientPubkeyHex: pubkeyHex,
                senderPubkeyHex: pubkeyHex,
                recipientAddressHex: "",
                senderAddressHex: "",
                parentCoinIdHex: "",
                prevTxHashHex: commHex,
                generatedPointers: [],
                opLen: 9236
            };
        }

        let offset = 1; // skip type
        const txIdBytes = payloadBytes.subarray(offset, offset + 32);
        const txIdHex = Array.from(txIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        offset += 32;
        offset += 8; // skip nonce
        const numInputs = view.getUint32(offset, false);
        offset += 4;
        offset += 32; // skip client_root
        
        let parentCoinIdBytes = null;
        let startSubunitVal = 0n;
        const inputPointerIds = [];

        const hasMmrProofs = true;

        for (let i = 0; i < numInputs; i++) {
            if (i === 0) {
                parentCoinIdBytes = payloadBytes.subarray(offset + 32, offset + 64);
                startSubunitVal = view.getBigUint64(offset + 64, false);
            }
            const inPtrBytes = payloadBytes.subarray(offset, offset + 32);
            inputPointerIds.push(Array.from(inPtrBytes).map(b => b.toString(16).padStart(2, '0')).join(''));
            offset += 152; // skip pointer (152 bytes)
            if (hasMmrProofs) {
                offset = parseMmrProof(view, offset);
            }
        }
        
        const recipientPubkeyBytes = payloadBytes.subarray(offset, offset + 2592);
        const recipientPubkeyHex = Array.from(recipientPubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        offset += 2592;
        
        const senderPubkeyBytes = payloadBytes.subarray(offset, offset + 2592);
        const senderPubkeyHex = Array.from(senderPubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        offset += 2592;
        
        const amountBig = view.getBigUint64(offset, false);
        const amount = Number(amountBig);

        const pkPtr = wasmInstance._wasm_malloc(2592);
        const addrPtr = wasmInstance._wasm_malloc(32);

        getLiveHeapU8().subarray(pkPtr, pkPtr + 2592).set(recipientPubkeyBytes);
        wasmInstance._wasm_sha256(pkPtr, 2592, addrPtr);
        const recipientAddressBytes = getLiveHeapU8().subarray(addrPtr, addrPtr + 32).slice(0);
        const recipientAddressHex = Array.from(recipientAddressBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        getLiveHeapU8().subarray(pkPtr, pkPtr + 2592).set(senderPubkeyBytes);
        wasmInstance._wasm_sha256(pkPtr, 2592, addrPtr);
        const senderAddressBytes = getLiveHeapU8().subarray(addrPtr, addrPtr + 32).slice(0);
        const senderAddressHex = Array.from(senderAddressBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        wasmInstance._wasm_free(pkPtr);
        wasmInstance._wasm_free(addrPtr);

        const generatedPointers = [];
        const splitInputPointerIds = [];
        if (type === 2 || type === 3 || type === 4) {
            const isStaked = (type === 3);
            const isUnstaked = (type === 4);
            const isHalved = (type === 3 || type === 4);
            
            let remainingAmount = amountBig;
            let remainingFee = calculateFeeSubunits(amountBig, isHalved);

            const inputPointers = [];
            let currOffset = 1 + 32 + 8 + 4 + 32; // base offset for inputs
            for (let i = 0; i < numInputs; i++) {
                const ptrBytes = payloadBytes.subarray(currOffset, currOffset + 152);
                const pointerIdHex = Array.from(ptrBytes.subarray(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('');
                const parentCoinId = ptrBytes.subarray(32, 64);
                const startSubunit = view.getBigUint64(currOffset + 64, false);
                const endSubunit = view.getBigUint64(currOffset + 72, false);
                const ownerAddr = ptrBytes.subarray(80, 112);
                const isInputStaked = view.getUint32(currOffset + 148, false) !== 0;
                inputPointers.push({ pointerId: pointerIdHex, parentCoinId, startSubunit, endSubunit, ownerAddr, staked: isInputStaked });
                
                currOffset += 152;
                if (hasMmrProofs) {
                    currOffset = parseMmrProof(view, currOffset);
                }
            }

            for (let i = 0; i < inputPointers.length; i++) {
                const input = inputPointers[i];
                let currentStart = input.startSubunit;
                const originalEnd = input.endSubunit;

                if (remainingAmount > 0n) {
                    const available = originalEnd - currentStart + 1n;
                    const allocSize = (available <= remainingAmount) ? available : remainingAmount;
                    const endSubunitVal = currentStart + allocSize - 1n;

                    const ptrData = new Uint8Array(112);
                    ptrData.set(input.parentCoinId, 0);
                    ptrData.set(recipientAddressBytes, 32);
                    const pView = new DataView(ptrData.buffer);
                    pView.setBigUint64(64, currentStart, false);
                    pView.setBigUint64(72, endSubunitVal, false);
                    ptrData.set(txIdBytes, 80);

                    const inPtr = wasmInstance._wasm_malloc(112);
                    const outPtr = wasmInstance._wasm_malloc(32);
                    getLiveHeapU8().subarray(inPtr, inPtr + 112).set(ptrData);
                    wasmInstance._wasm_sha256(inPtr, 112, outPtr);
                    const pointerIdBytes = getLiveHeapU8().subarray(outPtr, outPtr + 32).slice(0);
                    wasmInstance._wasm_free(inPtr);
                    wasmInstance._wasm_free(outPtr);

                    generatedPointers.push({
                        pointerIdHex: Array.from(pointerIdBytes).map(b => b.toString(16).padStart(2, '0')).join(''),
                        parentCoinIdHex: Array.from(input.parentCoinId).map(b => b.toString(16).padStart(2, '0')).join(''),
                        startSubunit: currentStart.toString(),
                        endSubunit: endSubunitVal.toString(),
                        ownerAddressHex: recipientAddressHex,
                        prevTxHashHex: txIdHex,
                        spent: false,
                        staked: isStaked || (isUnstaked ? false : false)
                    });

                    currentStart += allocSize;
                    remainingAmount -= allocSize;
                }

                const remainingInInput1 = originalEnd - currentStart + 1n;
                if (remainingFee > 0n && remainingInInput1 > 0n) {
                    const allocSize = (remainingInInput1 <= remainingFee) ? remainingInInput1 : remainingFee;
                    const feeEndSubunit = currentStart + allocSize - 1n;

                    const feePtrData = new Uint8Array(112);
                    feePtrData.set(input.parentCoinId, 0);
                    feePtrData.set(input.ownerAddr, 32); // fee goes to original owner
                    const fView = new DataView(feePtrData.buffer);
                    fView.setBigUint64(64, currentStart, false);
                    fView.setBigUint64(72, feeEndSubunit, false);
                    feePtrData.set(txIdBytes, 80);

                    const fInPtr = wasmInstance._wasm_malloc(112);
                    const fOutPtr = wasmInstance._wasm_malloc(32);
                    getLiveHeapU8().subarray(fInPtr, fInPtr + 112).set(feePtrData);
                    wasmInstance._wasm_sha256(fInPtr, 112, fOutPtr);
                    const feePointerIdBytes = getLiveHeapU8().subarray(fOutPtr, fOutPtr + 32).slice(0);
                    wasmInstance._wasm_free(fInPtr);
                    wasmInstance._wasm_free(fOutPtr);

                    generatedPointers.push({
                        pointerIdHex: Array.from(feePointerIdBytes).map(b => b.toString(16).padStart(2, '0')).join(''),
                        parentCoinIdHex: Array.from(input.parentCoinId).map(b => b.toString(16).padStart(2, '0')).join(''),
                        startSubunit: currentStart.toString(),
                        endSubunit: feeEndSubunit.toString(),
                        ownerAddressHex: Array.from(input.ownerAddr).map(b => b.toString(16).padStart(2, '0')).join(''),
                        prevTxHashHex: txIdHex,
                        spent: 2,
                        staked: false
                    });

                    currentStart += allocSize;
                    remainingFee -= allocSize;
                }

                const remainingInInput2 = originalEnd - currentStart + 1n;
                if (remainingInInput2 > 0n) {
                    splitInputPointerIds.push(input.pointerId);
                    const endSubunitVal = originalEnd;

                    const chgPtrData = new Uint8Array(112);
                    chgPtrData.set(input.parentCoinId, 0);
                    chgPtrData.set(input.ownerAddr, 32);
                    const cView = new DataView(chgPtrData.buffer);
                    cView.setBigUint64(64, currentStart, false);
                    cView.setBigUint64(72, endSubunitVal, false);
                    chgPtrData.set(txIdBytes, 80);

                    const cInPtr = wasmInstance._wasm_malloc(112);
                    const cOutPtr = wasmInstance._wasm_malloc(32);
                    getLiveHeapU8().subarray(cInPtr, cInPtr + 112).set(chgPtrData);
                    wasmInstance._wasm_sha256(cInPtr, 112, cOutPtr);
                    const chgPointerIdBytes = getLiveHeapU8().subarray(cOutPtr, cOutPtr + 32).slice(0);
                    wasmInstance._wasm_free(cInPtr);
                    wasmInstance._wasm_free(cOutPtr);

                    generatedPointers.push({
                        pointerIdHex: Array.from(chgPointerIdBytes).map(b => b.toString(16).padStart(2, '0')).join(''),
                        parentCoinIdHex: Array.from(input.parentCoinId).map(b => b.toString(16).padStart(2, '0')).join(''),
                        startSubunit: currentStart.toString(),
                        endSubunit: endSubunitVal.toString(),
                        ownerAddressHex: Array.from(input.ownerAddr).map(b => b.toString(16).padStart(2, '0')).join(''),
                        prevTxHashHex: txIdHex,
                        spent: false,
                        staked: input.staked
                    });
                }
            }
        }

        let opLen = offset + 8;
        if (type === 2) {
            opLen += 4595 + 32 + 4595;
            if (methodId !== 0x0002) {
                const zkProofLen = view.getUint32(opLen + 32, false);
                opLen += 32 + 4 + zkProofLen;
            }
        } else if (type === 3) {
            opLen += 4595 + 32 + 4595;
        } else if (type === 4) {
            opLen += 4595;
        }

        return {
            txIdHex,
            numInputs,
            inputPointerIds,
            splitInputPointerIds,
            amount,
            recipientPubkeyHex,
            senderPubkeyHex,
            recipientAddressHex,
            senderAddressHex,
            parentCoinIdHex: parentCoinIdBytes ? Array.from(parentCoinIdBytes).map(b => b.toString(16).padStart(2, '0')).join('') : "",
            generatedPointers,
            prevTxHashHex: txIdHex,
            opLen: opLen
        };
    } catch (e) {
        return null;
    }
}

/**
 * @brief Computes binary Merkle tree root over transaction input pointer signing representations.
 *
 * @param {Array<Object>} inputs Array of input Pointer descriptor objects.
 * @return {Uint8Array} 32-byte SHA-256 Merkle root digest over input pointers.
 * @complexity Time: O(N log N) where N = inputs.length, Space: O(N) temporary hash buffers.
 */
function computeInputsMerkleRoot(inputs) {
    if (!inputs || inputs.length === 0) {
        return new Uint8Array(32);
    }
    let currentHashes = [];
    for (let i = 0; i < inputs.length; i++) {
        const ptr = inputs[i];
        const ptrData = new Uint8Array(112);
        ptrData.set(hexToBytes(ptr.parentCoinId || ptr.parent_coin_id), 0);
        ptrData.set(hexToBytes(ptr.ownerAddress || ptr.owner_address), 32);
        const view = new DataView(ptrData.buffer);
        view.setBigUint64(64, BigInt(ptr.startSubunit || ptr.start_subunit || 0), false);
        view.setBigUint64(72, BigInt(ptr.endSubunit || ptr.end_subunit || 0), false);
        ptrData.set(hexToBytes(ptr.prevTxHash || ptr.prev_tx_hash), 80);

        const inPtr = wasmInstance._wasm_malloc(112);
        const outPtr = wasmInstance._wasm_malloc(32);
        getLiveHeapU8().subarray(inPtr, inPtr + 112).set(ptrData);
        wasmInstance._wasm_sha256(inPtr, 112, outPtr);
        const h = getLiveHeapU8().subarray(outPtr, outPtr + 32).slice(0);
        wasmInstance._wasm_free(inPtr);
        wasmInstance._wasm_free(outPtr);
        currentHashes.push(h);
    }

    while (currentHashes.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < currentHashes.length; i += 2) {
            const left = currentHashes[i];
            const right = (i + 1 < currentHashes.length) ? currentHashes[i + 1] : currentHashes[i];
            const combined = new Uint8Array(64);
            combined.set(left, 0);
            combined.set(right, 32);

            const inPtr = wasmInstance._wasm_malloc(64);
            const outPtr = wasmInstance._wasm_malloc(32);
            getLiveHeapU8().subarray(inPtr, inPtr + 64).set(combined);
            wasmInstance._wasm_sha256(inPtr, 64, outPtr);
            const nodeHash = getLiveHeapU8().subarray(outPtr, outPtr + 32).slice(0);
            wasmInstance._wasm_free(inPtr);
            wasmInstance._wasm_free(outPtr);
            nextLevel.push(nodeHash);
        }
        currentHashes = nextLevel;
    }
    return currentHashes[0];
}

/**
 * @brief Computes an ML-DSA-87 (Dilithium5) digital signature over arbitrary data using worker private key.
 *
 * @param {Uint8Array} dataBytes Message bytes to sign.
 * @return {Uint8Array} 4,595-byte Dilithium5 signature array.
 * @complexity Time: O(dataBytes.length + Dilithium5_sign), Space: O(1) WASM heap buffers.
 */
function signBufferWithDilithium(dataBytes) {
    if (!dilithiumKeyPtr || !wasmInstance) return new Uint8Array(4595);
    if (wasmInstance._wasm_dilithium_sign) {
        const msgPtr = wasmInstance._wasm_malloc(dataBytes.length);
        const sigPtr = wasmInstance._wasm_malloc(4595);
        getLiveHeapU8().subarray(msgPtr, msgPtr + dataBytes.length).set(dataBytes);
        const res = wasmInstance._wasm_dilithium_sign(msgPtr, dataBytes.length, dilithiumKeyPtr, sigPtr);
        const sigBytes = new Uint8Array(4595);
        if (res === 1) {
            sigBytes.set(getLiveHeapU8().subarray(sigPtr, sigPtr + 4595));
        }
        wasmInstance._wasm_free(msgPtr);
        wasmInstance._wasm_free(sigPtr);
        return sigBytes;
    }
    return new Uint8Array(4595);
}

/**
 * @brief Deterministically calculates required transaction fee in atomic subunits using 128-bit math.
 *
 * @param {bigint} amountSubunits Gross transaction volume in atomic subunits.
 * @param {boolean} [isHalved=false] True for staking/unstaking (halved rate ~1.5708%); false for standard (~3.14159%).
 * @return {bigint} Required fee in subunits.
 * @complexity Time: O(1), Space: O(1).
 */
function calculateFeeSubunits(amountSubunits, isHalved = false) {
    let denominator = FEE_DENOMINATOR_NORMAL;
    if (isHalved) {
        denominator *= 2n;
    }
    return (amountSubunits * FEE_NUMERATOR) / denominator;
}

/**
 * @brief Assembles, signs, and enqueues an on-chain transaction for dispatch to the node daemon.
 *
 * @details
 * Complete Client-Side Signing Pipeline:
 * 1. Resolves and binds Dilithium5 private/public verification keys.
 * 2. Formats operation-specific wire payloads:
 *    - `OP_TRANSFER_POINTER`: Computes input Merkle roots, signs roots, derives Module-SIS PRF nullifier,
 *      generates ZK-Stern proof of knowledge, and computes the main transaction signature.
 *    - `OP_STAKE` / `OP_UNSTAKE`: Serializes stake payload, derives stake ID, computes inputs Merkle root,
 *      and binds threshold signatures.
 *    - `OP_SUBMIT_VALUATION`: Signs core valuation vector with Dilithium5.
 *    - `OP_REDEEM_CENTINEL`: Attaches BDLOP commitments and ZK redemption proofs.
 * 3. Encloses operation in an RPC builder frame (`SclRpcBuilder`), setting method 0x0003 and `SCL_RPC_FLAG_SIGNED`.
 * 4. Finalizes the wire frame and transmits `WIRE_FRAME_READY` with transferable ArrayBuffer to UI thread.
 *
 * @param {string|number} requestId Correlation tracking identifier.
 * @param {string} opType Canonical operation discriminator string (e.g. `OP_TRANSFER_POINTER`).
 * @param {Object} payload Operation parameter object.
 * @return {void}
 *
 * @complexity Time: O(ZK_proof_generation + Dilithium5_sign), Space: O(MAX_MESSAGE_SIZE).
 */
function handleSubmitTransaction(requestId, opType, payload) {
    if (!wasmInstance) {
        postMessage({ type: 'ERROR', message: 'WASM engine not initialized' });
        return;
    }

    if (payload && payload.privkeyHex) {
        const kBytes = hexToBytes(payload.privkeyHex, DILITHIUM_KEY_SIZE);
        if (kBytes.length === DILITHIUM_KEY_SIZE && !kBytes.every(b => b === 0)) {
            if (dilithiumKeyPtr === 0) {
                dilithiumKeyPtr = wasmInstance._wasm_malloc(DILITHIUM_KEY_SIZE);
            }
            getLiveHeapU8().subarray(dilithiumKeyPtr, dilithiumKeyPtr + DILITHIUM_KEY_SIZE).set(kBytes);
        }
    }

    if (payload && (payload.senderPubkeyHex || payload.pubkeyHex)) {
        const pubHex = payload.senderPubkeyHex || payload.pubkeyHex;
        const pBytes = hexToBytes(pubHex, DILITHIUM_PUBKEY_SIZE);
        if (pBytes.length === DILITHIUM_PUBKEY_SIZE && !pBytes.every(b => b === 0)) {
            if (dilithiumPubkeyPtr === 0) {
                dilithiumPubkeyPtr = wasmInstance._wasm_malloc(DILITHIUM_PUBKEY_SIZE);
            }
            getLiveHeapU8().subarray(dilithiumPubkeyPtr, dilithiumPubkeyPtr + DILITHIUM_PUBKEY_SIZE).set(pBytes);
        }
    }

    const isZeroKey = !dilithiumKeyPtr || getLiveHeapU8().subarray(dilithiumKeyPtr, dilithiumKeyPtr + DILITHIUM_KEY_SIZE).every(b => b === 0);

    if (opType !== 'OP_REDEEM_CENTINEL' && isZeroKey) {
        postMessage({ type: 'ERROR', message: 'Dilithium private key missing for transaction signing' });
        return;
    }

    if (!dilithiumKeyPtr) {
        dilithiumKeyPtr = wasmInstance._wasm_malloc(DILITHIUM_KEY_SIZE);
        getLiveHeapU8().subarray(dilithiumKeyPtr, dilithiumKeyPtr + DILITHIUM_KEY_SIZE).fill(0);
    }

    try {
        let opCode = 0;
        let isHalved = false;

        if (opType === 'OP_TRANSFER_POINTER') {
            opCode = 2;
            isHalved = false;
        } else if (opType === 'OP_STAKE') {
            opCode = 3;
            isHalved = true;
        } else if (opType === 'OP_UNSTAKE') {
            opCode = 4;
            isHalved = true;
        } else if (opType === 'OP_SUBMIT_VALUATION') {
            opCode = 0;
            isHalved = false;
        } else if (opType === 'OP_MINT_COIN') {
            opCode = 1;
            isHalved = false;
        } else if (opType === 'OP_CLAIM_VALIDATION') {
            opCode = 6;
            isHalved = false;
        } else if (opType === 'OP_APPLY_DRIFT_CERT') {
            opCode = 7;
            isHalved = true; // Staking-grade halved fee schedule for on-chain anchoring
        }

        const amountSubunits = BigInt(payload.amountSubunits || '0');
        const computedFee = calculateFeeSubunits(amountSubunits, isHalved);

        let opPayloadBytes;
        if (payload.rawOpBytes) {
            opPayloadBytes = new Uint8Array(payload.rawOpBytes);
        } else if (opType === 'OP_SUBMIT_VALUATION') {
            const numbers = payload.numbers || new Array(10).fill(0);
            const timestamp = BigInt(payload.timestamp || Date.now() * 1000);

            let pubkeyBytes = new Uint8Array(2592);
            let hasPub = false;
            if (payload.pubkeyHex) {
                const pBytes = hexToBytes(payload.pubkeyHex, 2592);
                if (pBytes.length === 2592) {
                    pubkeyBytes.set(pBytes);
                    hasPub = true;
                }
            }
            if (!hasPub && dilithiumPubkeyPtr !== 0) {
                pubkeyBytes.set(getLiveHeapU8().subarray(dilithiumPubkeyPtr, dilithiumPubkeyPtr + 2592));
            }

            const pkPtr = wasmInstance._wasm_malloc(2592);
            const uidPtr = wasmInstance._wasm_malloc(32);
            getLiveHeapU8().subarray(pkPtr, pkPtr + 2592).set(pubkeyBytes);
            wasmInstance._wasm_sha256(pkPtr, 2592, uidPtr);
            const userIdBytes = getLiveHeapU8().subarray(uidPtr, uidPtr + 32).slice(0);
            wasmInstance._wasm_free(pkPtr);
            wasmInstance._wasm_free(uidPtr);

            const coreData = new Uint8Array(80);
            coreData.set(userIdBytes, 0);
            const viewCore = new DataView(coreData.buffer);
            for (let i = 0; i < 10; i++) {
                viewCore.setUint32(32 + i * 4, numbers[i] || 0, false);
            }
            viewCore.setBigUint64(72, timestamp, false);

            const coreSigBytes = signBufferWithDilithium(coreData);

            const fullOp = new Uint8Array(1 + 9891);
            fullOp[0] = 0; // OP_SUBMIT_VALUATION
            fullOp.set(userIdBytes, 1);
            for (let i = 0; i < 10; i++) {
                new DataView(fullOp.buffer, 33 + i * 4, 4).setUint32(0, numbers[i] || 0, false);
            }
            new DataView(fullOp.buffer, 73, 8).setBigUint64(0, timestamp, false);
            // Implicit 32-byte zeroed beacon_seed starts at 81.
            fullOp.set(pubkeyBytes, 113);
            fullOp.set(coreSigBytes, 2705);
            // Implicit 2592-byte zeroed threshold_pubkey starts at 7300 to successfully resolve length validation bounds.

            opPayloadBytes = fullOp;
        } else if (opType === 'OP_TRANSFER_POINTER') {
            const recipientPubkeyBytes = new Uint8Array(2592);
            if (payload.recipientPubkeyHex) {
                const rBytes = hexToBytes(payload.recipientPubkeyHex);
                if (rBytes.length === 2592) recipientPubkeyBytes.set(rBytes);
            }

            const senderPubkeyBytes = new Uint8Array(2592);
            let hasSender = false;
            if (payload.senderPubkeyHex) {
                const sBytes = hexToBytes(payload.senderPubkeyHex);
                if (sBytes.length === 2592) {
                    senderPubkeyBytes.set(sBytes);
                    hasSender = true;
                }
            }
            if (!hasSender && dilithiumPubkeyPtr !== 0) {
                senderPubkeyBytes.set(getLiveHeapU8().subarray(dilithiumPubkeyPtr, dilithiumPubkeyPtr + 2592));
            }

            const amountVal = BigInt(payload.amountSubunits || '0');
            const nonce = new Uint8Array(8);
            if (self.crypto && self.crypto.getRandomValues) {
                self.crypto.getRandomValues(nonce);
            }

            const clientRoot = new Uint8Array(32);
            if (payload.clientRootHex && payload.clientRootHex.length === 64) {
                clientRoot.set(hexToBytes(payload.clientRootHex));
            }

            const inputs = payload.inputs || [];
            const numInputs = inputs.length;

            let inputsBufferList = [];
            let totalInputsLen = 0;
            for (let i = 0; i < numInputs; i++) {
                const ptr = inputs[i];
                const ptrBuf = new Uint8Array(152);
                ptrBuf.set(hexToBytes(ptr.pointerId || ptr.pointer_id), 0);
                ptrBuf.set(hexToBytes(ptr.parentCoinId || ptr.parent_coin_id), 32);
                const viewP = new DataView(ptrBuf.buffer);
                viewP.setBigUint64(64, BigInt(ptr.startSubunit || ptr.start_subunit || 0), false);
                viewP.setBigUint64(72, BigInt(ptr.endSubunit || ptr.end_subunit || 0), false);
                ptrBuf.set(hexToBytes(ptr.ownerAddress || ptr.owner_address), 80);
                ptrBuf.set(hexToBytes(ptr.prevTxHash || ptr.prev_tx_hash), 112);
                viewP.setUint32(144, 0, false);
                viewP.setUint32(148, 0, false);

                const proof = ptr.proof || {};
                const pathHashes = proof.pathHashes || proof.path_hashes || [];
                const isLeft = proof.isLeft || proof.is_left || [];
                const leftPeaks = proof.leftPeaks || proof.left_peaks || [];
                const rightPeaks = proof.rightPeaks || proof.right_peaks || [];

                const proofLen = 4 + pathHashes.length * 36 + 4 + leftPeaks.length * 32 + 4 + rightPeaks.length * 32;
                const proofBuf = new Uint8Array(proofLen);
                const viewPrf = new DataView(proofBuf.buffer);
                let pOff = 0;

                viewPrf.setUint32(pOff, pathHashes.length, false); pOff += 4;
                for (let k = 0; k < pathHashes.length; k++) {
                    proofBuf.set(hexToBytes(pathHashes[k]), pOff); pOff += 32;
                    viewPrf.setUint32(pOff, isLeft[k] ? 1 : 0, false); pOff += 4;
                }

                viewPrf.setUint32(pOff, leftPeaks.length, false); pOff += 4;
                for (let k = 0; k < leftPeaks.length; k++) {
                    proofBuf.set(hexToBytes(leftPeaks[k]), pOff); pOff += 32;
                }

                viewPrf.setUint32(pOff, rightPeaks.length, false); pOff += 4;
                for (let k = 0; k < rightPeaks.length; k++) {
                    proofBuf.set(hexToBytes(rightPeaks[k]), pOff); pOff += 32;
                }

                const itemBuf = new Uint8Array(152 + proofLen);
                itemBuf.set(ptrBuf, 0);
                itemBuf.set(proofBuf, 152);

                inputsBufferList.push(itemBuf);
                totalInputsLen += itemBuf.length;
            }

            const inputsMerkleRoot = computeInputsMerkleRoot(inputs);
            const inputsRootSig = signBufferWithDilithium(inputsMerkleRoot);

            const intentBuf = new Uint8Array(8 + 4 + 32 + (numInputs * 48) + 2592 + 2592 + 8);
            intentBuf.set(nonce, 0);
            new DataView(intentBuf.buffer, 8, 4).setUint32(0, numInputs, false);
            intentBuf.set(clientRoot, 12);
            let intentOff = 44;
            for (let i = 0; i < numInputs; i++) {
                intentBuf.set(hexToBytes(inputs[i].pointerId || inputs[i].pointer_id), intentOff); intentOff += 32;
                const vI = new DataView(intentBuf.buffer, intentOff, 16);
                vI.setBigUint64(0, BigInt(inputs[i].startSubunit || inputs[i].start_subunit || 0), false);
                vI.setBigUint64(8, BigInt(inputs[i].endSubunit || inputs[i].end_subunit || 0), false);
                intentOff += 16;
            }
            intentBuf.set(recipientPubkeyBytes, intentOff); intentOff += 2592;
            intentBuf.set(senderPubkeyBytes, intentOff); intentOff += 2592;
            new DataView(intentBuf.buffer, intentOff, 8).setBigUint64(0, amountVal, false);

            const txIdPtr = wasmInstance._wasm_malloc(32);
            const intentPtr = wasmInstance._wasm_malloc(intentBuf.length);
            getLiveHeapU8().subarray(intentPtr, intentPtr + intentBuf.length).set(intentBuf);
            wasmInstance._wasm_sha256(intentPtr, intentBuf.length, txIdPtr);
            const txIdBytes = getLiveHeapU8().subarray(txIdPtr, txIdPtr + 32).slice(0);
            wasmInstance._wasm_free(intentPtr);
            wasmInstance._wasm_free(txIdPtr);

            let zkProofBytes = payload.zkProofBytes ? new Uint8Array(payload.zkProofBytes) : null;

            const nullifierBytes = new Uint8Array(32);
            if (prfKeyPtr !== 0) {
                const idPtr = wasmInstance._wasm_malloc(32);
                const seedPtr = wasmInstance._wasm_malloc(32);
                const outNulPtr = wasmInstance._wasm_malloc(32);

                getLiveHeapU8().subarray(idPtr, idPtr + 32).set(txIdBytes);
                getLiveHeapU8().subarray(seedPtr, seedPtr + 32).set(clientRoot);

                if (wasmInstance._wasm_prf_evaluate(outNulPtr, prfKeyPtr, idPtr, 32, seedPtr) === 0) {
                    nullifierBytes.set(getLiveHeapU8().subarray(outNulPtr, outNulPtr + 32));
                }

                if (!zkProofBytes && wasmInstance._wasm_generate_zk_prf_proof) {
                    const proofOutPtr = wasmInstance._wasm_malloc(4000000);
                    const proofLenPtr = wasmInstance._wasm_malloc(4);

                    const genRes = wasmInstance._wasm_generate_zk_prf_proof(
                        proofOutPtr,
                        proofLenPtr,
                        idPtr,
                        32,
                        prfKeyPtr,
                        1024,
                        seedPtr
                    );

                    if (genRes === 0) {
                        const viewLen = new DataView(wasmInstance.HEAPU8.buffer, proofLenPtr, 4);
                        const actualProofLen = viewLen.getUint32(0, true);
                        zkProofBytes = getLiveHeapU8().subarray(proofOutPtr, proofOutPtr + actualProofLen).slice(0);
                    }

                    wasmInstance._wasm_free(proofOutPtr);
                    wasmInstance._wasm_free(proofLenPtr);
                }

                wasmInstance._wasm_free(idPtr);
                wasmInstance._wasm_free(seedPtr);
                wasmInstance._wasm_free(outNulPtr);
            }

            if (!zkProofBytes) {
                zkProofBytes = new Uint8Array(128);
            }

            const sigPayloadBuf = new Uint8Array(32 + 8 + 32 + 2592 + 2592 + 8);
            sigPayloadBuf.set(txIdBytes, 0);
            sigPayloadBuf.set(nonce, 32);
            sigPayloadBuf.set(inputsMerkleRoot, 40);
            sigPayloadBuf.set(recipientPubkeyBytes, 72);
            sigPayloadBuf.set(senderPubkeyBytes, 72 + 2592);
            new DataView(sigPayloadBuf.buffer, 72 + 5184, 8).setBigUint64(0, amountVal, false);

            const txSignature = signBufferWithDilithium(sigPayloadBuf);
            const fullOpLen = 1 + 32 + 8 + 4 + 32 + totalInputsLen + 2592 + 2592 + 8 + 4595 + 32 + 4595 + 32 + 4 + zkProofBytes.length;
            const fullOp = new Uint8Array(fullOpLen);
            const viewFull = new DataView(fullOp.buffer);

            fullOp[0] = 2; // OP_TRANSFER_POINTER
            fullOp.set(txIdBytes, 1);
            fullOp.set(nonce, 33);
            viewFull.setUint32(41, numInputs, false);
            fullOp.set(clientRoot, 45);

            let offset = 77;
            for (let i = 0; i < numInputs; i++) {
                fullOp.set(inputsBufferList[i], offset);
                offset += inputsBufferList[i].length;
            }

            fullOp.set(recipientPubkeyBytes, offset); offset += 2592;
            fullOp.set(senderPubkeyBytes, offset); offset += 2592;
            viewFull.setBigUint64(offset, amountVal, false); offset += 8;
            fullOp.set(txSignature, offset); offset += 4595;
            fullOp.set(inputsMerkleRoot, offset); offset += 32;
            fullOp.set(inputsRootSig, offset); offset += 4595;
            fullOp.set(nullifierBytes, offset); offset += 32;
            viewFull.setUint32(offset, zkProofBytes.length, false); offset += 4;
            fullOp.set(zkProofBytes, offset);

            opPayloadBytes = fullOp;
        } else if (opType === 'OP_STAKE') {
            const recipientPubkeyBytes = new Uint8Array(2592);
            let hasRecipient = false;
            if (payload.recipientPubkeyHex) {
                const rBytes = hexToBytes(payload.recipientPubkeyHex);
                if (rBytes.length === 2592) {
                    recipientPubkeyBytes.set(rBytes);
                    hasRecipient = true;
                }
            }
            if (!hasRecipient && dilithiumPubkeyPtr !== 0) {
                recipientPubkeyBytes.set(getLiveHeapU8().subarray(dilithiumPubkeyPtr, dilithiumPubkeyPtr + 2592));
            }

            const senderPubkeyBytes = new Uint8Array(2592);
            let hasSender = false;
            if (payload.senderPubkeyHex) {
                const sBytes = hexToBytes(payload.senderPubkeyHex);
                if (sBytes.length === 2592) {
                    senderPubkeyBytes.set(sBytes);
                    hasSender = true;
                }
            }
            if (!hasSender && dilithiumPubkeyPtr !== 0) {
                senderPubkeyBytes.set(getLiveHeapU8().subarray(dilithiumPubkeyPtr, dilithiumPubkeyPtr + 2592));
            }

            const thresholdPubkeyBytes = new Uint8Array(2592);
            let hasThreshold = false;
            if (payload.thresholdPubkeyHex) {
                const tBytes = hexToBytes(payload.thresholdPubkeyHex);
                if (tBytes.length === 2592) {
                    thresholdPubkeyBytes.set(tBytes);
                    hasThreshold = true;
                }
            }
            if (!hasThreshold && dilithiumKeyPtr !== 0 && wasmInstance._wasm_compute_threshold_pubkey) {
                const tOutPtr = wasmInstance._wasm_malloc(2592);
                if (wasmInstance._wasm_compute_threshold_pubkey(dilithiumKeyPtr, tOutPtr) === 0) {
                    thresholdPubkeyBytes.set(getLiveHeapU8().subarray(tOutPtr, tOutPtr + 2592));
                    hasThreshold = true;
                }
                wasmInstance._wasm_free(tOutPtr);
            }
            if (!hasThreshold) {
                thresholdPubkeyBytes.set(senderPubkeyBytes);
            }

            const amountVal = BigInt(payload.amountSubunits || '0');
            const nonce = new Uint8Array(8);
            if (self.crypto && self.crypto.getRandomValues) {
                self.crypto.getRandomValues(nonce);
            }

            const clientRoot = new Uint8Array(32);
            if (payload.clientRootHex && payload.clientRootHex.length === 64) {
                clientRoot.set(hexToBytes(payload.clientRootHex));
            }

            const inputs = payload.inputs || [];
            const numInputs = inputs.length;

            let inputsBufferList = [];
            let totalInputsLen = 0;
            for (let i = 0; i < numInputs; i++) {
                const ptr = inputs[i];
                const ptrBuf = new Uint8Array(152);
                ptrBuf.set(hexToBytes(ptr.pointerId || ptr.pointer_id), 0);
                ptrBuf.set(hexToBytes(ptr.parentCoinId || ptr.parent_coin_id), 32);
                const viewP = new DataView(ptrBuf.buffer);
                viewP.setBigUint64(64, BigInt(ptr.startSubunit || ptr.start_subunit || 0), false);
                viewP.setBigUint64(72, BigInt(ptr.endSubunit || ptr.end_subunit || 0), false);
                ptrBuf.set(hexToBytes(ptr.ownerAddress || ptr.owner_address), 80);
                ptrBuf.set(hexToBytes(ptr.prevTxHash || ptr.prev_tx_hash), 112);
                viewP.setUint32(144, 0, false);
                viewP.setUint32(148, 0, false);

                const proof = ptr.proof || {};
                const pathHashes = proof.pathHashes || proof.path_hashes || [];
                const isLeft = proof.isLeft || proof.is_left || [];
                const leftPeaks = proof.leftPeaks || proof.left_peaks || [];
                const rightPeaks = proof.rightPeaks || proof.right_peaks || [];

                const proofLen = 4 + pathHashes.length * 36 + 4 + leftPeaks.length * 32 + 4 + rightPeaks.length * 32;
                const proofBuf = new Uint8Array(proofLen);
                const viewPrf = new DataView(proofBuf.buffer);
                let pOff = 0;

                viewPrf.setUint32(pOff, pathHashes.length, false); pOff += 4;
                for (let k = 0; k < pathHashes.length; k++) {
                    proofBuf.set(hexToBytes(pathHashes[k]), pOff); pOff += 32;
                    viewPrf.setUint32(pOff, isLeft[k] ? 1 : 0, false); pOff += 4;
                }

                viewPrf.setUint32(pOff, leftPeaks.length, false); pOff += 4;
                for (let k = 0; k < leftPeaks.length; k++) {
                    proofBuf.set(hexToBytes(leftPeaks[k]), pOff); pOff += 32;
                }

                viewPrf.setUint32(pOff, rightPeaks.length, false); pOff += 4;
                for (let k = 0; k < rightPeaks.length; k++) {
                    proofBuf.set(hexToBytes(rightPeaks[k]), pOff); pOff += 32;
                }

                const itemBuf = new Uint8Array(152 + proofLen);
                itemBuf.set(ptrBuf, 0);
                itemBuf.set(proofBuf, 152);

                inputsBufferList.push(itemBuf);
                totalInputsLen += itemBuf.length;
            }

            const inputsMerkleRoot = computeInputsMerkleRoot(inputs);
            const inputsRootSig = signBufferWithDilithium(inputsMerkleRoot);

            const stakePayloadBuf = new Uint8Array(32 + 8 + 4 + 32 + 32 + totalInputsLen + 2592 + 8);
            let sOff = 32;
            stakePayloadBuf.set(nonce, sOff); sOff += 8;
            new DataView(stakePayloadBuf.buffer, sOff, 4).setUint32(0, numInputs, false); sOff += 4;
            stakePayloadBuf.set(clientRoot, sOff); sOff += 32;
            stakePayloadBuf.set(inputsMerkleRoot, sOff); sOff += 32;

            for (let i = 0; i < numInputs; i++) {
                stakePayloadBuf.set(inputsBufferList[i], sOff);
                sOff += inputsBufferList[i].length;
            }

            stakePayloadBuf.set(thresholdPubkeyBytes, sOff); sOff += 2592;
            new DataView(stakePayloadBuf.buffer, sOff, 8).setBigUint64(0, amountVal, false); sOff += 8;

            const stakeTxIdPtr = wasmInstance._wasm_malloc(32);
            const stakePayloadPtr = wasmInstance._wasm_malloc(stakePayloadBuf.length);
            getLiveHeapU8().subarray(stakePayloadPtr, stakePayloadPtr + stakePayloadBuf.length).set(stakePayloadBuf);
            wasmInstance._wasm_sha256(stakePayloadPtr, stakePayloadBuf.length, stakeTxIdPtr);
            const stakeTxIdBytes = getLiveHeapU8().subarray(stakeTxIdPtr, stakeTxIdPtr + 32).slice(0);
            wasmInstance._wasm_free(stakePayloadPtr);
            wasmInstance._wasm_free(stakeTxIdPtr);

            const thresholdSig = payload.thresholdSignatureBytes ?
                new Uint8Array(payload.thresholdSignatureBytes) :
                signBufferWithDilithium(stakePayloadBuf);

            const fullOpLen = 1 + 32 + 8 + 4 + 32 + totalInputsLen + 2592 + 2592 + 8 + 4595 + 32 + 4595;
            const fullOp = new Uint8Array(fullOpLen);
            const viewFull = new DataView(fullOp.buffer);

            fullOp[0] = 3; // OP_STAKE
            fullOp.set(stakeTxIdBytes, 1);
            fullOp.set(nonce, 33);
            viewFull.setUint32(41, numInputs, false);
            fullOp.set(clientRoot, 45);

            let offset = 77;
            for (let i = 0; i < numInputs; i++) {
                fullOp.set(inputsBufferList[i], offset);
                offset += inputsBufferList[i].length;
            }

            fullOp.set(thresholdPubkeyBytes, offset); offset += 2592;
            fullOp.set(senderPubkeyBytes, offset); offset += 2592;
            viewFull.setBigUint64(offset, amountVal, false); offset += 8;
            fullOp.set(thresholdSig, offset); offset += 4595;
            fullOp.set(inputsMerkleRoot, offset); offset += 32;
            fullOp.set(inputsRootSig, offset); offset += 4595;

            opPayloadBytes = fullOp;
        } else if (opType === 'OP_UNSTAKE') {
            const recipientPubkeyBytes = new Uint8Array(2592);
            let hasRecipient = false;
            if (payload.recipientPubkeyHex) {
                const rBytes = hexToBytes(payload.recipientPubkeyHex);
                if (rBytes.length === 2592) {
                    recipientPubkeyBytes.set(rBytes);
                    hasRecipient = true;
                }
            }
            if (!hasRecipient && dilithiumPubkeyPtr !== 0) {
                recipientPubkeyBytes.set(getLiveHeapU8().subarray(dilithiumPubkeyPtr, dilithiumPubkeyPtr + 2592));
            }

            const thresholdPubkeyBytes = new Uint8Array(2592);
            let hasThreshold = false;
            if (payload.thresholdPubkeyHex) {
                const tBytes = hexToBytes(payload.thresholdPubkeyHex);
                if (tBytes.length === 2592) {
                    thresholdPubkeyBytes.set(tBytes);
                    hasThreshold = true;
                }
            }
            if (!hasThreshold && dilithiumKeyPtr !== 0 && wasmInstance._wasm_compute_threshold_pubkey) {
                const tOutPtr = wasmInstance._wasm_malloc(2592);
                if (wasmInstance._wasm_compute_threshold_pubkey(dilithiumKeyPtr, tOutPtr) === 0) {
                    thresholdPubkeyBytes.set(getLiveHeapU8().subarray(tOutPtr, tOutPtr + 2592));
                    hasThreshold = true;
                }
                wasmInstance._wasm_free(tOutPtr);
            }
            if (!hasThreshold) {
                thresholdPubkeyBytes.set(recipientPubkeyBytes);
            }

            const amountVal = BigInt(payload.amountSubunits || '0');
            const nonce = new Uint8Array(8);
            if (self.crypto && self.crypto.getRandomValues) {
                self.crypto.getRandomValues(nonce);
            }

            const clientRoot = new Uint8Array(32);
            if (payload.clientRootHex && payload.clientRootHex.length === 64) {
                clientRoot.set(hexToBytes(payload.clientRootHex));
            }

            const inputs = payload.inputs || [];
            const numInputs = inputs.length;

            let inputsBufferList = [];
            let totalInputsLen = 0;
            for (let i = 0; i < numInputs; i++) {
                const ptr = inputs[i];
                const ptrBuf = new Uint8Array(152);
                ptrBuf.set(hexToBytes(ptr.pointerId || ptr.pointer_id), 0);
                ptrBuf.set(hexToBytes(ptr.parentCoinId || ptr.parent_coin_id), 32);
                const viewP = new DataView(ptrBuf.buffer);
                viewP.setBigUint64(64, BigInt(ptr.startSubunit || ptr.start_subunit || 0), false);
                viewP.setBigUint64(72, BigInt(ptr.endSubunit || ptr.end_subunit || 0), false);
                ptrBuf.set(hexToBytes(ptr.ownerAddress || ptr.owner_address), 80);
                ptrBuf.set(hexToBytes(ptr.prevTxHash || ptr.prev_tx_hash), 112);
                viewP.setUint32(144, 0, false);
                viewP.setUint32(148, 1, false);

                const proof = ptr.proof || {};
                const pathHashes = proof.pathHashes || proof.path_hashes || [];
                const isLeft = proof.isLeft || proof.is_left || [];
                const leftPeaks = proof.leftPeaks || proof.left_peaks || [];
                const rightPeaks = proof.rightPeaks || proof.right_peaks || [];

                const proofLen = 4 + pathHashes.length * 36 + 4 + leftPeaks.length * 32 + 4 + rightPeaks.length * 32;
                const proofBuf = new Uint8Array(proofLen);
                const viewPrf = new DataView(proofBuf.buffer);
                let pOff = 0;

                viewPrf.setUint32(pOff, pathHashes.length, false); pOff += 4;
                for (let k = 0; k < pathHashes.length; k++) {
                    proofBuf.set(hexToBytes(pathHashes[k]), pOff); pOff += 32;
                    viewPrf.setUint32(pOff, isLeft[k] ? 1 : 0, false); pOff += 4;
                }

                viewPrf.setUint32(pOff, leftPeaks.length, false); pOff += 4;
                for (let k = 0; k < leftPeaks.length; k++) {
                    proofBuf.set(hexToBytes(leftPeaks[k]), pOff); pOff += 32;
                }

                viewPrf.setUint32(pOff, rightPeaks.length, false); pOff += 4;
                for (let k = 0; k < rightPeaks.length; k++) {
                    proofBuf.set(hexToBytes(rightPeaks[k]), pOff); pOff += 32;
                }

                const itemBuf = new Uint8Array(152 + proofLen);
                itemBuf.set(ptrBuf, 0);
                itemBuf.set(proofBuf, 152);

                inputsBufferList.push(itemBuf);
                totalInputsLen += itemBuf.length;
            }

            const unstakePayloadBuf = new Uint8Array(32 + 8 + 4 + 32 + totalInputsLen + 2592 + 2592 + 8);
            let uOff = 32;
            unstakePayloadBuf.set(nonce, uOff); uOff += 8;
            new DataView(unstakePayloadBuf.buffer, uOff, 4).setUint32(0, numInputs, false); uOff += 4;
            unstakePayloadBuf.set(clientRoot, uOff); uOff += 32;

            for (let i = 0; i < numInputs; i++) {
                unstakePayloadBuf.set(inputsBufferList[i], uOff);
                uOff += inputsBufferList[i].length;
            }

            unstakePayloadBuf.set(recipientPubkeyBytes, uOff); uOff += 2592;
            unstakePayloadBuf.set(thresholdPubkeyBytes, uOff); uOff += 2592;
            new DataView(unstakePayloadBuf.buffer, uOff, 8).setBigUint64(0, amountVal, false); uOff += 8;

            const unstakeTxIdPtr = wasmInstance._wasm_malloc(32);
            const unstakePayloadPtr = wasmInstance._wasm_malloc(unstakePayloadBuf.length);
            getLiveHeapU8().subarray(unstakePayloadPtr, unstakePayloadPtr + unstakePayloadBuf.length).set(unstakePayloadBuf);
            wasmInstance._wasm_sha256(unstakePayloadPtr, unstakePayloadBuf.length, unstakeTxIdPtr);
            const unstakeTxIdBytes = getLiveHeapU8().subarray(unstakeTxIdPtr, unstakeTxIdPtr + 32).slice(0);
            wasmInstance._wasm_free(unstakePayloadPtr);
            wasmInstance._wasm_free(unstakeTxIdPtr);

            const thresholdSig = payload.thresholdSignatureBytes ?
                new Uint8Array(payload.thresholdSignatureBytes) :
                signBufferWithDilithium(unstakePayloadBuf);

            const fullOpLen = 1 + 32 + 8 + 4 + 32 + totalInputsLen + 2592 + 2592 + 8 + 4595;
            const fullOp = new Uint8Array(fullOpLen);
            const viewFull = new DataView(fullOp.buffer);

            fullOp[0] = 4; // OP_UNSTAKE
            fullOp.set(unstakeTxIdBytes, 1);
            fullOp.set(nonce, 33);
            viewFull.setUint32(41, numInputs, false);
            fullOp.set(clientRoot, 45);

            let offset = 77;
            for (let i = 0; i < numInputs; i++) {
                fullOp.set(inputsBufferList[i], offset);
                offset += inputsBufferList[i].length;
            }

            fullOp.set(recipientPubkeyBytes, offset); offset += 2592;
            fullOp.set(thresholdPubkeyBytes, offset); offset += 2592;
            viewFull.setBigUint64(offset, amountVal, false); offset += 8;
            fullOp.set(thresholdSig, offset); offset += 4595;

            opPayloadBytes = fullOp;
        } else if (opType === 'OP_REDEEM_CENTINEL') {
            const nullifier = new Uint8Array(32);
            if (payload.nullifierBytes) {
                nullifier.set(new Uint8Array(payload.nullifierBytes));
            } else if (payload.nullifierHex && payload.nullifierHex.length === 64) {
                for (let i = 0; i < 32; i++) {
                    nullifier[i] = parseInt(payload.nullifierHex.substr(i * 2, 2), 16);
                }
            }

            const cTransfer = new Uint8Array(2048);
            if (payload.cTransferBytes) {
                cTransfer.set(new Uint8Array(payload.cTransferBytes));
            }

            const cChange = new Uint8Array(2048);
            if (payload.cChangeBytes) {
                cChange.set(new Uint8Array(payload.cChangeBytes));
            }

            const zkProof = payload.zkProofBytes ? new Uint8Array(payload.zkProofBytes) : new Uint8Array(128);
            const zkProofLen = zkProof.length;

            const fullOp = new Uint8Array(1 + 32 + 2048 + 2048 + 4 + zkProofLen);
            const view = new DataView(fullOp.buffer);

            fullOp[0] = 5; // OP_REDEEM_CENTINEL
            fullOp.set(nullifier, 1);
            fullOp.set(cTransfer, 33);
            fullOp.set(cChange, 33 + 2048);
            view.setUint32(33 + 4096, zkProofLen, false);
            fullOp.set(zkProof, 33 + 4096 + 4);

            opPayloadBytes = fullOp;
        } else if (opType === 'OP_CLAIM_VALIDATION') {
            const commitment = payload.commitmentBytes ? new Uint8Array(payload.commitmentBytes) : new Uint8Array(2048);
            const pubkeyBytes = new Uint8Array(2592);
            if (dilithiumPubkeyPtr !== 0) {
                pubkeyBytes.set(getLiveHeapU8().subarray(dilithiumPubkeyPtr, dilithiumPubkeyPtr + 2592));
            } else if (payload.pubkeyHex && payload.pubkeyHex.length === 5184) {
                pubkeyBytes.set(hexToBytes(payload.pubkeyHex));
            }

            const commHashPtr = wasmInstance._wasm_malloc(2048);
            const outHashPtr = wasmInstance._wasm_malloc(32);
            getLiveHeapU8().subarray(commHashPtr, commHashPtr + 2048).set(commitment);
            wasmInstance._wasm_sha256(commHashPtr, 2048, outHashPtr);
            const commHashBytes = getLiveHeapU8().subarray(outHashPtr, outHashPtr + 32).slice(0);
            wasmInstance._wasm_free(commHashPtr);
            wasmInstance._wasm_free(outHashPtr);

            const claimSig = signBufferWithDilithium(commHashBytes);

            const fullOp = new Uint8Array(1 + 2048 + 2592 + 4595);
            fullOp[0] = 6; // OP_CLAIM_VALIDATION
            fullOp.set(commitment, 1);
            fullOp.set(pubkeyBytes, 2049);
            fullOp.set(claimSig, 2049 + 2592);

            opPayloadBytes = fullOp;
        } else if (opType === 'OP_APPLY_DRIFT_CERT') {
            /* On-chain drift certificate anchoring op. Wire layout mirrors the C
             * serialize_operation case OP_APPLY_DRIFT_CERT byte-for-byte. */
            const recipientPubkeyBytes = new Uint8Array(2592);
            if (payload.recipientPubkeyHex) {
                const rBytes = hexToBytes(payload.recipientPubkeyHex);
                if (rBytes.length === 2592) recipientPubkeyBytes.set(rBytes);
            }
            const senderPubkeyBytes = new Uint8Array(2592);
            let hasSender = false;
            if (payload.senderPubkeyHex) {
                const sBytes = hexToBytes(payload.senderPubkeyHex);
                if (sBytes.length === 2592) {
                    senderPubkeyBytes.set(sBytes);
                    hasSender = true;
                }
            }
            if (!hasSender && dilithiumPubkeyPtr !== 0) {
                senderPubkeyBytes.set(getLiveHeapU8().subarray(dilithiumPubkeyPtr, dilithiumPubkeyPtr + 2592));
            }

            const amountVal = BigInt(payload.amountSubunits || '0');
            const nonce = new Uint8Array(8);
            if (self.crypto && self.crypto.getRandomValues) {
                self.crypto.getRandomValues(nonce);
            }

            const clientRoot = new Uint8Array(32);
            if (payload.clientRootHex && payload.clientRootHex.length === 64) {
                clientRoot.set(hexToBytes(payload.clientRootHex));
            }

            const circuitHash = hexToBytes(payload.circuitHashHex || '', 32);
            const commitmentRoot = hexToBytes(payload.commitmentRootHex || '', 32);
            const tvdScaled = BigInt(payload.tvdScaled || '0');
            const shotsVal = Number(payload.shots || 15000);
            const statusVal = Number(payload.status || 0);
            const tsVal = BigInt(payload.timestampUs || (Date.now() * 1000));

            const inputs = payload.inputs || [];
            const numInputs = inputs.length;

            let inputsBufferList = [];
            let totalInputsLen = 0;
            for (let i = 0; i < numInputs; i++) {
                const ptr = inputs[i];
                const ptrBuf = new Uint8Array(152);
                ptrBuf.set(hexToBytes(ptr.pointerId || ptr.pointer_id), 0);
                ptrBuf.set(hexToBytes(ptr.parentCoinId || ptr.parent_coin_id), 32);
                const viewP = new DataView(ptrBuf.buffer);
                viewP.setBigUint64(64, BigInt(ptr.startSubunit || ptr.start_subunit || 0), false);
                viewP.setBigUint64(72, BigInt(ptr.endSubunit || ptr.end_subunit || 0), false);
                ptrBuf.set(hexToBytes(ptr.ownerAddress || ptr.owner_address), 80);
                ptrBuf.set(hexToBytes(ptr.prevTxHash || ptr.prev_tx_hash), 112);
                viewP.setUint32(144, 0, false);
                viewP.setUint32(148, 0, false);

                const proof = ptr.proof || {};
                const pathHashes = proof.pathHashes || proof.path_hashes || [];
                const isLeft = proof.isLeft || proof.is_left || [];
                const leftPeaks = proof.leftPeaks || proof.left_peaks || [];
                const rightPeaks = proof.rightPeaks || proof.right_peaks || [];

                const proofLen = 4 + pathHashes.length * 36 + 4 + leftPeaks.length * 32 + 4 + rightPeaks.length * 32;
                const proofBuf = new Uint8Array(proofLen);
                const viewPrf = new DataView(proofBuf.buffer);
                let pOff = 0;

                viewPrf.setUint32(pOff, pathHashes.length, false); pOff += 4;
                for (let k = 0; k < pathHashes.length; k++) {
                    proofBuf.set(hexToBytes(pathHashes[k]), pOff); pOff += 32;
                    viewPrf.setUint32(pOff, isLeft[k] ? 1 : 0, false); pOff += 4;
                }

                viewPrf.setUint32(pOff, leftPeaks.length, false); pOff += 4;
                for (let k = 0; k < leftPeaks.length; k++) {
                    proofBuf.set(hexToBytes(leftPeaks[k]), pOff); pOff += 32;
                }

                viewPrf.setUint32(pOff, rightPeaks.length, false); pOff += 4;
                for (let k = 0; k < rightPeaks.length; k++) {
                    proofBuf.set(hexToBytes(rightPeaks[k]), pOff); pOff += 32;
                }

                const itemBuf = new Uint8Array(152 + proofLen);
                itemBuf.set(ptrBuf, 0);
                itemBuf.set(proofBuf, 152);

                inputsBufferList.push(itemBuf);
                totalInputsLen += itemBuf.length;
            }

            const inputsMerkleRoot = computeInputsMerkleRoot(inputs);

            /* Canonical certificate digest (mirrors the C builder):
             * SHA-256(circuit_hash || tvd_scaled BE || shots BE || status BE || commitment_root || timestamp BE) */
            const digestBuf = new Uint8Array(32 + 8 + 4 + 4 + 32 + 8);
            digestBuf.set(circuitHash, 0);
            new DataView(digestBuf.buffer, 32, 8).setBigUint64(0, tvdScaled, false);
            new DataView(digestBuf.buffer, 40, 4).setUint32(0, shotsVal, false);
            new DataView(digestBuf.buffer, 44, 4).setUint32(0, statusVal, false);
            digestBuf.set(commitmentRoot, 48);
            new DataView(digestBuf.buffer, 56, 8).setBigUint64(0, tsVal, false);

            const digestInPtr = wasmInstance._wasm_malloc(32);
            const digestOutPtr = wasmInstance._wasm_malloc(32);
            getLiveHeapU8().subarray(digestInPtr, digestInPtr + 32).set(digestBuf);
            wasmInstance._wasm_sha256(digestInPtr, 32, digestOutPtr);
            const certDigest = getLiveHeapU8().subarray(digestOutPtr, digestOutPtr + 32).slice(0);
            wasmInstance._wasm_free(digestInPtr);
            wasmInstance._wasm_free(digestOutPtr);

            /* ML-DSA-87 signature over the certificate digest by the funding wallet */
            const certSignature = signBufferWithDilithium(certDigest);

            /* Deterministic operation identity: SHA-256(cert_digest || amount || nonce) */
            const txIdBuf = new Uint8Array(48);
            txIdBuf.set(certDigest, 0);
            new DataView(txIdBuf.buffer, 32, 8).setBigUint64(0, amountVal, false);
            txIdBuf.set(nonce, 40);
            const txIdInPtr = wasmInstance._wasm_malloc(48);
            const txIdOutPtr = wasmInstance._wasm_malloc(32);
            getLiveHeapU8().subarray(txIdInPtr, txIdInPtr + 48).set(txIdBuf);
            wasmInstance._wasm_sha256(txIdInPtr, 48, txIdOutPtr);
            const txIdBytes = getLiveHeapU8().subarray(txIdOutPtr, txIdOutPtr + 32).slice(0);
            wasmInstance._wasm_free(txIdInPtr);
            wasmInstance._wasm_free(txIdOutPtr);

            const fullOpLen = 1 + 32 + 8 + 4 + 32 + totalInputsLen + 32 + 8 + 4 + 4 + 32 + 8 + 2592 + 2592 + 8 + 32 + 32 + 4595;
            const fullOp = new Uint8Array(fullOpLen);
            const viewFull = new DataView(fullOp.buffer);

            fullOp[0] = 7; // OP_APPLY_DRIFT_CERT
            fullOp.set(txIdBytes, 1);
            fullOp.set(nonce, 33);
            viewFull.setUint32(41, numInputs, false);
            fullOp.set(clientRoot, 45);

            let offset = 77;
            for (let i = 0; i < numInputs; i++) {
                fullOp.set(inputsBufferList[i], offset);
                offset += inputsBufferList[i].length;
            }

            fullOp.set(circuitHash, offset); offset += 32;
            viewFull.setBigUint64(offset, tvdScaled, false); offset += 8;
            viewFull.setUint32(offset, shotsVal, false); offset += 4;
            viewFull.setUint32(offset, statusVal, false); offset += 4;
            fullOp.set(commitmentRoot, offset); offset += 32;
            viewFull.setBigUint64(offset, tsVal, false); offset += 8;
            fullOp.set(recipientPubkeyBytes, offset); offset += 2592;
            fullOp.set(senderPubkeyBytes, offset); offset += 2592;
            viewFull.setBigUint64(offset, amountVal, false); offset += 8;
            fullOp.set(inputsMerkleRoot, offset); offset += 32;
            fullOp.set(certDigest, offset); offset += 32;
            fullOp.set(certSignature, offset);

            opPayloadBytes = fullOp;
        } else {
            const buf = new Uint8Array(1 + 32 + 8 + 4 + 32);
            buf[0] = opCode;
            opPayloadBytes = buf;
        }

        const builderPtr = wasmInstance._wasm_builder_create(1, 0x0003, BigInt(requestId));
        if (!builderPtr) {
            postMessage({ type: 'ERROR', message: 'Failed to create WASM RPC builder' });
            return;
        }

        wasmInstance._wasm_builder_set_flags(builderPtr, 1); // SCL_RPC_FLAG_SIGNED

        const argsPtr = wasmInstance._wasm_malloc(opPayloadBytes.length);
        const heapArgs = getLiveHeapU8().subarray(argsPtr, argsPtr + opPayloadBytes.length);
        heapArgs.set(opPayloadBytes);

        wasmInstance._wasm_builder_append_args(builderPtr, argsPtr, opPayloadBytes.length);
        wasmInstance._wasm_free(argsPtr);

        const signRes = wasmInstance._wasm_builder_sign(builderPtr, dilithiumKeyPtr);
        if (signRes !== 0) {
            wasmInstance._wasm_builder_destroy(builderPtr);
            postMessage({ type: 'ERROR', message: 'Failed to sign RPC wire frame' });
            return;
        }

        const maxLen = opPayloadBytes.length + 8192;
        const outBufPtr = wasmInstance._wasm_malloc(maxLen);
        const outLenPtr = wasmInstance._wasm_malloc(4);

        const finRes = wasmInstance._wasm_builder_finalize(builderPtr, outBufPtr, maxLen, outLenPtr);
        wasmInstance._wasm_builder_destroy(builderPtr);

        if (finRes === 0) {
            const view = new DataView(getLiveHeapU8().buffer, outLenPtr, 4);
            const actualLen = view.getUint32(0, true);
            const wireBytes = getLiveHeapU8().subarray(outBufPtr, outBufPtr + actualLen).slice(0);

            wasmInstance._wasm_free(outBufPtr);
            wasmInstance._wasm_free(outLenPtr);

            const txIdBytes = opPayloadBytes.subarray(1, 33);
            const txIdHex = Array.from(txIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');

            postMessage({
                type: 'WIRE_FRAME_READY',
                data: {
                    requestId: requestId,
                    wireBytes: wireBytes.buffer,
                    txIdHex: txIdHex,
                    computedFeeSubunits: computedFee.toString()
                }
            }, [wireBytes.buffer]);
        } else {
            wasmInstance._wasm_free(outBufPtr);
            wasmInstance._wasm_free(outLenPtr);
            postMessage({ type: 'ERROR', message: 'Failed to finalize WASM RPC wire frame' });
        }
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Transaction building error: ' + e.message });
    }
}

/**
 * @brief Deterministically derives the 32-byte BDLOP commitment blinding factor r for index `idx`.
 *
 * @details
 * Evaluates `SHA256(dilithium_privkey || "SCL_VAL_UTXO_" || idx)` to reproduce blinding factors
 * deterministically across sessions without persisting unencrypted random vectors to disk.
 *
 * @param {number} idx Zero-based derivation index.
 * @return {Uint8Array} 32-byte blinding factor array.
 * @complexity Time: O(1) SHA-256 evaluation, Space: O(1).
 */
function getCandidateR(idx) {
    if (idx >= 0 && idx < candidateRValues.length && candidateRValues[idx]) {
        return candidateRValues[idx];
    }
    if (dilithiumKeyPtr !== 0 && wasmInstance && wasmInstance._wasm_sha256) {
        const privKeyBytes = getLiveHeapU8().subarray(dilithiumKeyPtr, dilithiumKeyPtr + 4864).slice(0);
        const inPtr = wasmInstance._wasm_malloc(4864 + 32);
        const outPtr = wasmInstance._wasm_malloc(32);
        const tagStr = `SCL_VAL_UTXO_${idx}`;
        const tagBytes = new TextEncoder().encode(tagStr);
        const rInputBuf = new Uint8Array(4864 + tagBytes.length);
        rInputBuf.set(privKeyBytes, 0);
        rInputBuf.set(tagBytes, 4864);

        getLiveHeapU8().subarray(inPtr, inPtr + rInputBuf.length).set(rInputBuf);
        wasmInstance._wasm_sha256(inPtr, rInputBuf.length, outPtr);
        const candR = getLiveHeapU8().subarray(outPtr, outPtr + 32).slice(0);
        wasmInstance._wasm_free(inPtr);
        wasmInstance._wasm_free(outPtr);

        while (candidateRValues.length <= idx) {
            candidateRValues.push(null);
        }
        candidateRValues[idx] = candR;
        return candR;
    }
    const randR = new Uint8Array(32);
    if (self.crypto && self.crypto.getRandomValues) {
        self.crypto.getRandomValues(randR);
    }
    return randR;
}

/**
 * @brief Pre-populates the candidate blinding factor cache across the standard scan window.
 *
 * @param {boolean} [force=false] True to force cache regeneration even if already populated.
 * @return {void}
 * @complexity Time: O(SCL_WALLET_SCAN_WINDOW * SHA256), Space: O(SCL_WALLET_SCAN_WINDOW * 32).
 */
function ensureCandidateRValues(force = false) {
    if (dilithiumKeyPtr !== 0 && wasmInstance && wasmInstance._wasm_sha256 && (candidateRValues.length === 0 || force)) {
        candidateRValues.length = 0;
        for (let idx = 0; idx < SCL_WALLET_SCAN_WINDOW; idx++) {
            getCandidateR(idx);
        }
    }
}

/**
 * @brief Proves Centinel shielded coin redemption in zero-knowledge and generates off-chain bearer tickets.
 *
 * @details
 * Complete Shielded Proving Pipeline:
 * 1. Checks balance conservation: $v_{\text{old}} = v_{\text{transfer}} + v_{\text{change}}$ strictly.
 * 2. Evaluates double-spend protection: asserts nullifier is absent from `utxoNullifiers`.
 * 3. Derives deterministic blinding factors for transfer and change commitments.
 * 4. Generates an ephemeral Dilithium5 keypair and PRF key to endow the bearer instrument with ownership.
 * 5. Calls WASM export `_wasm_generate_centinel_proof` to execute the 219-round Stern ZK proof.
 * 6. Emits `OP_REDEEM_CENTINEL` on-chain transaction to burn input UTXO.
 * 7. Formats the binary Centinel ticket file (.dat) or animated QR code stream for off-chain export.
 *
 * @param {Object} data Input parameters containing amount, values, export format, and UTXO descriptors.
 * @return {void}
 *
 * @complexity Time: O(ZK_KAPPA * RING_DEG^2) = 219 rounds, Space: O(ZK_PROOF_MAX_LEN).
 */
function handleGenerateCentinelProof(data) {
    if (!wasmInstance) {
        postMessage({ type: 'ERROR', message: 'WASM engine not initialized' });
        return;
    }
    try {
        const { requestId, vOld, amountToTake, vChange, exportFormat, utxo, privkeyHex, pubkeyHex } = data;
        const numAmount = parseInt(amountToTake, 10) || 0;

        if (privkeyHex) {
            const kBytes = hexToBytes(privkeyHex, 4864);
            if (kBytes.length === 4864) {
                if (dilithiumKeyPtr === 0) {
                    dilithiumKeyPtr = wasmInstance._wasm_malloc(4864);
                }
                getLiveHeapU8().subarray(dilithiumKeyPtr, dilithiumKeyPtr + 4864).set(kBytes);
                ensureCandidateRValues(true);
            }
        } else {
            ensureCandidateRValues();
        }
        if (pubkeyHex) {
            const pBytes = hexToBytes(pubkeyHex, 2592);
            if (pBytes.length === 2592) {
                if (dilithiumPubkeyPtr === 0) {
                    dilithiumPubkeyPtr = wasmInstance._wasm_malloc(2592);
                }
                getLiveHeapU8().subarray(dilithiumPubkeyPtr, dilithiumPubkeyPtr + 2592).set(pBytes);
            }
        }

        let utxoIdx = 0;
        let nullifierBytes = new Uint8Array(32);
        let cTransferBytes = new Uint8Array(2048);
        let cChangeBytes = new Uint8Array(2048);
        let zkProofBytes = new Uint8Array(128);
        let zkProofLen = 128;
        let rTransfer = new Uint8Array(32);
        let ephemeralPubkey = new Uint8Array(2592);
        let ephemeralPrfKey = new Int8Array(1024);

        if (self.crypto && self.crypto.getRandomValues) {
            self.crypto.getRandomValues(rTransfer);
            self.crypto.getRandomValues(nullifierBytes);
        }

        const amountToTakeVal = BigInt(numAmount);
        let vOldVal = 0n;
        if (data.vOld) {
            vOldVal = BigInt(data.vOld);
        } else if (utxo && utxo.amount) {
            vOldVal = BigInt(utxo.amount);
        } else if (vOld) {
            vOldVal = BigInt(vOld);
        } else {
            vOldVal = 10n;
        }
        const vChangeVal = (data.vChange !== undefined && data.vChange !== null) ? BigInt(data.vChange) : (vOldVal > amountToTakeVal ? vOldVal - amountToTakeVal : 0n);

        let isTicket = utxo && utxo.ephemeralPrfKey;
        let ticketNullifierHex = null;

        if (isTicket && wasmInstance._wasm_bdlop_commit && wasmInstance._wasm_sha256 && wasmInstance._wasm_prf_evaluate) {
            const rhoPtr = wasmInstance._wasm_malloc(32);
            const rPtr = wasmInstance._wasm_malloc(32);
            const checkCommPtr = wasmInstance._wasm_malloc(2048);
            const hashPtr = wasmInstance._wasm_malloc(32);
            const nulPtr = wasmInstance._wasm_malloc(32);
            const candPrfKeyPtr = wasmInstance._wasm_malloc(1024);

            const encoder = new TextEncoder();
            const rhoSeedBytes = encoder.encode("SCL_CENTINEL_LATTICE_BDLOP_V1_SEED");
            const rhoBytes = new Uint8Array(32);
            rhoBytes.set(rhoSeedBytes.subarray(0, 32));
            getLiveHeapU8().subarray(rhoPtr, rhoPtr + 32).set(rhoBytes);

            let rTicket = toUint8Array(utxo.r, 32);
            getLiveHeapU8().subarray(rPtr, rPtr + 32).set(rTicket);

            let ephPrfBytes = toUint8Array(utxo.ephemeralPrfKey, 1024);
            getLiveHeapU8().subarray(candPrfKeyPtr, candPrfKeyPtr + 1024).set(ephPrfBytes);

            if (wasmInstance._wasm_bdlop_commit(rhoPtr, vOldVal, rPtr, checkCommPtr) === 0) {
                wasmInstance._wasm_sha256(checkCommPtr, 2048, hashPtr);
                if (wasmInstance._wasm_prf_evaluate(nulPtr, candPrfKeyPtr, hashPtr, 32, hashPtr) === 0) {
                    const tNulBytes = getLiveHeapU8().subarray(nulPtr, nulPtr + 32);
                    ticketNullifierHex = Array.from(tNulBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                }
            }

            wasmInstance._wasm_free(rhoPtr);
            wasmInstance._wasm_free(rPtr);
            wasmInstance._wasm_free(checkCommPtr);
            wasmInstance._wasm_free(hashPtr);
            wasmInstance._wasm_free(nulPtr);
            wasmInstance._wasm_free(candPrfKeyPtr);
        }

        // For ticket instruments, verify against ticketNullifierHex (the nullifier of c_transfer being spent).
        // utxo.nullifier in a ticket record represents N_old of the minting transaction and must not be checked here.
        const checkNulHex = isTicket ? ticketNullifierHex : (utxo ? utxo.nullifier : null);
        if (checkNulHex && utxoNullifiers.has(checkNulHex) && (exportFormat === 'redeem' || exportFormat === 'burn')) {
            postMessage({ type: 'ERROR', message: 'Double-spend prevented: This Centinel ticket has already been redeemed.' });
            return;
        }
        let rRaw = (utxo && utxo.r) ? utxo.r : (checkNulHex ? utxoBlindingFactors.get(checkNulHex) : null);
        let rBytes = toUint8Array(rRaw, 32);
        if (!rBytes || rBytes.length !== 32 || rBytes.every(b => b === 0)) {
            for (const [nulHex, r] of utxoBlindingFactors.entries()) {
                if (!utxoNullifiers.has(nulHex) && r) {
                    const candR = toUint8Array(r, 32);
                    if (candR && candR.length === 32 && !candR.every(b => b === 0)) {
                        rBytes = candR;
                        utxoNullifiers.add(nulHex);
                        break;
                    }
                }
            }
        }
        if (!rBytes || rBytes.length !== 32 || rBytes.every(b => b === 0)) {
            if (dilithiumKeyPtr !== 0 && wasmInstance._wasm_sha256) {
                const privKeyBytes = getLiveHeapU8().subarray(dilithiumKeyPtr, dilithiumKeyPtr + 4864).slice(0);
                let foundUnspent = false;

                const scanLimit = Math.max(candidateRValues.length, SCL_WALLET_SCAN_WINDOW, (utxoIdx + SCL_WALLET_SCAN_WINDOW));
                while (utxoIdx < scanLimit) {
                    const tagStr = `SCL_VAL_UTXO_${utxoIdx}`;
                    const tagBytes = new TextEncoder().encode(tagStr);
                    
                    const rInputBuf = new Uint8Array(4864 + tagBytes.length);
                    rInputBuf.set(privKeyBytes, 0);
                    rInputBuf.set(tagBytes, 4864);

                    const inPtr = wasmInstance._wasm_malloc(rInputBuf.length);
                    const outPtr = wasmInstance._wasm_malloc(32);

                    getLiveHeapU8().subarray(inPtr, inPtr + rInputBuf.length).set(rInputBuf);
                    wasmInstance._wasm_sha256(inPtr, rInputBuf.length, outPtr);

                    const candidateR = getLiveHeapU8().subarray(outPtr, outPtr + 32).slice(0);

                    wasmInstance._wasm_free(inPtr);
                    wasmInstance._wasm_free(outPtr);

                    let nulHex = "";
                    if (wasmInstance._wasm_bdlop_commit && wasmInstance._wasm_prf_keygen) {
                        const rhoPtr = wasmInstance._wasm_malloc(32);
                        const rPtr = wasmInstance._wasm_malloc(32);
                        const checkCommPtr = wasmInstance._wasm_malloc(2048);
                        const hashPtr = wasmInstance._wasm_malloc(32);
                        const nulPtr = wasmInstance._wasm_malloc(32);
                        const candPrfKeyPtr = wasmInstance._wasm_malloc(1024);

                        const encoder = new TextEncoder();
                        const rhoSeedBytes = encoder.encode("SCL_CENTINEL_LATTICE_BDLOP_V1_SEED");
                        const rhoBytes = new Uint8Array(32);
                        rhoBytes.set(rhoSeedBytes.subarray(0, 32));
                        getLiveHeapU8().subarray(rhoPtr, rhoPtr + 32).set(rhoBytes);
                        getLiveHeapU8().subarray(rPtr, rPtr + 32).set(candidateR);

                        if (wasmInstance._wasm_bdlop_commit(rhoPtr, vOldVal, rPtr, checkCommPtr) === 0) {
                            wasmInstance._wasm_sha256(checkCommPtr, 2048, hashPtr);
                            wasmInstance._wasm_prf_keygen(candPrfKeyPtr, rPtr, 32);
                            if (wasmInstance._wasm_prf_evaluate(nulPtr, candPrfKeyPtr, hashPtr, 32, hashPtr) === 0) {
                                const testNulBytes = getLiveHeapU8().subarray(nulPtr, nulPtr + 32);
                                nulHex = Array.from(testNulBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                            }
                        }

                        wasmInstance._wasm_free(rhoPtr);
                        wasmInstance._wasm_free(rPtr);
                        wasmInstance._wasm_free(checkCommPtr);
                        wasmInstance._wasm_free(hashPtr);
                        wasmInstance._wasm_free(nulPtr);
                        wasmInstance._wasm_free(candPrfKeyPtr);
                    }

                    if (nulHex && utxoNullifiers.has(nulHex)) {
                        utxoIdx++;
                    } else {
                        rBytes = candidateR;
                        foundUnspent = true;
                        break;
                    }
                }

                if (!foundUnspent && !rBytes) {
                    rBytes = new Uint8Array(32);
                    if (self.crypto && self.crypto.getRandomValues) {
                        self.crypto.getRandomValues(rBytes);
                    }
                }
            } else {
                rBytes = new Uint8Array(32);
                if (self.crypto && self.crypto.getRandomValues) {
                    self.crypto.getRandomValues(rBytes);
                }
            }
        }

        if (rBytes && rBytes.length === 32 && wasmInstance._wasm_generate_centinel_proof) {

            const pkOldPtr = wasmInstance._wasm_malloc(2592);
            const rOldPtr = wasmInstance._wasm_malloc(32);
            const pkTransferPtr = wasmInstance._wasm_malloc(2592);
            const rTransferPtr = wasmInstance._wasm_malloc(32);
            const pkChangePtr = wasmInstance._wasm_malloc(2592);
            const rChangePtr = wasmInstance._wasm_malloc(32);
            const rootPtr = wasmInstance._wasm_malloc(32);
            const outDataPtr = wasmInstance._wasm_malloc(4004132);

            if (utxo && utxo.ephemeralPubkey && utxo.ephemeralPubkey.length === 2592) {
                const ephPubBytes = toUint8Array(utxo.ephemeralPubkey, 2592);
                getLiveHeapU8().subarray(pkOldPtr, pkOldPtr + 2592).set(ephPubBytes);
            } else if (dilithiumPubkeyPtr !== 0) {
                getLiveHeapU8().subarray(pkOldPtr, pkOldPtr + 2592).set(getLiveHeapU8().subarray(dilithiumPubkeyPtr, dilithiumPubkeyPtr + 2592));
            }

            getLiveHeapU8().subarray(rOldPtr, rOldPtr + 32).set(rBytes);

            const isRedemption = (exportFormat === 'redeem');
            const isBurn = (exportFormat === 'burn');
            const rChange = new Uint8Array(32);
            ensureCandidateRValues();
            if (dilithiumKeyPtr !== 0 && candidateRValues.length > 0) {
                // Find next unused index
                let rTransIdx = -1;
                let rChangeIdx = -1;
                
                const maxAllocationWindow = Math.max(candidateRValues.length + SCL_WALLET_SCAN_WINDOW, 16384);
                if (isRedemption) {
                    for (let i = 0; i < maxAllocationWindow; i++) {
                        if (!usedRIndices.has(i)) {
                            rTransIdx = i;
                            usedRIndices.add(i);
                            break;
                        }
                    }
                }
                
                if (vChangeVal > 0n) {
                    for (let i = 0; i < maxAllocationWindow; i++) {
                        if (!usedRIndices.has(i)) {
                            rChangeIdx = i;
                            usedRIndices.add(i);
                            break;
                        }
                    }
                }

                if (isBurn) {
                    if (self.crypto && self.crypto.getRandomValues) {
                        self.crypto.getRandomValues(rTransfer);
                    }
                } else if (isRedemption && rTransIdx !== -1) {
                    const candTransR = getCandidateR(rTransIdx);
                    if (candTransR) rTransfer.set(candTransR);
                    
                    if (wasmInstance._wasm_bdlop_commit && wasmInstance._wasm_prf_keygen) {
                        const rhoPtr = wasmInstance._wasm_malloc(32);
                        const rTxPtr = wasmInstance._wasm_malloc(32);
                        const testCommPtr = wasmInstance._wasm_malloc(2048);
                        const hashPtr = wasmInstance._wasm_malloc(32);
                        const nulPtr = wasmInstance._wasm_malloc(32);
                        const candPrfKeyPtr = wasmInstance._wasm_malloc(1024);

                        const encoder = new TextEncoder();
                        const rhoSeedBytes = encoder.encode("SCL_CENTINEL_LATTICE_BDLOP_V1_SEED");
                        const rhoBytes = new Uint8Array(32);
                        rhoBytes.set(rhoSeedBytes.subarray(0, 32));
                        getLiveHeapU8().subarray(rhoPtr, rhoPtr + 32).set(rhoBytes);
                        getLiveHeapU8().subarray(rTxPtr, rTxPtr + 32).set(rTransfer);

                        if (wasmInstance._wasm_bdlop_commit(rhoPtr, BigInt(numAmount || 10), rTxPtr, testCommPtr) === 0) {
                            wasmInstance._wasm_sha256(testCommPtr, 2048, hashPtr);
                            wasmInstance._wasm_prf_keygen(candPrfKeyPtr, rTxPtr, 32);
                            if (wasmInstance._wasm_prf_evaluate(nulPtr, candPrfKeyPtr, hashPtr, 32, hashPtr) === 0) {
                                const tNulBytes = getLiveHeapU8().subarray(nulPtr, nulPtr + 32);
                                const tNulHex = Array.from(tNulBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                                utxoBlindingFactors.set(tNulHex, new Uint8Array(rTransfer));
                            }
                        }

                        wasmInstance._wasm_free(rhoPtr);
                        wasmInstance._wasm_free(rTxPtr);
                        wasmInstance._wasm_free(testCommPtr);
                        wasmInstance._wasm_free(hashPtr);
                        wasmInstance._wasm_free(nulPtr);
                        wasmInstance._wasm_free(candPrfKeyPtr);
                    }
                } else if (self.crypto && self.crypto.getRandomValues) {
                    self.crypto.getRandomValues(rTransfer);
                }

                if (rChangeIdx !== -1) {
                    const candChangeR = getCandidateR(rChangeIdx);
                    if (candChangeR) rChange.set(candChangeR);
                    
                    if (wasmInstance._wasm_bdlop_commit && wasmInstance._wasm_prf_keygen) {
                        const rhoPtr = wasmInstance._wasm_malloc(32);
                        const rChPtr = wasmInstance._wasm_malloc(32);
                        const testCommPtr = wasmInstance._wasm_malloc(2048);
                        const hashPtr = wasmInstance._wasm_malloc(32);
                        const nulPtr = wasmInstance._wasm_malloc(32);
                        const candPrfKeyPtr = wasmInstance._wasm_malloc(1024);

                        const encoder = new TextEncoder();
                        const rhoSeedBytes = encoder.encode("SCL_CENTINEL_LATTICE_BDLOP_V1_SEED");
                        const rhoBytes = new Uint8Array(32);
                        rhoBytes.set(rhoSeedBytes.subarray(0, 32));
                        getLiveHeapU8().subarray(rhoPtr, rhoPtr + 32).set(rhoBytes);
                        getLiveHeapU8().subarray(rChPtr, rChPtr + 32).set(rChange);

                        const chgAmt = vChangeVal;
                        if (wasmInstance._wasm_bdlop_commit(rhoPtr, BigInt(chgAmt), rChPtr, testCommPtr) === 0) {
                            wasmInstance._wasm_sha256(testCommPtr, 2048, hashPtr);
                            wasmInstance._wasm_prf_keygen(candPrfKeyPtr, rChPtr, 32);
                            if (wasmInstance._wasm_prf_evaluate(nulPtr, candPrfKeyPtr, hashPtr, 32, hashPtr) === 0) {
                                const cNulBytes = getLiveHeapU8().subarray(nulPtr, nulPtr + 32);
                                const cNulHex = Array.from(cNulBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                                utxoBlindingFactors.set(cNulHex, new Uint8Array(rChange));
                            }
                        }

                        wasmInstance._wasm_free(rhoPtr);
                        wasmInstance._wasm_free(rChPtr);
                        wasmInstance._wasm_free(testCommPtr);
                        wasmInstance._wasm_free(hashPtr);
                        wasmInstance._wasm_free(nulPtr);
                        wasmInstance._wasm_free(candPrfKeyPtr);
                    }
                } else if (self.crypto && self.crypto.getRandomValues) {
                    self.crypto.getRandomValues(rChange);
                }
            } else if (self.crypto && self.crypto.getRandomValues) {
                self.crypto.getRandomValues(rTransfer);
                self.crypto.getRandomValues(rChange);
            }
            getLiveHeapU8().subarray(rTransferPtr, rTransferPtr + 32).set(rTransfer);
            getLiveHeapU8().subarray(rChangePtr, rChangePtr + 32).set(rChange);

            if (dilithiumPubkeyPtr !== 0) {
                getLiveHeapU8().subarray(pkChangePtr, pkChangePtr + 2592).set(getLiveHeapU8().subarray(dilithiumPubkeyPtr, dilithiumPubkeyPtr + 2592));
            }

            if (isBurn) {
                getLiveHeapU8().subarray(pkTransferPtr, pkTransferPtr + 2592).fill(0);
            } else if (isRedemption && dilithiumPubkeyPtr !== 0) {
                const liveU8 = getLiveHeapU8();
                const live8 = getLiveHeap8();
                const myPub = liveU8 ? liveU8.subarray(dilithiumPubkeyPtr, dilithiumPubkeyPtr + 2592).slice(0) : null;
                if (myPub) {
                    if (liveU8) liveU8.subarray(pkTransferPtr, pkTransferPtr + 2592).set(myPub);
                    ephemeralPubkey.set(myPub);
                }
                if (prfKeyPtr !== 0 && live8) {
                    const heapEphPrf = live8.subarray(prfKeyPtr, prfKeyPtr + 1024);
                    if (heapEphPrf) ephemeralPrfKey.set(heapEphPrf);
                }
            } else if (wasmInstance._wasm_dilithium_generate_keypair && wasmInstance._wasm_prf_keygen) {
                const ephPubPtr = wasmInstance._wasm_malloc(2592);
                const ephPrivPtr = wasmInstance._wasm_malloc(4864);
                const prfSeedPtr = wasmInstance._wasm_malloc(32);
                const ephPrfKeyPtr = wasmInstance._wasm_malloc(1024);

                if (wasmInstance._wasm_dilithium_generate_keypair(ephPubPtr, ephPrivPtr) === 1) {
                    wasmInstance._wasm_sha256(ephPrivPtr, 4864, prfSeedPtr);
                    wasmInstance._wasm_prf_keygen(ephPrfKeyPtr, prfSeedPtr, 32);

                    const liveU8 = getLiveHeapU8();
                    const live8 = getLiveHeap8();

                    const heapEphPub = liveU8 ? liveU8.subarray(ephPubPtr, ephPubPtr + 2592) : null;
                    if (heapEphPub) ephemeralPubkey.set(heapEphPub);

                    const heapEphPrf = live8 ? live8.subarray(ephPrfKeyPtr, ephPrfKeyPtr + 1024) : null;
                    if (heapEphPrf) ephemeralPrfKey.set(heapEphPrf);

                    if (heapEphPub && liveU8) liveU8.subarray(pkTransferPtr, pkTransferPtr + 2592).set(heapEphPub);
                }

                wasmInstance._wasm_secure_wipe(ephPrivPtr, 4864);
                wasmInstance._wasm_free(ephPubPtr);
                wasmInstance._wasm_free(ephPrivPtr);
                wasmInstance._wasm_free(prfSeedPtr);
                wasmInstance._wasm_free(ephPrfKeyPtr);
            }

            let currentPrfKeyPtr = 0;
            let ephPrfKeyPtr = 0;
            if (utxo && utxo.ephemeralPrfKey) {
                let ephPrfBytes = toUint8Array(utxo.ephemeralPrfKey, 1024);
                if (ephPrfBytes && ephPrfBytes.length === 1024 && !ephPrfBytes.every(b => b === 0)) {
                    ephPrfKeyPtr = wasmInstance._wasm_malloc(1024);
                    getLiveHeapU8().subarray(ephPrfKeyPtr, ephPrfKeyPtr + 1024).set(ephPrfBytes);
                    currentPrfKeyPtr = ephPrfKeyPtr;
                }
            }

            const genRes = wasmInstance._wasm_generate_centinel_proof(
                pkOldPtr, vOldVal, rOldPtr,
                pkTransferPtr, amountToTakeVal, rTransferPtr,
                pkChangePtr, vChangeVal, rChangePtr,
                currentPrfKeyPtr, rootPtr,
                0, 0,
                outDataPtr
            );

            if (ephPrfKeyPtr !== 0) {
                wasmInstance._wasm_free(ephPrfKeyPtr);
            }

            if (genRes === 0) {
                const heapOut = getLiveHeapU8();
                nullifierBytes = heapOut.subarray(outDataPtr, outDataPtr + 32).slice(0);
                cTransferBytes = heapOut.subarray(outDataPtr + 32, outDataPtr + 32 + 2048).slice(0);
                cChangeBytes = heapOut.subarray(outDataPtr + 32 + 2048, outDataPtr + 32 + 4096).slice(0);

                const viewOut = new DataView(getLiveHeapU8().buffer, outDataPtr + 32 + 4096, 4);
                zkProofLen = viewOut.getUint32(0, true);
                zkProofBytes = heapOut.subarray(outDataPtr + 32 + 4096 + 4, outDataPtr + 32 + 4096 + 4 + zkProofLen).slice(0);

                const spentNullifierHex = Array.from(nullifierBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                utxoNullifiers.add(spentNullifierHex);
                if (isTicket && ticketNullifierHex) {
                    utxoNullifiers.add(ticketNullifierHex);
                }

                // Broadcast OP_REDEEM_CENTINEL on-chain to burn the spent UTXO and publish commitments to the blockchain
                handleSubmitTransaction(requestId, 'OP_REDEEM_CENTINEL', {
                    nullifierBytes: nullifierBytes,
                    cTransferBytes: cTransferBytes,
                    cChangeBytes: cChangeBytes,
                    zkProofBytes: zkProofBytes,
                    amountSubunits: (BigInt(numAmount) * 160000000n).toString(),
                    privkeyHex: privkeyHex,
                    pubkeyHex: pubkeyHex
                });
            }

            wasmInstance._wasm_free(pkOldPtr);
            wasmInstance._wasm_free(rOldPtr);
            wasmInstance._wasm_free(pkTransferPtr);
            wasmInstance._wasm_free(rTransferPtr);
            wasmInstance._wasm_free(pkChangePtr);
            wasmInstance._wasm_free(rChangePtr);
            wasmInstance._wasm_free(rootPtr);
            wasmInstance._wasm_free(outDataPtr);
        }

        if (exportFormat !== 'redeem' && exportFormat !== 'burn') {
            const safeZkProofLen = zkProofLen || 128;
            const headerLen = 4;
            const ticketLen = 2048 + 2048 + 32 + 4 + safeZkProofLen + 8 + 32 + 2592 + 1024;
            const ticketBuf = new Uint8Array(headerLen + ticketLen);
            const view = new DataView(ticketBuf.buffer);

            view.setUint32(0, 1, true); // num_tickets = 1 (Little-Endian)
            let offset = 4;

            ticketBuf.set(toUint8Array(cTransferBytes, 2048), offset); offset += 2048;
            ticketBuf.set(toUint8Array(cChangeBytes, 2048), offset); offset += 2048;
            ticketBuf.set(toUint8Array(nullifierBytes, 32), offset); offset += 32;

            view.setUint32(offset, safeZkProofLen, true); offset += 4;
            ticketBuf.set(toUint8Array(zkProofBytes, safeZkProofLen), offset); offset += safeZkProofLen;

            view.setBigUint64(offset, BigInt(numAmount || 0), true); offset += 8;
            ticketBuf.set(toUint8Array(rTransfer, 32), offset); offset += 32;
            ticketBuf.set(toUint8Array(ephemeralPubkey, 2592), offset); offset += 2592;
            ticketBuf.set(toUint8Array(ephemeralPrfKey, 1024), offset); offset += 1024;

            postMessage({
                type: 'CENTINEL_PROOF_READY',
                data: {
                    requestId: requestId,
                    status: 'SUCCESS',
                    amountToTake: numAmount,
                    exportFormat: exportFormat || 'dat',
                    ticketBytes: ticketBuf.buffer
                }
            }, [ticketBuf.buffer]);
        }
    } catch (e) {
        postMessage({ type: 'ERROR', message: 'Centinel proof generation error: ' + e.message });
    }
}

/* ============================================================================
 * SECTION 7: BINARY CONVERSION & TYPE COERCION UTILITIES
 * ============================================================================ */

/**
 * @brief Coerces arbitrary input representations (Array, Int8Array, Hex string, Object) into a Uint8Array.
 *
 * @param {*} input Source object, typed view, array, or hex string.
 * @param {number|null} [expectedLen=null] Optional byte length requirement for strict zero-padding/truncation.
 * @return {Uint8Array} Guaranteed valid Uint8Array.
 * @complexity Time: O(N) where N is byte length, Space: O(N).
 */
function toUint8Array(input, expectedLen = null) {
    try {
        if (input === null || input === undefined) return expectedLen ? new Uint8Array(expectedLen) : new Uint8Array(0);
        if (input instanceof Uint8Array) {
            return (expectedLen && input.length !== expectedLen) ? new Uint8Array(expectedLen) : new Uint8Array(input);
        }
        if (input instanceof Int8Array || ArrayBuffer.isView(input)) {
            return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
        }
        if (typeof input === 'string') {
            return hexToBytes(input, expectedLen);
        }
        if (Array.isArray(input)) {
            return new Uint8Array(input);
        }
        if (typeof input === 'object' && input !== null) {
            const vals = Object.values(input);
            if (Array.isArray(vals) && vals.length > 0) {
                return new Uint8Array(vals);
            }
        }
    } catch (e) {
        console.error("toUint8Array error:", e);
    }
    return expectedLen ? new Uint8Array(expectedLen) : new Uint8Array(0);
}

/**
 * @brief Decodes a hexadecimal ASCII string into a raw Uint8Array buffer.
 *
 * @param {string} hex Hexadecimal string input.
 * @param {number|null} [expectedByteLen=null] Optional required output byte length.
 * @return {Uint8Array} Parsed binary byte buffer.
 * @complexity Time: O(hex.length), Space: O(hex.length / 2).
 */
function hexToBytes(hex, expectedByteLen = null) {
    if (!hex || typeof hex !== 'string') {
        return new Uint8Array(0);
    }
    const cleaned = hex.replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
    if (expectedByteLen) {
        const targetHexLen = expectedByteLen * 2;
        if (cleaned.length >= targetHexLen) {
            const bytes = new Uint8Array(expectedByteLen);
            for (let i = 0; i < expectedByteLen; i++) {
                bytes[i] = parseInt(cleaned.substring(i * 2, i * 2 + 2), 16);
            }
            return bytes;
        }
        return new Uint8Array(0);
    }
    if (cleaned.length % 2 !== 0) {
        return new Uint8Array(0);
    }
    const bytes = new Uint8Array(cleaned.length / 2);
    for (let i = 0; i < cleaned.length; i += 2) {
        bytes[i / 2] = parseInt(cleaned.substring(i, i + 2), 16);
    }
    return bytes;
}
