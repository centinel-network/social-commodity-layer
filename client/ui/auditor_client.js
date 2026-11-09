/**
 * @file auditor_client.js
 * @module client/ui/auditor_client.js - WebAssembly Auditor Client & Vault Controller
 *
 * @brief Manages the main-thread browser interface to the isolated WebWorker,
 *        handles high-speed binary WebSocket pipelines to the node daemon, and
 *        provides hardware-grade encrypted IndexedDB vault storage at rest.
 *
 * @details
 * Functional Responsibilities:
 * 1. WebWorker Lifecycle Supervisor:
 *    Spawns and monitors `auditor.worker.js`, coordinating the asynchronous `postMessage`
 *    channel and routing incoming binary wire responses to UI callback subscribers.
 * 2. High-Throughput Binary WebSocket Pipeline:
 *    Maintains an active `WebSocket` connection (`binaryType = 'arraybuffer'`) to the
 *    node daemon bridge (`ws://127.0.0.1:5554`), handling automated exponential backoff
 *    reconnection and heartbeat polling sweeps.
 * 3. Encrypted IndexedDB Vault Storage (`SclVaultStorage`):
 *    Implements PBKDF2-HMAC-SHA256 key derivation with 600,000 iterations (NIST SP 800-132)
 *    and AES-GCM-256 authenticated encryption to secure post-quantum key material at rest.
 * 4. Local Cryptographic Credential Sync:
 *    Synchronizes wallet credentials directly with the node daemon via the binary
 *    `SyncWalletKeys` RPC method (opcode `0x0009`).
 *
 * @invariants
 * - Non-Custodial Isolation: Master private keys and PRF seeds are never stored in unencrypted
 *   cookies, LocalStorage, or DOM attributes.
 * - Single Active Pipeline: Only one WebSocket pipeline instance is active at any time;
 *   reconnection teardown cleanly aborts pending poll intervals.
 * - Endianness Invariance: Outbound binary query frames format multi-byte integers in network order (Big-Endian).
 *
 * @standards
 * - NIST SP 800-132: Recommendation for Password-Based Key Derivation (PBKDF2).
 * - NIST FIPS 197: Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM).
 * - RFC 6455: The WebSocket Protocol.
 * - W3C Web Cryptography API (`crypto.subtle`).
 *
 * @dependencies
 * - `auditor.worker.js` (Isolated WebWorker script).
 * - Web Cryptography API (`window.crypto.subtle`).
 * - IndexedDB API (`window.indexedDB`).
 *
 * @threading
 * - Executes in the browser main UI thread.
 * - Asynchronous operations are Promise-driven and non-blocking to the DOM event loop.
 */

/* ============================================================================
 * SECTION 1: ENCRYPTED INDEXEDDB VAULT STORAGE (PBKDF2 + AES-GCM-256)
 * ============================================================================ */

/**
 * @class SclVaultStorage
 * @brief Persistent client-side vault providing authenticated AES-GCM-256 encryption at rest.
 */
class SclVaultStorage {
    /**
     * @brief Instantiates the vault storage controller.
     * @param {string} [dbName='scl_vault_db'] Name of the underlying IndexedDB database.
     */
    constructor(dbName = 'scl_vault_db') {
        this.dbName = dbName;
        this.db = null;
    }

    /**
     * @brief Initializes the IndexedDB database and ensures object store creation.
     * @return {Promise<boolean>} Resolves true when database is ready for transactions.
     * @complexity Time: O(1) asynchronous open, Space: O(1).
     */
    async init() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(this.dbName, 1);
            req.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains('vault_keys')) {
                    db.createObjectStore('vault_keys', { keyPath: 'id' });
                }
            };
            req.onsuccess = (e) => {
                this.db = e.target.result;
                resolve(true);
            };
            req.onerror = (e) => reject(e.target.error);
        });
    }

    /**
     * @brief Encrypts and writes credential data to IndexedDB using PBKDF2-derived AES-GCM-256 keys.
     *
     * @details
     * Key Derivation & Encryption Pipeline:
     * 1. Generates a fresh 32-byte random salt and 12-byte random IV via `crypto.getRandomValues`.
     * 2. Derives a 256-bit AES key using PBKDF2-HMAC-SHA256 across 600,000 iterations.
     * 3. Encrypts stringified `vaultData` using AES-GCM-256.
     * 4. Persists the record `{ id: 'master_vault', salt, iv, ciphertext }` into `vault_keys`.
     *
     * @param {string} passphrase User-supplied master passphrase.
     * @param {Object} vaultData Plaintext credentials object (e.g., PRF key, Dilithium keys).
     * @return {Promise<boolean>} Resolves true upon durable disk commit.
     *
     * @complexity Time: O(600,000 * SHA256) dominated by PBKDF2 computation.
     * @complexity Space: O(JSON.stringify(vaultData).length) ciphertext allocation.
     */
    async saveVault(passphrase, vaultData) {
        if (!this.db) await this.init();
        const salt = window.crypto.getRandomValues(new Uint8Array(32));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            enc.encode(passphrase),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        const aesKey = await window.crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );

        const plaintextBytes = enc.encode(JSON.stringify(vaultData));
        const ciphertext = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            aesKey,
            plaintextBytes
        );

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('vault_keys', 'readwrite');
            const store = tx.objectStore('vault_keys');
            store.put({
                id: 'master_vault',
                salt: Array.from(salt),
                iv: Array.from(iv),
                ciphertext: Array.from(new Uint8Array(ciphertext))
            });
            tx.oncomplete = () => resolve(true);
            tx.onerror = (e) => reject(e.target.error);
        });
    }

    /**
     * @brief Decrypts and retrieves credential data from IndexedDB using the master passphrase.
     *
     * @param {string} passphrase User-supplied master passphrase.
     * @return {Promise<Object|null>} Resolves decrypted credentials object, or null if uninitialized/corrupt.
     * @throws {DOMException} Rejects if passphrase is incorrect or authenticated tag mismatch occurs.
     *
     * @complexity Time: O(600,000 * SHA256) PBKDF2 key derivation.
     * @complexity Space: O(ciphertext.length) plaintext output allocation.
     */
    async loadVault(passphrase) {
        if (!this.db) await this.init();
        const record = await new Promise((resolve, reject) => {
            const tx = this.db.transaction('vault_keys', 'readonly');
            const store = tx.objectStore('vault_keys');
            const req = store.get('master_vault');
            req.onsuccess = () => resolve(req.result);
            req.onerror = (e) => reject(e.target.error);
        });

        if (!record) return null;

        const salt = new Uint8Array(record.salt);
        const iv = new Uint8Array(record.iv);
        const ciphertext = new Uint8Array(record.ciphertext);

        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            enc.encode(passphrase),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        const aesKey = await window.crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            aesKey,
            ciphertext
        );

        const dec = new TextDecoder();
        return JSON.parse(dec.decode(decrypted));
    }

    /**
     * @brief Inspects whether an encrypted vault record exists in local storage.
     * @return {Promise<boolean>} True if encrypted vault record is present.
     * @complexity Time: O(1), Space: O(1).
     */
    async isVaultSaved() {
        if (!this.db) await this.init();
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('vault_keys', 'readonly');
            const store = tx.objectStore('vault_keys');
            const req = store.get('master_vault');
            req.onsuccess = () => resolve(!!req.result);
            req.onerror = (e) => reject(e.target.error);
        });
    }
}
window.SclVaultStorage = SclVaultStorage;

/* ============================================================================
 * SECTION 2: AUDITOR CLIENT ORCHESTRATION & WORKER ISOLATION
 * ============================================================================ */

/**
 * @class SclAuditorClient
 * @brief Coordinates client-side cryptographic proving, node pipeline bridging, and UI telemetry.
 */
class SclAuditorClient {
    /**
     * @brief Instantiates an SCL Auditor Client.
     * @param {string} wsUrl WebSocket server endpoint URL (e.g., `ws://127.0.0.1:5554`).
     * @param {string} [workerPath='auditor.worker.js'] Relative or absolute URL to worker script.
     */
    constructor(wsUrl, workerPath = 'auditor.worker.js') {
        /** @type {string} Target WebSocket endpoint. */
        this.wsUrl = wsUrl;
        /** @type {string} Path to background worker script. */
        this.workerPath = workerPath;
        /** @type {Worker|null} Active WebWorker thread reference. */
        this.worker = null;
        /** @type {WebSocket|null} Active binary WebSocket connection. */
        this.socket = null;
        /** @type {SclVaultStorage} Persistent encrypted vault instance. */
        this.vault = new SclVaultStorage();
        /** @type {boolean} True once keys have been installed into the worker. */
        this.isInitialized = false;
        /** @type {boolean} True once WebAssembly runtime compilation completes inside worker. */
        this.isWasmLoaded = false;
        /** @type {number|null} Polling interval timer ID. */
        this.pollInterval = null;
        /** @type {number|null} Reconnection backoff timer ID. */
        this.reconnectTimer = null;
        /** @type {number} Current reconnection backoff iteration count. */
        this.reconnectAttempts = 0;
                
        // External UI telemetry subscriber callbacks
        /** @type {Function|null} Callback invoked upon block receipt. */
        this.onBlockReceived = null;
        /** @type {Function|null} Callback invoked upon chain metrics receipt. */
        this.onChainInfoReceived = null;
        /** @type {Function|null} Callback invoked upon recent transaction IDs receipt. */
        this.onRecentTxsReceived = null;
        /** @type {Function|null} Callback invoked upon account balance update. */
        this.onBalanceReceived = null;
        /** @type {Function|null} Callback invoked upon economic stage metrics update. */
        this.onValuationsReceived = null;
        /** @type {Function|null} Callback invoked upon 10x10 Game Audit matrix update. */
        this.onAuditReceived = null;
        /** @type {Function|null} Callback invoked upon client-side MMR proof verification. */
        this.onMmrProofVerified = null;
        /** @type {Function|null} Callback invoked upon Quantum TVD drift audit receipt. */
        this.onQuantumTvdAuditReceived = null;
        /** @type {Function|null} Callback invoked upon enterprise drift certificate histogram audit receipt. */
        this.onDriftCertAuditReceived = null;
        /** @type {Object|null} Last drift audit context retained for autonomous 402 replay. */
        this._lastDriftAuditContext = null;
        /** @type {Function|null} Callback invoked upon HTTP/RPC 402 Payment Required challenge. */
        this.onPaymentRequired = null;
        
        /** @type {boolean} Autonomous agent auto-settlement flag. */
        this.autoSettlePayments = true;
        /** @type {Map<string, Object>} Tracks pending API queries awaiting transaction serialization. */
        this._pending402Replays = new Map();
        /** @type {number} SCL402 auto-settlement attempts for the current query (loop guard). */
        this._settlementAttempts = 0;
        /** @type {Function|null} Callback invoked when a settlement tx is accepted by the node mempool. */
        this.onSettlementTxAccepted = null;
        /** @type {Function|null} Callback invoked when autonomous SCL402 settlement cannot proceed. */
        this.onSettlementFailed = null;
        /** @type {string|null} Full 2,592-byte node fee-recipient pubkey from chain info (SCL402). */
        this._nodeFeePubkeyHex = null;
        /** @type {Function|null} Callback invoked upon transaction decryption audit. */
        this.onTransactionAudited = null;
        /** @type {Function|null} Callback invoked upon autopilot state update. */
        this.onAutopilotStatusReceived = null;
        /** @type {Function|null} Callback invoked upon blockchain ledger receipt. */
        this.onBlockchainLedgerReceived = null;
        /** @type {number|null} Cached block height of last DKG epoch. */
        this._lastDkgEpoch = null;
        
        // Status & error callbacks
        /** @type {Function|null} Callback invoked on connection status changes. */
        this.onStatusChange = null;
        /** @type {Function|null} Callback invoked on nullifier match detection. */
        this.onTransactionMatch = null;
        /** @type {Function|null} Callback invoked on client errors. */
        this.onError = null;
        /** @type {Function|null} Callback invoked on RPC errors. */
        this.onRpcError = null;
        
        /** @type {Uint8Array|null} Active 2,592-byte target public key for balance inquiries. */
        this.walletPubkeyBytes = null;
        /** @type {Uint8Array|null} 4,864-byte Dilithium5 private key bytes. */
        this.rawDilithiumKey = null;
        /** @type {Uint8Array|null} 2,592-byte Dilithium5 public key bytes. */
        this.rawDilithiumPubkey = null;
        /** @type {Uint8Array|null} 1,024-byte Module-SIS PRF key bytes. */
        this.expandedPrfKey = null;

        this._lastSyncedPubkey = null;
        this._lastSyncedPrivkey = null;
        this._lastInjectedPrfSeed = null;
        this._lastInjectedDilithiumKey = null;
        this._lastInjectedDilithiumPubkey = null;
    }

    /**
     * @brief Deep equality comparator for Uint8Array byte sequences.
     * @param {Uint8Array|null} a First array.
     * @param {Uint8Array|null} b Second array.
     * @return {boolean} True if byte arrays are identical in length and content.
     * @complexity Time: O(len), Space: O(1).
     */
    _arrayEquals(a, b) {
        if (!a || !b) return a === b;
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }

    /**
     * @brief Configures target public key for account balance audits.
     * @param {Uint8Array} pubkeyBytes 2,592-byte Dilithium5 public key.
     * @return {void}
     */
    setTargetPubkey(pubkeyBytes) {
        if (pubkeyBytes && pubkeyBytes.length === 2592) {
            this.walletPubkeyBytes = pubkeyBytes;
        } else {
            this.walletPubkeyBytes = null;
        }
    }

    /**
     * @brief Instantiates the background WebWorker and registers event listener bridges.
     * @return {void}
     * @complexity Time: O(1) worker thread instantiation, Space: O(1).
     */
    initialize() {
        if (typeof window !== 'undefined' && window.location && window.location.protocol === 'file:') {
            this._handleError('Browser Security Policy: WebWorkers and WebAssembly cannot load directly over file://. Please run a local web server (e.g. "python3 -m http.server 8080" inside client/ui) and browse to http://localhost:8080.');
            return;
        }

        try {
            this.worker = new Worker(this.workerPath);
            this.worker.onmessage = (event) => this._handleWorkerMessage(event);
            this.worker.onerror = (err) => {
                this._handleError('WebWorker error: ' + (err.message || 'Script error in ' + this.workerPath));
            };
            this._logStatus('WORKER CREATED');
        } catch (err) {
            this._handleError('Failed to spawn auditor WebWorker: ' + err.message);
        }
    }

    /**
     * @brief Transfers copies of cryptographic key material into the isolated WebWorker thread.
     *
     * @details
     * Transmits keys as distinct ArrayBuffer copies to ensure the main thread can deallocate
     * or garbage-collect its transient views while the worker pins keys in WASM linear RAM.
     *
     * @param {Uint8Array} prfSeed 32-byte Module-SIS seed or 1,024-byte expanded key.
     * @param {Array<string|Object>} [utxoNullifiers=[]] Array of known spent nullifier strings.
     * @param {Uint8Array|null} [siphashKey=null] 16-byte shared SipHash session key.
     * @param {Uint8Array|null} [dilithiumKey=null] 4,864-byte Dilithium5 private signing key.
     * @param {Uint8Array|null} [dilithiumPubkey=null] 2,592-byte Dilithium5 public verification key.
     * @return {void}
     *
     * @complexity Time: O(total_key_bytes), Space: O(total_key_bytes) message cloning.
     */
    injectAuditorKeys(prfSeed, utxoNullifiers = [], siphashKey = null, dilithiumKey = null, dilithiumPubkey = null) {
        if (!this.worker) {
            this._handleError('Worker not initialized');
            return;
        }
        if (!this.isWasmLoaded) {
            this._handleError('WebAssembly is still loading inside the worker thread');
            return;
        }
        if (prfSeed.byteLength !== 32 && prfSeed.byteLength !== 1024) {
            this._handleError('Invalid PRF key/seed length. Expected 32-byte seed or 1024-byte expanded key.');
            return;
        }

        const currentDilithiumKey = dilithiumKey ? new Uint8Array(dilithiumKey).slice(0) : null;
        const currentDilithiumPubkey = dilithiumPubkey ? new Uint8Array(dilithiumPubkey).slice(0) : null;
        const currentPrfSeed = new Uint8Array(prfSeed).slice(0);

        if (this._lastInjectedPrfSeed && this._arrayEquals(this._lastInjectedPrfSeed, currentPrfSeed) &&
            ((!this._lastInjectedDilithiumKey && !currentDilithiumKey) || (this._lastInjectedDilithiumKey && currentDilithiumKey && this._arrayEquals(this._lastInjectedDilithiumKey, currentDilithiumKey))) &&
            ((!this._lastInjectedDilithiumPubkey && !currentDilithiumPubkey) || (this._lastInjectedDilithiumPubkey && currentDilithiumPubkey && this._arrayEquals(this._lastInjectedDilithiumPubkey, currentDilithiumPubkey)))) {
            return;
        }

        this._lastInjectedPrfSeed = currentPrfSeed;
        this._lastInjectedDilithiumKey = currentDilithiumKey;
        this._lastInjectedDilithiumPubkey = currentDilithiumPubkey;

        this.rawDilithiumKey = currentDilithiumKey;
        this.rawDilithiumPubkey = currentDilithiumPubkey;

        // Transfer copy of the array buffer
        const seedBuffer = new Uint8Array(prfSeed).slice(0);
        let sipBuffer = null;
        if (siphashKey) {
            sipBuffer = new Uint8Array(siphashKey).slice(0);
        }
        let dilithiumBuffer = null;
        if (dilithiumKey) {
            dilithiumBuffer = new Uint8Array(dilithiumKey).slice(0);
        }
        let dilithiumPubBuffer = null;
        if (dilithiumPubkey) {
            dilithiumPubBuffer = new Uint8Array(dilithiumPubkey).slice(0);
        }
        this.worker.postMessage({
            type: 'INITIALIZE_KEYS',
            data: {
                prfSeed: seedBuffer,
                utxoNullifiers: utxoNullifiers,
                siphashKey: sipBuffer,
                dilithiumKey: dilithiumBuffer,
                dilithiumPubkey: dilithiumPubBuffer
            }
        });
    }

/* ============================================================================
 * SECTION 3: BINARY WEBSOCKET PIPELINE & TELEMETRY STREAMING
 * ============================================================================ */

    /**
     * @brief Connects to the node daemon's binary WebSocket bridge and begins telemetry polling.
     *
     * @details
     * Initializes a binary `WebSocket` handle, binds message routing to `_handleIncomingFrame`,
     * initiates an automated 2-second telemetry polling loop (`setInterval`), and configures
     * exponential backoff reconnection handlers upon socket disconnect.
     *
     * @return {void}
     * @complexity Time: O(1) connection setup, Space: O(1).
     */
    connectPipeline() {
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
        if (this.socket) {
            this.socket.onopen = null;
            this.socket.onmessage = null;
            this.socket.onclose = null;
            this.socket.onerror = null;
            this.socket.close();
        }
        
        if (typeof this.reconnectAttempts === 'undefined') {
            this.reconnectAttempts = 0;
        }
        
        this.manualDisconnect = false;

        try {
            // H-2 fix: the SCL402 bearer token rides as the second WebSocket subprotocol
            // entry (browsers cannot set Authorization headers on upgrades).
            const bridgeToken = (typeof window !== 'undefined' && window.SCL_BRIDGE_TOKEN) ? window.SCL_BRIDGE_TOKEN : '';
            this.socket = bridgeToken ? new WebSocket(this.wsUrl, ['SCL402', bridgeToken]) : new WebSocket(this.wsUrl);
            this.socket.binaryType = 'arraybuffer';
            const socketRef = this.socket;

            this.socket.onopen = () => {
                this.reconnectAttempts = 0; // Reset backoff counter on success
                this._logStatus('PIPELINE CONNECTED');
                this.lastChainInfoResponseTime = Date.now();
                this.lastValuationsResponseTime = Date.now();
                this.lastBalanceResponseTime = Date.now();
                this._trySyncNodeWallet();
                // The load balancer may have switched backends: drop any rollback debounce
                if (this.worker) {
                    this.worker.postMessage({ type: 'RESET_ROLLBACK_STATE' });
                }
                this.requestRecentTransactions(0);
                this.requestChainInfo();
                this.requestValuations();
                this.requestAudit();
                this.requestQuantumTvdAudit();
                this.requestAutopilot(-1);
                this.requestBlockchainLedger();
                if (this.walletPubkeyBytes) {
                    this.requestBalance(this.walletPubkeyBytes);
                }
                
                // Polling loop to continuously refresh metrics & unconfirmed txs
                this.pollInterval = setInterval(() => {
                    this.requestRecentTransactions(0);
                    this.requestChainInfo();
                    this.requestValuations();
                    this.requestAudit();
                    this.requestAutopilot(-1);
                    if (this.walletPubkeyBytes) {
                        this.requestBalance(this.walletPubkeyBytes);
                    }
                }, 2000);
            };

            // Route incoming binary frames to the isolated WebWorker
            this.socket.onmessage = (event) => this._handleIncomingFrame(event);

            this.socket.onclose = () => {
                if (this.socket !== socketRef) return; // stale socket from a superseded pipeline
                this._logStatus('PIPELINE DISCONNECTED');
                if (this.pollInterval) {
                    clearInterval(this.pollInterval);
                    this.pollInterval = null;
                }
                
                // Exponential backoff auto-reconnect ensuring UI never permanently halts
                if (!this.manualDisconnect) {
                    const backoffTime = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
                    this.reconnectAttempts++;
                    if (this.wsUrl.includes('127.0.0.1')) {
                        this.wsUrl = this.wsUrl.replace('127.0.0.1', 'localhost');
                    } else if (this.wsUrl.includes('localhost')) {
                        this.wsUrl = this.wsUrl.replace('localhost', '127.0.0.1');
                    }
                    console.warn(`[SclAuditorClient] Pipeline dropped. Attempting graceful reconnect in ${backoffTime}ms...`);
                    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
                    this.reconnectTimer = setTimeout(() => this.connectPipeline(), backoffTime);
                }
            };

            this.socket.onerror = (err) => {
                this._handleError('WebSocket error occurred');
            };

        } catch (err) {
            this._handleError('Failed to connect WebSocket pipeline: ' + err.message);
        }
    }

    /**
     * @brief Dispatches a GetBalance query request frame (Method 0x0001).
     * @param {Uint8Array} targetPubkeyBytes 2,592-byte Dilithium5 public verification key.
     * @return {void}
     */
    requestBalance(targetPubkeyBytes) {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;
        if (targetPubkeyBytes.length !== 2592) {
            this._handleError('Invalid Dilithium public key size for GetBalance');
            return;
        }
        const timestamp = BigInt(Date.now());
        const salt = BigInt(Math.floor(Math.random() * 65535));
        const reqId = (timestamp << 16n) | salt;

        this.worker.postMessage({
            type: 'BUILD_BALANCE_QUERY',
            data: {
                requestId: reqId,
                targetPubkey: targetPubkeyBytes
            }
        });
    }

    /**
     * @brief Dispatches a GetValuations query request frame (Method 0x0005).
     * @return {void}
     */
    requestValuations() {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;
        const timestamp = BigInt(Date.now());
        const salt = BigInt(Math.floor(Math.random() * 65535));
        const reqId = (timestamp << 16n) | salt;

        this.worker.postMessage({
            type: 'BUILD_GET_VALUATIONS',
            data: {
                requestId: reqId
            }
        });
    }

    /**
     * Build and transmit a request frame for GetAudit (Method 0x0004).
     */
    requestAudit() {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;
        const timestamp = BigInt(Date.now());
        const salt = BigInt(Math.floor(Math.random() * 65535));
        const reqId = (timestamp << 16n) | salt;

        this.worker.postMessage({
            type: 'BUILD_GET_AUDIT',
            data: {
                requestId: reqId
            }
        });
    }

    /**
     * Build and transmit a request frame for querying or configuring Node Auto-Pilot (Method 0x000B).
     * @param {number} enable - 1 to enable, 0 to disable, -1 to query without changing.
     * @param {number} valPerHr - Total valuations to submit per hour.
     * @param {number} stakeRatio - Staked/unstaked percentage ratio (0-100).
     */
    requestAutopilot(enable = -1, valPerHr = 1, stakeRatio = 50) {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;
        const timestamp = BigInt(Date.now());
        const salt = BigInt(Math.floor(Math.random() * 65535));
        const reqId = (timestamp << 16n) | salt;

        this.worker.postMessage({
            type: 'BUILD_AUTOPILOT',
            data: {
                requestId: reqId,
                enable: enable,
                valPerHr: valPerHr,
                stakeRatio: stakeRatio
            }
        });
    }

    /**
     * Build and transmit a request frame for Quantum TVD Audit (Method 0x000A).
     */
    requestQuantumTvdAudit(shots = 15000, beaconSeed = null, circuitBytes = null, receipt = null) {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;
        if (!receipt) this._settlementAttempts = 0; // fresh query: reset the SCL402 auto-settle budget
        const timestamp = BigInt(Date.now());
        const salt = BigInt(Math.floor(Math.random() * 65535));
        const reqId = (timestamp << 16n) | salt;

        this.worker.postMessage({
            type: 'BUILD_QUANTUM_TVD_AUDIT',
            data: {
                requestId: reqId,
                shots: shots,
                beaconSeed: beaconSeed,
                circuitBytes: circuitBytes,
                receipt: receipt
            }
        });
    }

    /**
     * Build and transmit a request frame for an enterprise Drift Certificate
     * Histogram Audit (Method 0x000D). Metered via SCL402: the node replies with a
     * 402 Payment Required challenge which is auto-settled by an OP_TRANSFER_POINTER
     * micro-transaction, after which this method is replayed with the receipt.
     * @param {number} shots - Measurement shot budget (1..100,000).
     * @param {Uint8Array|null} beaconSeed - 32-byte DKG beacon seed.
     * @param {Uint8Array|null} histogram - 512-byte wire histogram (128 x u32 BE).
     * @param {Uint8Array|null} circuitBytes - Optional OpenQASM circuit bytes.
     * @param {Object|null} receipt - SCL402 payment receipt.
     */
    requestDriftCertAudit(shots = 15000, beaconSeed = null, histogram = null, circuitBytes = null, receipt = null) {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;
        if (!receipt) this._settlementAttempts = 0; // fresh query: reset the SCL402 auto-settle budget
        const timestamp = BigInt(Date.now());
        const salt = BigInt(Math.floor(Math.random() * 65535));
        const reqId = (timestamp << 16n) | salt;

        if (!receipt) {
            this._lastDriftAuditContext = {
                shots: shots,
                beaconSeed: beaconSeed,
                histogram: histogram,
                circuitBytes: circuitBytes
            };
        }

        this.worker.postMessage({
            type: 'BUILD_DRIFT_CERT_AUDIT',
            data: {
                requestId: reqId,
                shots: shots,
                beaconSeed: beaconSeed,
                histogram: histogram,
                circuitBytes: circuitBytes,
                receipt: receipt
            }
        });
    }
    
    /**
     * Build and transmit a request frame for the complete blockchain ledger (Method 0x000C).
     */
    requestBlockchainLedger() {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;
        const timestamp = BigInt(Date.now());
        const salt = BigInt(Math.floor(Math.random() * 65535));
        const reqId = (timestamp << 16n) | salt;

        this.worker.postMessage({
            type: 'BUILD_GET_BLOCKCHAIN_LEDGER',
            data: {
                requestId: reqId
            }
        });
    }

    /**
     * Build and transmit a request frame for recent transactions (Method 0x0006).
     * @param {number} cursor - The pagination cursor offset.
     */
    requestRecentTransactions(cursor = 0) {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
            this._handleError('Socket connection not open');
            return;
        }
        const timestamp = BigInt(Date.now());
        const salt = BigInt(Math.floor(Math.random() * 65535));
        const reqId = (timestamp << 16n) | salt;

        /* Remember which page of the walk this request opened: the
         * RECENT_TXS_RECEIVED handler resets its accumulator whenever a walk
         * restarts from page 0 (see the pagination fix there). */
        this._lastTxCursor = cursor;
        this.worker.postMessage({
            type: 'BUILD_RECENT_TXS',
            data: {
                requestId: reqId,
                cursor: cursor
            }
        });
    }
    
    /**
     * Build and transmit a request frame for chain info (Method 0x0008).
     */
    requestChainInfo() {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
            return;
        }
        const timestamp = BigInt(Date.now());
        const salt = BigInt(Math.floor(Math.random() * 65535));
        const reqId = (timestamp << 16n) | salt;

        this.worker.postMessage({
            type: 'BUILD_CHAIN_INFO',
            data: {
                requestId: reqId
            }
        });
    }

    /**
     * Build and transmit a request frame for retrieving a specific block (Method 0x0002).
     * @param {number} height - The pagination cursor mapping to block height.
     */
    requestBlock(height) {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;
        const timestamp = BigInt(Date.now());
        const salt = BigInt(Math.floor(Math.random() * 65535));
        const reqId = (timestamp << 16n) | salt;

        this.worker.postMessage({
            type: 'BUILD_GET_BLOCK',
            data: {
                requestId: reqId,
                height: height
            }
        });
    }

    /**
     * Build and transmit a request frame for retrieving a specific transaction (Method 0x0007).
     * @param {Uint8Array|Array} txIdBytes - The 32-byte transaction ID.
     */
    requestTransaction(txIdBytes) {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;
        if (txIdBytes.length !== 32) {
            this._handleError('Invalid transaction hash size');
            return;
        }
        const timestamp = BigInt(Date.now());
        const salt = BigInt(Math.floor(Math.random() * 65535));
        const reqId = (timestamp << 16n) | salt;

        this.worker.postMessage({
            type: 'BUILD_GET_TX',
            data: {
                requestId: reqId,
                txHash: txIdBytes
            }
        });
    }

    /**
     * Handle incoming frames from the WebSocket pipeline.
     */
    _handleIncomingFrame(event) {
        const arrayBuffer = event.data;
        if (arrayBuffer.byteLength < 32) return;

        const uint8View = new Uint8Array(arrayBuffer);

        // Forward raw wire bytes straight to the WebWorker to avoid main thread parsing bottlenecks
        // Optimized using Transferable Objects to eliminate memory copy overhead in the zero-copy pipeline
        if (this.worker) {
            this.worker.postMessage({
                type: 'PROCESS_STREAM_FRAME',
                data: { wireBytes: uint8View }
            }, [arrayBuffer]);
        }
    }

    /**
     * Handle incoming messages from the isolated auditor WebWorker.
     */
    _handleWorkerMessage(event) {
        const { type, status, nullifier, methodId, message, data } = event.data;

        switch (type) {
            case 'PAYMENT_REQUIRED':
                if (this.autoSettlePayments) {
                    this._handleAutonomousSettlement(data);
                }
                if (this.onPaymentRequired) {
                    this.onPaymentRequired(data);
                }
                break;
            case 'STATUS':
                this._logStatus(status);
                break;
            case 'FRAME_BUILT':
                if (this.socket && this.socket.readyState === WebSocket.OPEN) {
                    this.socket.send(data.frame);
                }
                break;
            case 'WIRE_FRAME_READY':
                if (this.socket && this.socket.readyState === WebSocket.OPEN) {
                    this.socket.send(data.wireBytes);
                }

                /* NOTE: the SCL402 replay intentionally no longer fires here.
                 * WIRE_FRAME_READY only proves the settlement frame left the
                 * browser; the node re-selects inputs and re-signs the transfer
                 * custodially, so the tx id computed locally is NOT the id that
                 * lands in the mempool. Replaying with it made the node miss the
                 * receipt and re-issue the 402 challenge forever. The replay now
                 * waits for the SubmitTx RESPONSE (TRANSACTION_AUDITED), which
                 * echoes the authoritative settlement operation. */

                if (this.onWireFrameReady) {
                    this.onWireFrameReady(data);
                }
                break;
            case 'CENTINEL_PROOF_READY':
                if (this.onCentinelProofReady) {
                    this.onCentinelProofReady(data);
                }
                break;
            case 'TRANSACTION_MATCH':
                if (this.onTransactionMatch) {
                    this.onTransactionMatch(event.data);
                }
                break;
            case 'BLOCK_RECEIVED':
                if (this.onBlockReceived) {
                    this.onBlockReceived(data);
                }
                break;
            case 'CHAIN_INFO_RECEIVED':
                this.lastChainInfoResponseTime = Date.now();
                if (data.nodeFeePubkeyHex) {
                    this._nodeFeePubkeyHex = data.nodeFeePubkeyHex;
                }
                if (this.onChainInfoReceived) {
                    this.onChainInfoReceived(data);
                }
                break;
            case 'VALUATIONS_RECEIVED':
                this.lastValuationsResponseTime = Date.now();
                if (this.onValuationsReceived) {
                    this.onValuationsReceived(data);
                }
                break;
            case 'BALANCE_RECEIVED':
                this.lastBalanceResponseTime = Date.now();
                if (this.onBalanceReceived) {
                    this.onBalanceReceived(data);
                }
                break;
            case 'TRANSACTION_AUDITED':
                /* SCL402 replay: the node accepted the settlement transaction and
                 * echoed the canonical operation. Build the payment receipt from
                 * the NODE's tx id (never the local guess) and replay the blocked
                 * query — receipt validation resolves against this mempool op. */
                if (data && data.requestId !== undefined && data.txId &&
                    this._pending402Replays.has(String(data.requestId))) {
                    const replayRid = String(data.requestId);
                    const replayCtx = this._pending402Replays.get(replayRid);
                    this._pending402Replays.delete(replayRid);

                    console.log(`[Agent Bridge] Settled 402 challenge via node tx: ${data.txId}. Replaying Method 0x${Number(replayCtx.methodId).toString(16)}...`);

                    const receipt = {
                        paymentType: 0x01, // OP_TRANSFER_POINTER
                        txIdHex: data.txId,
                        rateLockId: replayCtx.challenge.rateLockId
                    };

                    if (typeof this.onSettlementTxAccepted === 'function') {
                        this.onSettlementTxAccepted({
                            requestId: replayRid,
                            txIdHex: data.txId,
                            amountSubunits: replayCtx.challenge.amountSubunits,
                            methodId: replayCtx.methodId
                        });
                    }

                    if (Number(replayCtx.methodId) === 0x000A) {
                        this.requestQuantumTvdAudit(15000, null, null, receipt);
                    } else if (Number(replayCtx.methodId) === 0x000D && this._lastDriftAuditContext) {
                        const auditCtx = this._lastDriftAuditContext;
                        this.requestDriftCertAudit(auditCtx.shots, auditCtx.beaconSeed, auditCtx.histogram, auditCtx.circuitBytes, receipt);
                    }
                }
                if (this.onTransactionAudited) {
                    this.onTransactionAudited(data);
                }
                break;
            case 'RECENT_TXS_RECEIVED':
                if (data && data.txs) {
                    /* Pagination: the bridge caps each page at
                     * MAX_PAGINATION_RANGE (500) tx ids and signals further
                     * pages via nextCursor. Accumulate across the walk and
                     * paint the badge only when the walk completes; a fresh
                     * walk (opened from cursor 0) restarts the total. */
                    if (this._lastTxCursor === 0 || this._mempoolWalkTotal === undefined) {
                        this._mempoolWalkTotal = 0;
                    }
                    this._mempoolWalkTotal += data.txs.length;

                    if (!this._seenMempoolTxs) this._seenMempoolTxs = new Set();
                    for (const txId of data.txs) {
                        const txBytes = new Uint8Array(txId);
                        const txHex = Array.from(txBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                        if (!this._seenMempoolTxs.has(txHex)) {
                            this._seenMempoolTxs.add(txHex);
                            this.requestTransaction(txBytes);
                        }
                    }

                    const hasMorePages = (data.nextCursor !== undefined && data.nextCursor !== null && data.nextCursor > 0);
                    if (hasMorePages) {
                        this.requestRecentTransactions(data.nextCursor);
                    } else {
                        const mempoolVal = document.getElementById('mempool-size-val');
                        if (mempoolVal) mempoolVal.textContent = this._mempoolWalkTotal;
                    }
                }
                // Suppress onRecentTxsReceived to eliminate redundant [Mempool Tx] viewport messages
                break;
            case 'AUDIT_RECEIVED':
                if (this.onAuditReceived) {
                    this.onAuditReceived(data);
                }
                break;
            case 'QUANTUM_TVD_AUDIT_RECEIVED':
                if (this.onQuantumTvdAuditReceived) {
                    this.onQuantumTvdAuditReceived(data);
                }
                break;
            case 'DRIFT_CERT_AUDIT_RECEIVED':
                if (this.onDriftCertAuditReceived) {
                    this.onDriftCertAuditReceived(data);
                }
                break;
            case 'AUTOPILOT_STATUS_RECEIVED':
                if (this.onAutopilotStatusReceived) {
                    this.onAutopilotStatusReceived(data);
                }
                break;
            case 'BLOCKCHAIN_LEDGER_RECEIVED':
                if (this.onBlockchainLedgerReceived) {
                    this.onBlockchainLedgerReceived(data);
                }
                break;
            case 'MMR_PROOF_VERIFIED':
                if (this.onMmrProofVerified) {
                    this.onMmrProofVerified(data);
                }
                break;
            case 'RPC_ERROR':
                if (this.onRpcError) {
                    this.onRpcError(data);
                }
                break;
            case 'KEYS_GENERATED':
                if (this.onKeysGenerated) {
                    this.onKeysGenerated(data);
                }
                break;
            case 'KEYS_EXPANDED':
                this.expandedPrfKey = new Uint8Array(data.expandedPrfKey).slice(0);
                this._trySyncNodeWallet();
                if (this.onKeysExpanded) {
                    this.onKeysExpanded(data);
                }
                break;
            case 'KEYS_AUTO_INITIALIZED':
                if (this.onKeysAutoInitialized) {
                    this.onKeysAutoInitialized(data);
                }
                break;
            case 'ERROR':
                this._handleError(message);
                break;
        }
    }

    _logStatus(status) {
        const cleanStatus = (status || '').replace(/_/g, ' ');
        this.currentStatus = cleanStatus;
        if (cleanStatus === 'WASM LOADED' || status === 'WASM_LOADED') {
            this.isWasmLoaded = true; // Mark as loaded so we can safely inject keys
        }
        if (cleanStatus === 'KEYS INITIALIZED' || status === 'KEYS_INITIALIZED') {
            this.isInitialized = true;
        }
        if (this.onStatusChange) {
            this.onStatusChange(cleanStatus);
        }
    }

    /**
     * @brief Synchronizes wallet keys to node daemon if socket is open and keys differ from last sync.
     * @return {void}
     */
    _trySyncNodeWallet() {
        /* SyncWalletKeys (0x0009) is categorically rejected with UNAUTHORIZED by
         * both the WebSocket bridge and the P2P RPC handler (remote wallet
         * mutation is disabled by design), and this.wsUrl can point at a remote
         * wss:// endpoint. Never ship 8.5 KB of key material — including the
         * 4,864-byte Dilithium private key — to a remote node just to receive a
         * guaranteed rejection; restrict the sync to loopback dev sessions. */
        if (!/^(ws|wss):\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/.test(this.wsUrl)) {
            return;
        }
        if (this.socket && this.socket.readyState === WebSocket.OPEN &&
            this.rawDilithiumPubkey && this.rawDilithiumPubkey.length === 2592 && !this.rawDilithiumPubkey.every(b => b === 0) &&
            this.rawDilithiumKey && this.rawDilithiumKey.length === 4864 && !this.rawDilithiumKey.every(b => b === 0) &&
            this.expandedPrfKey && this.expandedPrfKey.length === 1024) {

            if (this._lastSyncedPubkey && this._lastSyncedPrivkey &&
                this._arrayEquals(this._lastSyncedPubkey, this.rawDilithiumPubkey) &&
                this._arrayEquals(this._lastSyncedPrivkey, this.rawDilithiumKey)) {
                return;
            }

            this._lastSyncedPubkey = new Uint8Array(this.rawDilithiumPubkey).slice(0);
            this._lastSyncedPrivkey = new Uint8Array(this.rawDilithiumKey).slice(0);
            this.syncNodeWalletKeys(this.rawDilithiumPubkey, this.rawDilithiumKey, this.expandedPrfKey);
        }
    }

    /**
     * @brief Transmits a SyncWalletKeys binary RPC frame (Method 0x0009) to hot-swap daemon credentials.
     *
     * @param {Uint8Array} pubkeyBytes 2,592-byte Dilithium5 public key.
     * @param {Uint8Array} privkeyBytes 4,864-byte Dilithium5 private key.
     * @param {Uint8Array} prfKeyBytes 1,024-byte Module-SIS PRF key matrix.
     * @return {void}
     *
     * @complexity Time: O(key_lengths), Space: O(key_lengths) wire buffer allocation.
     */
    syncNodeWalletKeys(pubkeyBytes, privkeyBytes, prfKeyBytes) {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;
        const timestamp = BigInt(Date.now());
        const salt = BigInt(Math.floor(Math.random() * 65535));
        const reqId = (timestamp << 16n) | salt;

        const headerLen = 32;
        const payloadLen = 2592 + 4864 + 1024;
        const frameBuf = new Uint8Array(headerLen + payloadLen);
        const view = new DataView(frameBuf.buffer);

        view.setUint8(0, 1);
        view.setUint8(1, 0);
        view.setUint16(2, 0, false);
        view.setUint16(4, 0x0009, false); // SyncWalletKeys opcode
        view.setUint16(6, 0, false);
        view.setBigUint64(8, reqId, false);
        view.setUint32(16, payloadLen, false);
        view.setUint32(20, 0, false);
        view.setBigUint64(24, 0n, false);

        let offset = headerLen;
        frameBuf.set(pubkeyBytes, offset); offset += 2592;
        frameBuf.set(privkeyBytes, offset); offset += 4864;
        frameBuf.set(prfKeyBytes, offset);

        this.socket.send(frameBuf);
    }

    _handleError(msg) {
        if (this.onError) {
            this.onError(msg);
        } else {
            console.error('[SclAuditorClient] ' + msg);
        }
    }
    
    /**
     * Triggers asynchronous key generation inside the isolated WebWorker.
     */
    generateAuditorKeys() {
        if (!this.worker) {
            this._handleError('Worker not initialized');
            return;
        }
        if (!this.isWasmLoaded) {
            this._handleError('WebAssembly is still loading inside the worker thread');
            return;
        }
        this.worker.postMessage({ type: 'GENERATE_KEYS' });
    }

    /**
     * Build and transmit a request for local client-side verification of an MMR proof.
     * @param {Uint8Array} leafHash - 32-byte leaf hash.
     * @param {Uint8Array} proofBytes - Serialized proof bytes.
     * @param {Array<Uint8Array>} peaks - List of peak hashes.
     */
    verifyMmrProof(leafHash, proofBytes, peaks) {
        if (!this.worker) return;
        const timestamp = BigInt(Date.now());
        const salt = BigInt(Math.floor(Math.random() * 65535));
        const reqId = (timestamp << 16n) | salt;

        this.worker.postMessage({
            type: 'VERIFY_MMR_PROOF',
            data: {
                requestId: reqId,
                leafHash: leafHash,
                proofBytes: proofBytes,
                peaks: peaks
            }
        });
    }

    /**
     * Submit a transaction request to the WebWorker for signing and wire framing.
     * @param {string} requestId
     * @param {string} opType
     * @param {Object} payload
     */
    submitTransaction(requestId, opType, payload) {
        if (!this.worker) return;
        this.worker.postMessage({
            type: 'SUBMIT_TRANSACTION',
            data: { requestId, opType, payload }
        });
    }

    /**
     * Request Centinel proof generation from the WebWorker.
     * @param {Object} data - Centinel proof parameters
     */
    generateCentinelProof(data) {
        if (!this.worker) return;
        this.worker.postMessage({
            type: 'GENERATE_CENTINEL_PROOF',
            data: data
        });
    }

    /**
     * @brief Autonomous API Payment challenge settlement handler.
     * @details Every abort path reports through onSettlementFailed so the UI can
     *          state the exact unmet requirement instead of hanging on
     *          "Settling autonomously…" — a silent dead end is the worst failure
     *          mode this platform can ship.
     */
    async _handleAutonomousSettlement(challenge) {
        const settleFail = (reason) => {
            console.error('[Agent Bridge] Autonomous settlement failed: ' + reason);
            if (typeof this.onSettlementFailed === 'function') {
                this.onSettlementFailed({
                    methodId: challenge ? challenge.methodId : null,
                    amountSubunits: challenge ? challenge.amountSubunits : 0,
                    reason: reason
                });
            }
        };

        try {
            console.warn(`[Agent Bridge] 402 Payment Required for Method 0x${Number(challenge.methodId).toString(16)}: ${challenge.amountSubunits} subunits`);

            /* Loop guard: a node that keeps re-issuing the 402 challenge (receipt
             * not resolving) must not drive an unbounded settle/replay cycle. */
            this._settlementAttempts = (this._settlementAttempts || 0) + 1;
            if (this._settlementAttempts > 3) {
                settleFail('the node re-issued the SCL402 challenge after ' + (this._settlementAttempts - 1) +
                    ' settlement attempts — the payment receipt is not resolving against a mempool transaction. ' +
                    'Verify the node runs the settlement-echo build (SubmitTx must return the settlement operation).');
                return;
            }

            const requiredAmount = BigInt(challenge.amountSubunits);
            /* Input selection must cover the payment PLUS the network fee
             * (calculate_fee: amount × π/100) or the node rejects the transfer. */
            const networkFee = (requiredAmount * 3141592653589793n) / 100000000000000000n;
            const targetAmount = requiredAmount + networkFee;
            if ((window.lastBalanceSubunits || 0n) < targetAmount) {
                settleFail('insufficient liquid SCL — the wallet holds ' +
                    (window.lastBalanceSubunits !== undefined
                        ? (Number(window.lastBalanceSubunits) / 160000000).toFixed(4) + ' SCL'
                        : 'no polled balance') +
                    ' but settlement needs ' + (Number(targetAmount) / 160000000).toFixed(4) +
                    ' SCL (fee + π% network fee)');
                return;
            }

            // Defer pointer selection to the consuming application (explorer_app.js implements window.selectUnspentPointers natively)
            if (typeof window.selectUnspentPointers === 'undefined') {
                settleFail('pointer selector unavailable — connect the node on the Dashboard first');
                return;
            }

            const selectedInputs = window.selectUnspentPointers(targetAmount, false);
            if (!selectedInputs) {
                settleFail('unable to aggregate UTXO pointers covering ' + (Number(targetAmount) / 160000000).toFixed(4) +
                    ' SCL — the unspent-pointer cache may be empty or every liquid pointer is mempool-locked');
                return;
            }

            let privKeyHex = null;
            let pubKeyHex = null;
            if (typeof window.resolveWalletCredentials === 'function') {
                const creds = window.resolveWalletCredentials();
                privKeyHex = creds.privKeyHex;
                pubKeyHex = creds.pubKeyHex;
            }

            if (!privKeyHex || !pubKeyHex) {
                settleFail('cryptographic credentials unavailable — load or unlock the wallet (private key) on the Dashboard');
                return;
            }

            if (!this.worker) {
                settleFail('the auditor worker thread is not running — reload the page and reconnect');
                return;
            }

            const reqIdStr = ((BigInt(Date.now()) << 16n) | BigInt(Math.floor(Math.random() * 65535))).toString();

            this._pending402Replays.set(reqIdStr, {
                challenge: challenge,
                methodId: challenge.methodId
            });

            // SCL402: challenge.recipientHex is the node's 32-byte SHA-256 *address*,
            // but the worker's OP_TRANSFER_POINTER builder requires the full 2,592-byte
            // Dilithium pubkey and zero-fills anything shorter — paying the 32-byte hash
            // directly would fund SHA256(0x00 x 2592), a burn address. Resolve the node
            // pubkey whose SHA-256 equals the recipient address and pass that instead.
            const resolveFeeRecipientPubkey = async () => {
                const recipient = (challenge.recipientHex || '').toLowerCase();
                if (!recipient || !window.crypto || !window.crypto.subtle) return null;

                const candidates = [];
                if (this._nodeFeePubkeyHex) candidates.push(this._nodeFeePubkeyHex);
                if (typeof window.nodePubkeyHex === 'string') candidates.push(window.nodePubkeyHex);

                for (const candidate of candidates) {
                    const hex = candidate.toLowerCase();
                    if (hex.length !== 5184) continue; // 2,592 bytes

                    const pubkeyBytes = new Uint8Array(2592);
                    for (let i = 0; i < 2592; i++) {
                        pubkeyBytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
                    }

                    const digest = await window.crypto.subtle.digest('SHA-256', pubkeyBytes);
                    const digestHex = Array.from(new Uint8Array(digest))
                        .map(b => b.toString(16).padStart(2, '0')).join('');

                    if (digestHex === recipient) return hex;
                }
                return null;
            };

            const feeRecipientPubkeyHex = await resolveFeeRecipientPubkey();
            if (!feeRecipientPubkeyHex) {
                this._pending402Replays.delete(reqIdStr);
                settleFail('no known node pubkey hashes to the 402 recipient ' + challenge.recipientHex +
                    ' (chain info did not publish the fee-recipient key) — refusing to transfer to a burn address');
                return;
            }

            this.submitTransaction(reqIdStr, 'OP_TRANSFER_POINTER', {
                recipientPubkeyHex: feeRecipientPubkeyHex,
                senderPubkeyHex: pubKeyHex,
                privkeyHex: privKeyHex,
                amountSubunits: challenge.amountSubunits,
                inputs: selectedInputs
            });
        } catch (e) {
            settleFail('internal error — ' + (e && e.message ? e.message : String(e)));
        }
    }

    /**
     * Save key material to encrypted IndexedDB vault at rest.
     */
    async saveVault(passphrase, vaultData) {
        return await this.vault.saveVault(passphrase, vaultData);
    }

    /**
     * Unlock and load key material from encrypted IndexedDB vault.
     */
    async loadVault(passphrase) {
        return await this.vault.loadVault(passphrase);
    }

    /**
     * Terminate connection and trigger strict memory zeroing inside the WebWorker.
     */
    disconnect() {
        this.manualDisconnect = true;
        this._lastSyncedPubkey = null;
        this._lastSyncedPrivkey = null;
        this._lastInjectedPrfSeed = null;
        this._lastInjectedDilithiumKey = null;
        this._lastInjectedDilithiumPubkey = null;
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
        
        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }
        if (this.worker) {
            this.worker.postMessage({ type: 'TERMINATE' });
            this.worker = null;
        }
        this.isInitialized = false;
        this.isWasmLoaded = false; // Reset flag on disconnect
        this._logStatus('TERMINATED');
    }
}
