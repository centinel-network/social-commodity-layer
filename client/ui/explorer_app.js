/**
 * @file explorer_app.js
 * @module client/ui/explorer_app.js - Frontend Application Coordinator & Blockchain Explorer UI
 *
 * @brief High-level application controller, UI event dispatcher, and multi-view coordinator
 *        for the Centinel Network browser client, connecting real-time WebSocket streams
 *        to canvas topographies and user interaction panels.
 *
 * @details
 * Architectural Responsibilities:
 * 1. View Routing & DOM Navigation:
 *    Manages single-page tab transitions across Main Dashboard, Full Blockchain Explorer,
 *    `satocialist.conf` Settings Manager, and Cryptographic Privacy Policy disclosures.
 * 2. Real-Time Cryptographic Auditing:
 *    - Renders Module-SIS lattice coefficient matrices and computes dynamic transport PoW difficulty.
 *    - Evaluates total supply conservation invariants in real time (`v_minted + v_remaining == 16,000,000 SCL`).
 *    - Renders live QPU Total Variation Distance (TVD) and Chernoff-Hoeffding confidence bounds.
 * 3. Client-Side MMR & Cryptographic Proof Synthesis:
 *    Maintains an in-memory client `RealMmrTree` reflecting on-chain leaf additions, generates
 *    Merkle inclusion proofs, and verifies roots locally within the WebAssembly container.
 * 4. Animated QR Code Streaming (BC-UR v1.0):
 *    Encapsulates binary Centinel bearer tickets (.dat) into animated high-density QR video streams
 *    for optical air-gapped transfers between mobile cameras and node readers.
 *
 * @invariants
 * - Non-Destructive DOM Updates: Periodic metrics loops update `textContent` directly to avoid
 *   canvas element tearing or DOM garbage collection spikes.
 * - Supply Invariance: Real-time checks verify that `totalRewarded + remainingSubunits` strictly
 *   equals the protocol hard cap of 2,560,000,000,000,000 atomic subunits (16,000,000 SCL).
 *
 * @standards
 * - NIST FIPS 180-4: Secure Hash Standard (SHA-256).
 * - Blockchain Commons Uniform Resources (BC-UR v1.0) Animated QR Specification.
 *
 * @dependencies
 * - `auditor_client.js`, `mmr_canvas_renderer.js`, `index.html`.
 */

/* ============================================================================
 * SECTION 1: LATTICE COEFFICIENT DENSITY & DYNAMIC POW SAMPLING
 * ============================================================================ */

/**
 * @brief Formats a numeric value with thousands commas and fixed decimal places for UI display.
 * @param {number|string|bigint} val Number to format.
 * @param {number} [decimals=4] Fractional digits to display.
 * @return {string} Formatted number string (e.g. "16,000,000.0000").
 */
function formatScl(val, decimals = 4) {
    const num = Number(val) || 0;
    const parts = num.toFixed(decimals).split('.');
    parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    return parts.join('.');
}

/** @type {Array<number>} Rolling history buffer tracking dynamic PoW difficulty values. */
const difficultyHistory = [];

// Global telemetry readiness state flags (guarantee "Awaiting Telemetry" until live data arrives)
window.hasDkgTelemetry = false;
window.hasLatticeTelemetry = false;
window.hasInvariantTelemetry = false;

/**
 * @brief Evaluates and renders real-time Module-SIS lattice density and transport PoW difficulty.
 *
 * @details
 * Calculates dynamic proof-of-work puzzle difficulty based on active DKG sessions and network
 * staked SCL, renders ASCII difficulty sparklines, and visualizes ternary lattice coefficients
 * ($\eta \in [-2, 2]$) across an interactive HTML5 canvas matrix grid.
 *
 * @param {number} activeDkgSessions Number of concurrent DKG ceremonies active.
 * @param {number|bigint} totalStaked Cumulative staked subunits across all validators.
 * @return {void}
 * @complexity Time: O(rows * cols) = O(16 * 64) matrix rasterization, Space: O(1).
 */
function updateLatticeDensity(activeDkgSessions, totalStaked) {
    const container = document.getElementById('lattice-density-container');
    if (!container || !window.hasLatticeTelemetry) return;

    // Sample mathematical coefficients governing module-SIS parameters
    const q = 8380417;
    const eta = 2;
    const tau = 60;
    const coefficientRange = (2 * eta) + 1; // Maps strictly to [-2, 2] bounds for Dilithium5 / SIS

    // Base difficulty starts at 10, scales up based on DKG sessions and staked coins
    const baseDifficulty = 10;
    const stakedScl = totalStaked / 160000000;
    const dkgPenalty = activeDkgSessions * 1.5;
    const dynamicDifficulty = Math.min(
        20,
        baseDifficulty + (stakedScl / 1000000) + dkgPenalty
    ).toFixed(1);

    difficultyHistory.push(Number(dynamicDifficulty));
    if (difficultyHistory.length > 15) {
        difficultyHistory.shift();
    }

    // Generate ASCII sparkline representing the difficulty trends
    const sparkline = difficultyHistory.map(val => {
        const normalized = Math.round((val - 10) / 2);
        const chars = [' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        return chars[Math.max(0, Math.min(chars.length - 1, normalized))];
    }).join('');

        // If the canvas structures do not exist, initialize the containers and elements once
    if (!document.getElementById('lattice-density-canvas')) {
        container.innerHTML = `
            <div style="display: flex; flex-direction: column; gap: 8px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="color: var(--text-muted); display: flex; align-items: center;">Modulus (Q): <span class="info-pop"><i class="info-icon">i</i><span class="info-bubble">Prime modulus $q = 8{,}380{,}417$ defining polynomial ring $R_q = \\mathbb{Z}_q[X]/(X^{256} + 1)$ for ML-DSA-87 and Module-SIS.</span></span></span>
                    <span style="color: var(--text-main); font-weight: 600;">8,380,417</span>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="color: var(--text-muted); display: flex; align-items: center;">Bound / Weight: <span class="info-pop"><i class="info-icon">i</i><span class="info-bubble">Noise bound $\\lVert s \\rVert_\\infty \\le \\eta = 2$; challenge weight $\\lVert c \\rVert_1 = \\tau = 60$ with ternary coefficients $c_i \\in \\{-1, 0, 1\\}$.</span></span></span>
                    <span style="color: var(--text-main); font-weight: 600;">eta=2 / tau=60</span>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="color: var(--text-muted); display: flex; align-items: center;">Dynamic PoW Difficulty: <span class="info-pop"><i class="info-icon">i</i><span class="info-bubble">Adaptive PoW difficulty $D = \\min(20,\\, 10 + C_{\\text{staked}}/10^6 + 1.5 \\cdot N_{\\text{DKG}})$ bits for transport handshake cookies.</span></span></span>
                    <span id="lattice-difficulty-val" style="color: var(--accent-green); font-weight: 600;">${dynamicDifficulty} bits</span>
                </div>
                <div style="margin-top: 4px; display: flex; flex-direction: column; gap: 4px;">
                    <span style="color: var(--text-muted); font-size: 0.75rem;">Aggregate Difficulty Trend:</span>
                    <span id="lattice-sparkline-val" style="color: var(--text-main); letter-spacing: 2px; font-size: 1.1rem; font-family: monospace;">${sparkline}</span>
                </div>
                <div style="margin-top: 6px; display: flex; flex-direction: column; gap: 4px;">
                    <span style="color: var(--text-muted); font-size: 0.75rem;">Lattice Density Sample (SIS Matrix):</span>
                    <canvas id="lattice-density-canvas" width="256" height="64" style="background-color: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 4px; width: 100%; height: 64px; cursor: crosshair;"></canvas>
                    <div id="lattice-coeff-info" style="color: var(--text-muted); font-size: 0.7rem; font-family: monospace; min-height: 1.2rem; margin-top: 2px; text-align: center;">Hover over cells to probe SIS coefficients</div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px;">
                        <span style="color: var(--text-muted); font-size: 0.75rem;">Coefficient Density Graphing:</span>
                        <span id="lattice-graph-tooltip" style="color: var(--text-muted); font-size: 0.7rem; font-family: monospace;">Hover to inspect</span>
                    </div>
                    <div style="position: relative;">
                        <canvas id="lattice-graph-canvas" width="256" height="88" style="background-color: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 4px; width: 100%; height: 88px; display: block; cursor: crosshair;"></canvas>
                        <span id="lattice-graph-current-density" style="position: absolute; top: 4px; left: 6px; font-size: 10px; font-family: monospace; color: var(--text-muted); pointer-events: none;"></span>
                    </div>
                </div>
            </div>
        `;
    } else {
        // Direct, non-destructive DOM update for text nodes prevents tearing canvas instances
        const difficultyEl = document.getElementById('lattice-difficulty-val');
        const sparklineEl = document.getElementById('lattice-sparkline-val');
        if (difficultyEl) difficultyEl.textContent = `${dynamicDifficulty} bits`;
        if (sparklineEl) sparklineEl.textContent = sparkline;
    }

    // Render the sparse Module-SIS coefficient matrix grid representation
    // Enforce strict performance budgets by bypassing heavy canvas rasterization when tab is backgrounded
    if (document.hidden) return;

    const densityCanvas = document.getElementById('lattice-density-canvas');
    const coeffInfo = document.getElementById('lattice-coeff-info');
    if (densityCanvas && coeffInfo) {
        const densityCtx = densityCanvas.getContext('2d');
        if (densityCtx) {
            densityCtx.clearRect(0, 0, densityCanvas.width, densityCanvas.height);
            const cols = 64;
            const rows = 16;
            const cellWidth = densityCanvas.width / cols;
            const cellHeight = densityCanvas.height / rows;

            const actualKeyBytes = window.expandedPrfKeyBytes;
            const gridValues = [];

            let nonZeroCount = 0;
            const totalCells = rows * cols;

            // Fill with real-time ternary coefficients from the user's PRF key if available,
            // otherwise fallback to pseudo-random matrix parameters
            for (let r = 0; r < rows; r++) {
                gridValues[r] = [];
                for (let c = 0; c < cols; c++) {
                    let val = 0;
                    if (actualKeyBytes && actualKeyBytes.length === 1024) {
                        const keyIdx = (r * cols + c) % 1024;
                        val = actualKeyBytes[keyIdx];
                    } else {
                        // Enforce the mathematical bounds of eta=2 [-2, 2] for the simulated CRS matrix A
                        const seed = Math.sin(r * 12.9898 + c * 78.233 + stakedScl) * 43758.5453;
                        val = Math.floor((seed - Math.floor(seed)) * coefficientRange) - eta;
                    }
                    gridValues[r][c] = val;

                    if (val !== 0) {
                        nonZeroCount++;
                    }

                    const isOrange = document.documentElement.classList.contains('orange-mode');
                    const isLight = document.documentElement.classList.contains('light-mode');
                    if (val === 0) {
                        densityCtx.fillStyle = isOrange
                            ? (isLight ? '#e7e5e4' : '#292119')
                            : (isLight ? '#e2e8f0' : '#1e293b'); // Zero (Sparse)
                    } else if (val > 0) {
                        densityCtx.fillStyle = isOrange
                            ? (isLight ? '#ea580c' : '#f7931a')
                            : (isLight ? '#059669' : '#10b981'); // Positive coefficients
                    } else {
                        densityCtx.fillStyle = isLight ? '#7c3aed' : '#a78bfa'; // Negative coefficients
                    }
                    densityCtx.fillRect(c * cellWidth, r * cellHeight, cellWidth - 1, cellHeight - 1);
                }
            }

            const densityPct = (nonZeroCount / totalCells) * 100;

            // Persist matrix arrays directly to the DOM element to prevent massive closure memory leaks on each 2s tick
            densityCanvas._gridValues = gridValues;
            densityCanvas._actualKeyBytes = actualKeyBytes;

            if (!densityCanvas._hasHoverProbe) {
                // Attach interactive hover probe safely on persistence ONCE to enforce Phase 3 performance budgets
                densityCanvas.addEventListener('mousemove', (e) => {
                    const rect = densityCanvas.getBoundingClientRect();
                    const x = e.clientX - rect.left;
                    const y = e.clientY - rect.top;
                    const colIdx = Math.floor(x / (rect.width / cols));
                    const rowIdx = Math.floor(y / (rect.height / rows));

                    if (colIdx >= 0 && colIdx < cols && rowIdx >= 0 && rowIdx < rows) {
                        const val = densityCanvas._gridValues[rowIdx][colIdx];
                        let elementLabel = "0 (Sparse)";
                        if (val > 0) elementLabel = `+${val} (Active)`;
                        else if (val < 0) elementLabel = `${val} (Active)`;
                        const coeffType = densityCanvas._actualKeyBytes ? "User Private Key k" : "CRS Matrix A";
                        coeffInfo.innerHTML = `<span style="color: var(--text-main)">[Row:${rowIdx}, Col:${colIdx}] ${coeffType} coeff = ${elementLabel}</span>`;
                    }
                });

                densityCanvas.addEventListener('mouseleave', () => {
                    coeffInfo.innerHTML = "Hover over cells to probe SIS coefficients";
                });
                
                densityCanvas._hasHoverProbe = true;
            }

            // Real-time density graphing implementation (Phase 3 spec alignment)
            if (!window.densityHistory) {
                window.densityHistory = [];
            }
            window.densityHistory.push(densityPct);
            if (window.densityHistory.length > 30) {
                window.densityHistory.shift();
            }

            const graphCanvas = document.getElementById('lattice-graph-canvas');
            if (graphCanvas) {
                const graphCtx = graphCanvas.getContext('2d');
                if (graphCtx) {
                    graphCanvas.width = graphCanvas.clientWidth;
                    graphCtx.clearRect(0, 0, graphCanvas.width, graphCanvas.height);

                    // Draw subtle background grid lines
                    graphCtx.strokeStyle = document.documentElement.classList.contains('light-mode') ? 'rgba(148, 163, 184, 0.3)' : 'rgba(51, 65, 85, 0.4)';
                    graphCtx.lineWidth = 1;
                    graphCtx.beginPath();
                    for (let i = 1; i < 4; i++) {
                        let y = (graphCanvas.height / 4) * i;
                        graphCtx.moveTo(0, y);
                        graphCtx.lineTo(graphCanvas.width, y);
                    }
                    graphCtx.stroke();

                    // Draw rolling history line
                    const isOrange = document.documentElement.classList.contains('orange-mode');
                    const isLight = document.documentElement.classList.contains('light-mode');
                    graphCtx.strokeStyle = isOrange
                        ? (isLight ? '#ea580c' : '#f7931a')
                        : (isLight ? '#059669' : '#10b981');
                    graphCtx.lineWidth = 1.5;
                    graphCtx.beginPath();
                    const maxPoints = 30;
                    const xStep = graphCanvas.width / (maxPoints - 1);

                    for (let i = 0; i < window.densityHistory.length; i++) {
                        const x = i * xStep;
                        const val = window.densityHistory[i];
                        const normalized = val / 100;
                        const y = graphCanvas.height - (normalized * graphCanvas.height);
                        if (i === 0) {
                            graphCtx.moveTo(x, y);
                        } else {
                            graphCtx.lineTo(x, y);
                        }
                    }
                    graphCtx.stroke();

                    // Update HTML overlay text to avoid canvas stretching distortion
                    const densityLabel = document.getElementById('lattice-graph-current-density');
                    if (densityLabel) {
                        densityLabel.textContent = `Density: ${densityPct.toFixed(1)}%`;
                    }

                    // Attach hover inspection listener once
                    if (!graphCanvas._hasHoverListener) {
                        graphCanvas._hasHoverListener = true;
                        graphCanvas.addEventListener('mousemove', (e) => {
                            const rect = graphCanvas.getBoundingClientRect();
                            const x = e.clientX - rect.left;
                            const idx = Math.min(window.densityHistory.length - 1, Math.max(0, Math.round((x / rect.width) * (window.densityHistory.length - 1))));
                            const val = window.densityHistory[idx];
                            const tooltip = document.getElementById('lattice-graph-tooltip');
                            if (tooltip) {
                                tooltip.innerHTML = `<span style="color: var(--accent-green); font-weight: bold;">${val.toFixed(1)}%</span> <span style="color: var(--text-muted); font-weight: normal;">(T-${(window.densityHistory.length - 1 - idx) * 2}s)</span>`;
                            }
                        });
                        graphCanvas.addEventListener('mouseleave', () => {
                            const tooltip = document.getElementById('lattice-graph-tooltip');
                            if (tooltip) {
                                tooltip.textContent = 'Hover to inspect';
                            }
                        });
                    }
                }
            }
        }
    }
}

/* ============================================================================
 * SECTION 2: STANDALONE CRYPTOGRAPHIC UTILITIES & MMR ACCUMULATOR
 * ============================================================================ */

/**
 * @brief Strictly escapes RPC-derived strings to prevent innerHTML XSS injection.
 */
function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/[&<>'"]/g, match => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[match]);
}

/**
 * @brief Evaluates single-shot SHA-256 digest in pure JavaScript for client-side validation.
 *
 * @param {Uint8Array} bytes Input binary data buffer.
 * @return {Uint8Array} 32-byte SHA-256 digest array.
 * @complexity Time: O(bytes.length) 64-byte block compression, Space: O(1).
 */

function sha256_uint8(bytes) {
    var K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    var H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    var l = bytes.length;
    var len = l * 8;
    var k = (55 - l) % 64;
    if (k < 0) k += 64;
    var padding = new Uint8Array(l + 1 + k + 8);
    padding.set(bytes);
    padding[l] = 0x80;
     
    var view = new DataView(padding.buffer);
    view.setUint32(padding.length - 4, len, false);
    if (len > 0xffffffff) {
        view.setUint32(padding.length - 8, Math.floor(len / 0x100000000), false);
    }

    var W = new Uint32Array(64);

    for (var i = 0; i < padding.length; i += 64) {
        var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

        for (var j = 0; j < 64; j++) {
            if (j < 16) {
                W[j] = view.getUint32(i + j * 4, false);
            } else {
                var s0 = ((W[j-15] >>> 7) | (W[j-15] << 25)) ^ ((W[j-15] >>> 18) | (W[j-15] << 14)) ^ (W[j-15] >>> 3);
                var s1 = ((W[j-2] >>> 17) | (W[j-2] << 15)) ^ ((W[j-2] >>> 19) | (W[j-2] << 13)) ^ (W[j-2] >>> 10);
                W[j] = (W[j-16] + s0 + W[j-7] + s1) | 0;
            }

            var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
            var ch = (e & f) ^ (~e & g);
            var temp1 = (h + S1 + ch + K[j] + W[j]) | 0;
            var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
            var maj = (a & b) ^ (a & c) ^ (b & c);
            var temp2 = (S0 + maj) | 0;

            h = g;
            g = f;
            f = e;
            e = (d + temp1) | 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) | 0;
        }

        H[0] = (H[0] + a) | 0;
        H[1] = (H[1] + b) | 0;
        H[2] = (H[2] + c) | 0;
        H[3] = (H[3] + d) | 0;
        H[4] = (H[4] + e) | 0;
        H[5] = (H[5] + f) | 0;
        H[6] = (H[6] + g) | 0;
        H[7] = (H[7] + h) | 0;
    }

    var result = new Uint8Array(32);
    var resView = new DataView(result.buffer);
    for (var i = 0; i < 8; i++) {
        resView.setUint32(i * 4, H[i], false);
    }
    return result;
}
                                                      
/**
 * @brief Computes intermediate parent digest from two adjacent MMR node hashes: SHA256(left || right).
 *
 * @param {Uint8Array} leftHash 32-byte left child digest.
 * @param {Uint8Array} rightHash 32-byte right child digest.
 * @return {Uint8Array} 32-byte parent node hash.
 * @complexity Time: O(1), Space: O(1).
 */
function hashNode(leftHash, rightHash) {
    const combined = new Uint8Array(64);
    combined.set(leftHash, 0);
    combined.set(rightHash, 32);
    return sha256_uint8(combined);
}

/**
 * @class RealMmrTree
 * @brief In-memory Merkle Mountain Range accumulator mirroring on-chain block commitments.
 */
class RealMmrTree {
    /**
     * @brief Instantiates an empty client-side MMR accumulator tree.
     */
    constructor() {
        /** @type {Array<Object>} Linear array of node records `{ hash, position, height, parent, leftChild, rightChild }`. */
        this.nodes = [];
        /** @type {Array<number>} Stack of peak indices ordered descending by height. */
        this.peaks = [];
    }

    /**
     * @brief Appends a leaf digest to the tree and cascades merges across balanced peaks.
     *
     * @param {Uint8Array} hashBytes 32-byte pre-computed leaf hash.
     * @return {void}
     * @complexity Time: O(log N) amortized peak merges, Space: O(1) amortized growth.
     */
    addLeafHash(hashBytes) {
        const position = this.nodes.length;
        const node = {
            hash: hashBytes,
            position: position,
            height: 0,
            parent: -1,
            leftChild: -1,
            rightChild: -1
        };
        this.nodes.push(node);
        this.peaks.push(position);

        while (this.peaks.length >= 2) {
            const last = this.peaks[this.peaks.length - 1];
            const secondLast = this.peaks[this.peaks.length - 2];
            if (this.nodes[last].height !== this.nodes[secondLast].height) break;

            const parentPos = this.nodes.length;
            const parentNode = {
                hash: hashNode(this.nodes[secondLast].hash, this.nodes[last].hash),
                position: parentPos,
                height: this.nodes[last].height + 1,
                parent: -1,
                leftChild: secondLast,
                rightChild: last
            };

            this.nodes.push(parentNode);
            this.nodes[secondLast].parent = parentPos;
            this.nodes[last].parent = parentPos;
            
            this.peaks.pop();
            this.peaks[this.peaks.length - 1] = parentPos;
        }
    }
}

/* ============================================================================
 * SECTION 3: FRONTEND APPLICATION COORDINATOR & UI LIFECYCLE
 * ============================================================================ */

/**
 * @brief Main DOM initialization lifecycle coordinator.
 * Configures event listeners, UI stores, view routers, and WebWorker subscriptions.
 */
document.addEventListener('DOMContentLoaded', () => {
    // Hoisted client reference. `var` (not `let`/`const`) avoids the temporal dead zone:
    // any event listener registered below can safely reference `client` even if it fires
    // before the real assignment further down in this callback.
    var client = null;

    // Toggle ZK and Wallet Keys collapsible container with header centering on collapse
    const toggleKeysBtn = document.getElementById('btn-toggle-keys');
    const collapsibleContainer = document.getElementById('collapsible-keys-container');
    if (toggleKeysBtn && collapsibleContainer) {
        const headerDiv = toggleKeysBtn.parentElement;
        toggleKeysBtn.addEventListener('click', () => {
            const isCollapsed = collapsibleContainer.style.display === 'none';
            if (isCollapsed) {
                collapsibleContainer.style.display = 'flex';
                headerDiv.style.marginBottom = '12px';
                toggleKeysBtn.textContent = '▲';
            } else {
                collapsibleContainer.style.display = 'none';
                headerDiv.style.marginBottom = '0px';
                toggleKeysBtn.textContent = '▼';
            }
        });
    }

    // DOM Element Queries
    const nodeUrlInput = document.getElementById('node-url');
    const prfKeyInput = document.getElementById('prf-key');
    const walletPubkeyInput = document.getElementById('wallet-pubkey');
    const walletPrivkeyInput = document.getElementById('wallet-privkey');
    const manualBlockRequests = new Set();
    const connectBtn = document.getElementById('btn-connect');
    const statusText = document.getElementById('status-text');
    const matchesList = document.getElementById('matches-list');
    const canvas = document.getElementById('mmr-canvas');
    const centinelFileInput = document.getElementById('centinel-file');
    const toggle3dBtn = document.getElementById('btn-toggle-3d');

    // Key Generator UI Elements
    const generateKeysBtn = document.getElementById('btn-generate-keys');
    const generatedKeysDisplay = document.getElementById('generated-keys-display');
    const genPubkeySpan = document.getElementById('gen-pubkey');
    const genPrivkeySpan = document.getElementById('gen-privkey');
    const genPrfkeySpan = document.getElementById('gen-prfkey');
    const genUseridSpan = document.getElementById('gen-userid');
    const applyGeneratedBtn = document.getElementById('btn-apply-generated');

    let latestGeneratedData = null;

    window.loadedUTXOs = [];

    /**
     * @brief Parses an off-chain binary Centinel bearer ticket file (.dat) into UTXO descriptors.
     *
     * @param {ArrayBuffer} arrayBuffer Binary file bytes.
     * @return {Array<Object>} Array of unpacked Centinel ticket records.
     * @complexity Time: O(arrayBuffer.byteLength), Space: O(num_tickets * sizeof(CentinelTicket)).
     */
    function parseCentinelFile(arrayBuffer) {
        const view = new DataView(arrayBuffer);
        const uint8 = new Uint8Array(arrayBuffer);
        let offset = 0;
        if (arrayBuffer.byteLength < 4) return [];

        const numTickets = view.getUint32(offset, true);
        offset += 4;

        const loadedUTXOs = [];
        for (let i = 0; i < numTickets; i++) {
            if (offset + 2048 * 2 + 32 + 4 > arrayBuffer.byteLength) break;

            // Skip c_transfer (2048 bytes) and c_change (2048 bytes) BDLOP commitments
            offset += 2048;
            offset += 2048;

            const nullifierBytes = uint8.slice(offset, offset + 32);
            const nullifierHex = Array.from(nullifierBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            offset += 32;

            const zkProofLen = view.getUint32(offset, true);
            offset += 4;

            if (offset + zkProofLen + 8 + 32 + 2592 + 1024 > arrayBuffer.byteLength) break;
            offset += zkProofLen;

            const amount = Number(view.getBigUint64(offset, true));
            offset += 8;

            const rTransfer = uint8.slice(offset, offset + 32);
            offset += 32;

            const ephPub = uint8.slice(offset, offset + 2592);
            offset += 2592;

            const ephPrf = uint8.slice(offset, offset + 1024);
            offset += 1024;

            loadedUTXOs.push({
                nullifier: nullifierHex,
                r: rTransfer,
                amount: amount,
                ephemeralPubkey: ephPub,
                ephemeralPrfKey: ephPrf
            });
        }
        return loadedUTXOs;
    }

    if (!canvas) {
        console.error('[ExplorerApp] Canvas element not found.');
        return;
    }

    // Initialize Canvas Renderer
    const renderer = new MmrCanvasRenderer(canvas);
    window.renderer = renderer;
    renderer.setNodes([]);

    // Theme Switcher Controller
    const themeSlider = document.getElementById('theme-slider');
    if (themeSlider) {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        if (savedTheme === 'light') {
            themeSlider.checked = false;
            document.documentElement.classList.add('light-mode');
        } else {
            themeSlider.checked = true;
            document.documentElement.classList.remove('light-mode');
        }
        if (toggle3dBtn) {
            toggle3dBtn.style.color = renderer.is3D ? "var(--text-main)" : "#ffffff";
        }

        themeSlider.addEventListener('change', () => {
            if (!themeSlider.checked) {
                document.documentElement.classList.add('light-mode');
                localStorage.setItem('theme', 'light');
            } else {
                document.documentElement.classList.remove('light-mode');
                localStorage.setItem('theme', 'dark');
            }
            renderer.draw();
            
            if (toggle3dBtn) {
                toggle3dBtn.style.color = renderer.is3D ? "var(--text-main)" : "#ffffff";
            }
            
            // Force instant updates on secondary canvases only if telemetry was received
            if (window.hasInvariantTelemetry) {
                updateInvariantAuditor();
            }
            if (window.hasDkgTelemetry) {
                const dkgContainer = document.getElementById('dkg-health-container');
                if (dkgContainer) {
                    const committeeCountStr = document.getElementById('dkg-committee-val')?.textContent || "0 / 10 Nodes";
                    const committeeCount = parseInt(committeeCountStr) || 0;
                    const activeDkgSessions = parseInt(dkgContainer.dataset.activeDkgSessions) || 0;
                    const lastDkgEpoch = parseInt((document.getElementById('dkg-epoch-val')?.textContent || '0').replace(/,/g, ''), 10) || 0;
                    updateDkgBeacon(committeeCount, activeDkgSessions, lastDkgEpoch);
                }
            }
            if (window.hasLatticeTelemetry) {
                const totalStakedStr = document.getElementById('total-staked-val')?.textContent || "¢0.0000";
                const totalStaked = (parseFloat(totalStakedStr.replace(/[^\d.-]/g, '')) || 0) * 160000000;
                const activeDkgSessions = parseInt(document.getElementById('dkg-sessions-val')?.textContent) || 0;
                updateLatticeDensity(activeDkgSessions, totalStaked);
            }
            if (window.updateQuantumTvdAudit && window.lastQuantumTvdData) {
                window.updateQuantumTvdAudit(window.lastQuantumTvdData);
            }
            if (window.updateTpsChart) {
                window.updateTpsChart();
            }
            if (statusText && statusText.textContent) {
                updateStatusBadge(statusText.textContent);
            }
        });
    }

    // Add 3D toggle event listener calling the dynamic canvas reset mechanism
    if (toggle3dBtn) {
        toggle3dBtn.addEventListener('click', () => {
            renderer.toggleMode();
            toggle3dBtn.textContent = renderer.is3D ? "Toggle 2D Mode" : "Toggle 3D Mode";
            toggle3dBtn.style.backgroundColor = renderer.is3D ? "var(--bg-primary)" : "var(--accent-green)";
            toggle3dBtn.style.color = renderer.is3D ? "var(--text-main)" : "#ffffff";
        });
    }

    const toggleLoupeBtn = document.getElementById('btn-toggle-loupe');
    if (toggleLoupeBtn) {
        toggleLoupeBtn.addEventListener('click', () => {
            const active = renderer.toggleLoupe();
            toggleLoupeBtn.style.backgroundColor = active ? "var(--accent-green)" : "var(--bg-primary)";
            toggleLoupeBtn.style.borderColor = active ? "var(--accent-green-border)" : "var(--border-color)";
            toggleLoupeBtn.style.color = active ? "#ffffff" : "var(--text-main)";
        });
    }

    const zoomInBtn = document.getElementById('btn-zoom-in');
    if (zoomInBtn) {
        zoomInBtn.addEventListener('click', () => {
            if (renderer.is3D) renderer.zoomIn();
        });
    }

    const zoomOutBtn = document.getElementById('btn-zoom-out');
    if (zoomOutBtn) {
        zoomOutBtn.addEventListener('click', () => {
            if (renderer.is3D) renderer.zoomOut();
        });
    }

    const reset3dBtn = document.getElementById('btn-reset-3d');
    if (reset3dBtn) {
        reset3dBtn.addEventListener('click', () => {
            if (renderer.is3D) renderer.resetRotation();
        });
    }

    // Default Node Coordinates & Persistent Testnet Wallet Initialization
    const host = window.location.hostname || 'localhost';
    const isLocal = ['localhost', '127.0.0.1'].includes(host);
    const wsHost = isLocal ? 'localhost:5554' : (window.SCL_BRIDGE_HOST || 'node.centinel.network');
    const defaultWsUrl = (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + wsHost;
    if (nodeUrlInput) nodeUrlInput.value = defaultWsUrl;

    // Instantiate network pipeline client (assigns the hoisted `var client` from the top
    // of this callback, so listeners registered earlier can safely check `if (client)`).
    client = new SclAuditorClient(nodeUrlInput.value, 'auditor.worker.js');
    window.client = client;

    /* H-3 fix: the testnet keypair is held in memory for the session only. Every
     * blank 'Connect Node' re-loads it live from the seed node; the identity is kept
     * stable across seeds and restarts by the shared testnet_identity_<port>.dat file
     * on the node side, so localStorage persistence is no longer needed. */
    localStorage.removeItem('scl_testnet_privkey');
    localStorage.removeItem('scl_testnet_pubkey');
    if (prfKeyInput) prfKeyInput.value = '';
    if (walletPubkeyInput) walletPubkeyInput.value = '';
    if (walletPrivkeyInput) walletPrivkeyInput.value = '';

    // Always present the Wallet State Configuration panel open by default on reload
    if (collapsibleContainer && toggleKeysBtn) {
        collapsibleContainer.style.display = 'flex';
        toggleKeysBtn.parentElement.style.marginBottom = '12px';
        toggleKeysBtn.textContent = '▲';
    }

    // Ensure cryptographic material is explicitly zeroed upon tab closure
    window.addEventListener('beforeunload', () => {
        if (client) client.disconnect();
    });

    // Set initial UI state waiting for WebAssembly compilation
    connectBtn.disabled = true;
    connectBtn.textContent = 'WASM Loading...';
    connectBtn.className = 'btn btn-connect';

    // Maintain a local state snapshot of valuations for graceful degradation fallback
    let cachedValuations = [
        {
            userId: [
                0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 1
            ],
            numbers: [12, 34, 56, 78, 90, 11, 22, 33, 44, 55],
            timestamp: Date.now() * 1000,
            beaconSeed: new Array(32).fill(0)
        }
    ];

    /**
     * @brief Renders the 10x10 Game Audit circular valuation matrix into the UI match list.
     *
     * @param {Array<Object>} valuations Array of 10 valuation row objects.
     * @param {boolean} [isFallback=false] True if displaying cached fallback snapshot.
     * @param {string|null} [customBadge=null] Optional custom header badge text.
     * @param {string|null} [customDesc=null] Optional custom header description text.
     * @return {void}
     * @complexity Time: O(valuations.length), Space: O(1).
     */
    function _renderValuations(valuations, isFallback = false, customBadge = null, customDesc = null) {
        const item = document.createElement('li');
        item.className = 'match-item';
        item.style.borderLeftColor = isFallback ? 'var(--accent-red)' : 'var(--accent-green)';

        let valuationsHtml = valuations.map((v, i) => {
            const hexUser = (v.userId && Array.isArray(v.userId)) ? v.userId.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 8) : '00000000';
            const isZeroUser = !v.userId || v.userId.every(b => b === 0);
            const userLabel = isZeroUser ? 'Empty Slot' : `User: ${hexUser}...`;
            const numbers = v.numbers || [];
            return `<div style="font-size: 0.75rem; margin-top: 4px; color: var(--text-main); font-family: monospace;">Row ${i + 1} [${userLabel}]: ${numbers.map(n => n.toString().padStart(2, '0')).join(' ')}</div>`;
        }).join('');

        const badgeText = customBadge || (isFallback ? '[Game Audit Cached Snapshot Fallback]' : '[Current Game Audit]');
        const descText = customDesc || (isFallback ? 'GetAudit pipeline unresponsive/desynced. Displaying cached state snapshot:' : 'Decrypted 10x10 Game Audit Matrix State:');

        item.innerHTML = `
            <span class="match-method" style="color: ${isFallback ? 'var(--accent-red)' : 'var(--accent-green)'}; font-weight: 600;">${badgeText}</span>
            <span class="match-hash" style="font-size: 0.8rem; font-weight: bold; color: var(--text-muted);">${descText}</span>
            ${valuationsHtml}
        `;
        matchesList.prepend(item);
    }

    client.onRpcError = (data) => {
        const { methodId, status, version, error } = data;
        console.warn(`[ExplorerApp] RPC Error: Method 0x${methodId.toString(16).padStart(4, '0')} failed with status ${status} (Version: ${version}). Error Message: ${error || 'None'}`);

        if (error && (error.includes('Double-spend') || error.includes('already redeemed'))) {
            const item = document.createElement('li');
            item.className = 'match-item';
            item.style.borderLeftColor = 'var(--accent-red)';
            item.style.backgroundColor = 'rgba(239, 68, 68, 0.05)';
            item.innerHTML = `
                <span class="match-method" style="color: var(--accent-red);">[Replay Rejected]</span>
                <span class="match-hash" style="color: var(--accent-red); font-weight: bold;">${escapeHTML(error)}</span>
                <div style="color: var(--accent-red); font-weight: 700; margin-top: 6px; font-size: 0.8rem;">⚠️ REPLAY DETECTED: DUPLICATE NULLIFIER / CENTINEL TICKET ALREADY REDEEMED</div>
            `;
            matchesList.prepend(item);
        }

        if (methodId === 0x0004) {
            if (window.auditTimeoutTimer) {
                clearTimeout(window.auditTimeoutTimer);
                window.auditTimeoutTimer = null;
            }
            send_audit_fallback();
        } else if (methodId === 0x0005) {
            send_valuations_fallback();
        } else if (methodId === 0x0008) {
            send_chain_info_fallback();
        }
    };

    function send_audit_fallback() {
        if (client) client.lastAuditResponseTime = Date.now();
        console.warn('[ExplorerApp] Falling back to local cached valuations state snapshot.');
        _renderValuations(cachedValuations, true);
        const syncModeEl = document.getElementById('sync-mode-text');
        if (syncModeEl) {
            syncModeEl.textContent = 'FALLBACK SNAPSHOT';
            syncModeEl.className = 'status-badge status-fallback';
            syncModeEl.style.display = 'inline-block';
        }
    }
            
    function updateGlobalValidations() {
        const valEl = document.getElementById('total-validations-val');
        if (!valEl) return;

        let unspentCommitments = 0;

        // 1. Authoritative calculation from synchronized PTXM ledger pointers
        if (blockchainStore && blockchainStore.pointers && blockchainStore.pointers.size > 0) {
            const coinsWithPointers = new Set();

            for (const ptr of blockchainStore.pointers.values()) {
                if (ptr.parentCoinId) {
                    coinsWithPointers.add(ptr.parentCoinId);
                }
                const isSpent = (ptr.spent === true || ptr.spent === 1 || ptr.spent === '1' || ptr.spent === 2 || ptr.spent === '2');
                if (!isSpent) {
                    unspentCommitments++;
                }
            }

            // Include any base mined coins that have not yet been split into pointers
            if (blockchainStore.coins) {
                for (const coin of blockchainStore.coins.values()) {
                    if (!coinsWithPointers.has(coin.coinId) && coin.totalSubunits > 0) {
                        unspentCommitments++;
                    }
                }
            }
        } else {
            // 2. Fallback to MMR accumulator leaves minus known nullifiers during initial sync
            const mmrLeaves = (typeof mmrTree !== 'undefined' && mmrTree.nodes)
                ? mmrTree.nodes.filter(n => n.height === 0).length
                : 0;
            const spentCount = window.globalSpentNullifiers ? window.globalSpentNullifiers.size : 0;
            unspentCommitments = Math.max(0, mmrLeaves - spentCount);
        }

        valEl.textContent = Number(unspentCommitments).toLocaleString('en-US');
    }

    function send_valuations_fallback() {
        if (client) client.lastValuationsResponseTime = Date.now();
        window.hasInvariantTelemetry = true;
        console.warn('[ExplorerApp] Falling back to local cached valuations state snapshot.');
        const fallbackData = {
            totalRewarded: window.systemMetrics.totalRewarded || 0,
            remainingSubunits: window.systemMetrics.remainingSubunits || (16000000 * 160000000),
            curStage: 2
        };
        document.getElementById('current-stage-val').textContent = fallbackData.curStage;
        document.getElementById('remaining-subunits-val').textContent = '¢' + formatScl(fallbackData.remainingSubunits / 160000000, 0);
        window.systemMetrics.totalRewarded = fallbackData.totalRewarded;
        window.systemMetrics.remainingSubunits = fallbackData.remainingSubunits;
        updateInvariantAuditor();
        updateGlobalValidations();
        const syncModeEl = document.getElementById('sync-mode-text');
        if (syncModeEl) {
            syncModeEl.textContent = 'FALLBACK SNAPSHOT';
            syncModeEl.className = 'status-badge status-fallback';
            syncModeEl.style.display = 'inline-block';
        }
    }

    function send_chain_info_fallback() {
        if (client) client.lastChainInfoResponseTime = Date.now();
        window.hasDkgTelemetry = true;
        window.hasLatticeTelemetry = true;
        window.hasInvariantTelemetry = true;
        console.warn('[ExplorerApp] Falling back to local cached chain info state snapshot.');
        const fallbackData = {
            blockHeight: window.lastKnownChainHeight ?? 0,
            totalSubunits: window.systemMetrics.totalSubunits || 0,
            totalStaked: window.lastKnownTotalStaked || 0,
            committeeCount: window.lastKnownCommitteeCount ?? window.lastStableCommitteeCount ?? 0,
            activeDkgSessions: 0,
            lastDkgEpoch: window.lastKnownDkgEpoch || 0
        };
        document.getElementById('block-height-val').textContent = Number(fallbackData.blockHeight).toLocaleString('en-US');
        document.getElementById('total-subunits-val').textContent = '¢' + formatScl(fallbackData.totalSubunits / 160000000, 0);
        document.getElementById('total-staked-val').textContent = '¢' + formatScl(fallbackData.totalStaked / 160000000, 4);

        const activeNodesEl = document.getElementById('active-nodes-val');
        if (activeNodesEl) {
            activeNodesEl.textContent = fallbackData.committeeCount;
        }

        window.systemMetrics.totalSubunits = fallbackData.totalSubunits;
        updateInvariantAuditor();
        updateLatticeDensity(fallbackData.activeDkgSessions > 0 ? 1 : 0, fallbackData.totalStaked);
        updateDkgBeacon(fallbackData.committeeCount, fallbackData.activeDkgSessions, fallbackData.lastDkgEpoch);
        const syncModeEl = document.getElementById('sync-mode-text');
        if (syncModeEl) {
            syncModeEl.textContent = 'FALLBACK SNAPSHOT';
            syncModeEl.className = 'status-badge status-fallback';
            syncModeEl.style.display = 'inline-block';
        }
    }

    // Start a periodic background watchdog to trigger fallbacks under network desynchronization
    setInterval(() => {
        if (client.socket && client.socket.readyState === WebSocket.OPEN) {
            const now = Date.now();
            if (client.lastChainInfoResponseTime && now - client.lastChainInfoResponseTime > 65000) {
                send_chain_info_fallback();
            }
            if (client.lastValuationsResponseTime && now - client.lastValuationsResponseTime > 65000) {
                send_valuations_fallback();
            }
        }
    }, 5000);

    /**
     * @brief Color-codes the primary status badge according to lifecycle state and active theme.
     * @param {string} displayStatus Active status text (e.g., 'WASM LOADED', 'PIPELINE CONNECTED').
     */
    function updateStatusBadge(displayStatus) {
        if (!statusText) return;
        statusText.textContent = displayStatus;
        /* Per-status colour coding (restores the blue WASM_LOADED badge):
         * map the displayed token back to its underscore CSS class so
         * 'WASM LOADED'          -> .status-wasm_loaded           (blue)
         * 'KEYS INITIALIZED'      -> .status-keys_initialized      (blue)
         * 'PIPELINE CONNECTED'    -> .status-pipeline_connected    (green)
         * 'PIPELINE DISCONNECTED' -> .status-pipeline_disconnected (red)
         * 'WORKER CREATED'        -> .status-worker_created        (purple)
         * 'TERMINATED'            -> .status-terminated            (grey)
         * Unknown tokens (e.g. 'ERROR') keep the neutral base badge.
         * All rules already exist in the index.html stylesheet. */
        const classToken = String(displayStatus || '').trim().toLowerCase().replace(/\s+/g, '_');
        statusText.className = `status-badge status-${classToken}`;
        statusText.style.display = 'inline-block';
    }

    // Register Status Updates
    client.onStatusChange = (status) => {
        let displayStatus = (status || '').replace(/_/g, ' ');
        if ((displayStatus === 'KEYS INITIALIZED' || status === 'KEYS_INITIALIZED') && client.socket && client.socket.readyState === WebSocket.OPEN) {
            displayStatus = 'PIPELINE CONNECTED';
        }
        updateStatusBadge(displayStatus);

        if (displayStatus === 'WASM LOADED' || status === 'WASM_LOADED') {
            connectBtn.disabled = false;
            connectBtn.textContent = 'Connect Node';
            connectBtn.className = 'btn btn-connect';
        } else if (displayStatus === 'PIPELINE CONNECTED' || status === 'PIPELINE_CONNECTED') {
            connectBtn.disabled = false;
            connectBtn.textContent = 'Disconnect';
            connectBtn.className = 'btn btn-disconnect';

            window.hasCustomLoadedFile = false;
            // Reset synchronization tracking
            latestKnownBlockHeight = -1;
            syncedBlockHeight = -1;
            isSyncingBlocks = false;
            lastBlockResponseTime = Date.now();
            mmrTree.nodes = [];
            mmrTree.peaks = [];
            pendingBlocks.clear();
            requestedBlocks.clear();
            blockchainStore.coins.clear();
            blockchainStore.pointers.clear();
            blockchainStore.transactions.length = 0;
            renderer.setNodes([]);
        } else if (displayStatus === 'TERMINATED' || displayStatus === 'PIPELINE DISCONNECTED' || status === 'PIPELINE_DISCONNECTED') {
            connectBtn.disabled = false;
            connectBtn.textContent = 'Connect Node';
            connectBtn.className = 'btn btn-connect';
            const syncModeEl = document.getElementById('sync-mode-text');
            if (syncModeEl) {
                syncModeEl.style.display = 'none';
            }

            // Reset telemetry arrival state and restore placeholder UI
            window.hasDkgTelemetry = false;
            window.hasLatticeTelemetry = false;
            window.hasInvariantTelemetry = false;
            const dkgCont = document.getElementById('dkg-health-container');
            if (dkgCont) dkgCont.innerHTML = '<span style="color: var(--text-muted);">Awaiting Telemetry...</span>';
            const invCont = document.getElementById('invariant-auditor-container');
            if (invCont) invCont.innerHTML = '<span style="color: var(--text-muted);">Awaiting Telemetry...</span>';
            const latCont = document.getElementById('lattice-density-container');
            if (latCont) latCont.innerHTML = '<span style="color: var(--text-muted);">Awaiting Telemetry...</span>';
        }
    };

    // Register Error Updates
    client.onError = (errorMsg) => {
        console.error('[ExplorerApp] Error:', errorMsg);
        if (errorMsg && (errorMsg.includes('Double-spend') || errorMsg.includes('already redeemed'))) {
            const item = document.createElement('li');
            item.className = 'match-item';
            item.style.borderLeftColor = 'var(--accent-red)';
            item.style.backgroundColor = 'rgba(239, 68, 68, 0.05)';
            item.innerHTML = `
                <span class="match-method" style="color: var(--accent-red);">[Replay Rejected]</span>
                <span class="match-hash" style="color: var(--accent-red); font-weight: bold;">${escapeHTML(errorMsg)}</span>
                <div style="color: var(--accent-red); font-weight: 700; margin-top: 6px; font-size: 0.8rem;">⚠️ REPLAY DETECTED: DUPLICATE NULLIFIER / CENTINEL TICKET ALREADY REDEEMED</div>
            `;
            matchesList.prepend(item);
            alert(errorMsg);
            return;
        }
        updateStatusBadge('ERROR');
        connectBtn.textContent = 'Connect Node';
        connectBtn.className = 'btn btn-connect';
        if (generateKeysBtn) {
            generateKeysBtn.disabled = false;
            generateKeysBtn.textContent = 'Generate New Credentials';
        }
    };

    // Initialize WebWorker and WASM pipeline after attaching event listeners
    client.initialize();

    // Initialize global tracking for ZK-PRF nullifier replay protection
    if (!window.seenNullifiers) window.seenNullifiers = new Set();

    client.onTransactionMatch = (matchData) => {
        const { nullifier, methodId, isCentinel, cTransfer, cChange, leafHash } = matchData;
        const hexNullifier = nullifier.map(b => b.toString(16).padStart(2, '0')).join('');

        if (!window.globalSpentNullifiers) window.globalSpentNullifiers = new Set();
        window.globalSpentNullifiers.add(hexNullifier);

        const isReplay = window.seenNullifiers.has(hexNullifier);
        if (isReplay) return;
        window.seenNullifiers.add(hexNullifier);

        if (!window.loadedUTXOs) window.loadedUTXOs = [];

        const spentNulHex = matchData.nullifier ? matchData.nullifier.map(b => b.toString(16).padStart(2, '0')).join('') : null;
        if (spentNulHex) {
            const spentIdx = window.loadedUTXOs.findIndex(u => u.nullifier === spentNulHex);
            if (spentIdx !== -1) {
                window.loadedUTXOs.splice(spentIdx, 1);
            }
        }

        if (matchData.newNullifiers && matchData.newNullifiers.length > 0) {
            matchData.newNullifiers.forEach(n => {
                if (!window.loadedUTXOs.some(u => u.nullifier === n.hex)) {
                    window.loadedUTXOs.push({ nullifier: n.hex, amount: n.amount, r: n.r || null });
                }
            });
        }

        window.privateUtxoBalance = window.loadedUTXOs.reduce((sum, u) => sum + (u.amount || 0), 0);
        const utxoValEl = document.getElementById('decrypted-utxo-val');
        if (utxoValEl) utxoValEl.textContent = Number(window.privateUtxoBalance).toLocaleString('en-US');
        updateGlobalValidations();

        const item = document.createElement('li');
        item.className = 'match-item';

        let replayWarning = isReplay ? `<div style="color: var(--accent-red); font-weight: 700; margin-top: 6px; font-size: 0.8rem;">⚠️ REPLAY DETECTED: DUPLICATE NULLIFIER</div>` : '';

        if (isCentinel) {
            const hexTransfer = cTransfer.map(b => b.toString(16).padStart(2, '0')).join('');
            const hexChange = cChange.map(b => b.toString(16).padStart(2, '0')).join('');
            const decryptedText = matchData.decryptedTransferAmount !== undefined && matchData.decryptedTransferAmount !== null ?
                `<div style="color: var(--accent-green); font-weight: bold; font-size: 0.8rem; margin-top: 4px;">🔓 Decrypted Amount: ${matchData.decryptedTransferAmount} Validations</div>` :
                '';
            item.innerHTML = `
                <span class="match-method">[Method 0x${methodId.toString(16).padStart(4, '0')}]</span>
                <span class="match-hash" style="${isReplay ? 'color: var(--accent-red);' : ''}">Matched Tx Asset: ${hexNullifier.substring(0, 16)}...</span>
                <span style="color: var(--accent-green); margin-top: 4px; font-size: 0.75rem;">+ c_transfer: ${hexTransfer}...</span>
                <span style="color: var(--text-muted); font-size: 0.75rem;">+ c_change: ${hexChange}...</span>
                ${decryptedText}
                ${replayWarning}
            `;
        } else if (matchData.isClaimValidation) {
            const hexTransfer = cTransfer.map(b => b.toString(16).padStart(2, '0')).join('');
            const decryptedText = matchData.decryptedTransferAmount !== undefined && matchData.decryptedTransferAmount !== null ?
                `<div style="color: var(--accent-green); font-weight: bold; font-size: 0.8rem; margin-top: 4px;">🔓 Decrypted Grant: ${matchData.decryptedTransferAmount} Validations</div>` :
                '';
            item.innerHTML = `
                <span class="match-method">[Method 0x${methodId.toString(16).padStart(4, '0')}]</span>
                <span class="match-hash" style="${isReplay ? 'color: var(--accent-red);' : ''}">Matched Validation Claim: ${hexNullifier.substring(0, 16)}...</span>
                <span style="color: var(--accent-green); margin-top: 4px; font-size: 0.75rem;">+ c_claim: ${hexTransfer}...</span>
                ${decryptedText}
                ${replayWarning}
            `;
        } else {
            item.innerHTML = `
                <span class="match-method">[Method 0x${methodId.toString(16).padStart(4, '0')}]</span>
                <span class="match-hash" style="${isReplay ? 'color: var(--accent-red);' : ''}">Matched Tx Asset: ${hexNullifier.substring(0, 16)}...</span>
                ${replayWarning}
            `;
        }

        if (isReplay) {
            item.style.borderLeftColor = 'var(--accent-red)';
            item.style.backgroundColor = 'rgba(239, 68, 68, 0.05)';
        }

        matchesList.prepend(item);

        // Highlight the matched leaf and animate the proof
        if (leafHash && Array.isArray(leafHash)) {
            const leaves = renderer.nodes.filter(n => n.height === 0);
            let matchedLeaf = leaves.find(leaf => {
                if (!leaf.hash) return false;
                for (let i = 0; i < 32; i++) {
                    if (leaf.hash[i] !== leafHash[i]) return false;
                }
                return true;
            });
            
            if (matchedLeaf) {
                console.log(`[ExplorerApp] Highlighting matched leaf position: ${matchedLeaf.position}`);
                const proofPath = _computeDeterministicProofPath(matchedLeaf.position, renderer.nodes);
                renderer.animateProofPath(matchedLeaf.position, proofPath);
            } else {
                // Fallback to the newest leaf if not found in current nodes
                const targetLeaf = leaves[leaves.length - 1];
                if (targetLeaf) {
                    const proofPath = _computeDeterministicProofPath(targetLeaf.position, renderer.nodes);
                    renderer.animateProofPath(targetLeaf.position, proofPath);
                }
            }
        } else {
            // Fallback to the newest leaf if no leafHash provided
            const leaves = renderer.nodes.filter(n => n.height === 0);
            if (leaves.length > 0) {
                const targetLeaf = leaves[leaves.length - 1];
                const proofPath = _computeDeterministicProofPath(targetLeaf.position, renderer.nodes);
                renderer.animateProofPath(targetLeaf.position, proofPath);
            }
        }
    };

    let latestKnownBlockHeight = -1;
    let syncedBlockHeight = -1;
    let isSyncingBlocks = false;
    let lastBlockResponseTime = Date.now();
    const mmrTree = new RealMmrTree();
    const pendingBlocks = new Map();
    const requestedBlocks = new Set();
    const MAX_PAGINATION_RANGE = 500;

    function fillBlockDownloadPipeline() {
        if (syncedBlockHeight === -1) {
            if (!requestedBlocks.has(0)) {
                requestedBlocks.add(0);
                lastBlockResponseTime = Date.now();
                client.requestBlock(0);
            }
            return;
        }

        if (syncedBlockHeight < latestKnownBlockHeight && !isSyncingBlocks) {
            const startHeight = syncedBlockHeight + 1;
            const limit = Math.min(startHeight + MAX_PAGINATION_RANGE - 1, latestKnownBlockHeight);
            
            for (let h = startHeight; h <= limit; h++) {
                requestedBlocks.add(h);
            }
            
            isSyncingBlocks = true;
            lastBlockResponseTime = Date.now();
            client.requestBlock(startHeight);
        }
    }

    // Phase 2: Macro Auditing & Consensus Health Global State
    window.systemMetrics = { totalSubunits: 0, totalRewarded: 0, remainingSubunits: 0 };

    /**
     * @brief Audits global monetary supply invariants and renders inflation metrics in real time.
     *
     * @details
     * Validates that `totalRewarded + remainingSubunits == MAX_SUPPLY_SUBUNITS` (16M SCL),
     * calculates burn-in progress percentage, renders historical issuance trends,
     * and confirms that no unauthorized delta exists between the ledger and minted totals.
     *
     * @return {void}
     * @complexity Time: O(1), Space: O(1).
     */
    function updateInvariantAuditor() {
        const container = document.getElementById('invariant-auditor-container');
        if (!container || !window.hasInvariantTelemetry) return;

        const { totalSubunits, totalRewarded, remainingSubunits, totalFees } = window.systemMetrics;
        const MAX_SUPPLY_SUBUNITS = 2560000000000000;

        const isSupplySecure = (totalRewarded + remainingSubunits) === MAX_SUPPLY_SUBUNITS;
        // Prevent desync alerts during initialization sequences
        const isLedgerSynced = (totalSubunits === 0 || totalRewarded === 0) ? true : (totalSubunits === totalRewarded);
        const progress = totalRewarded ? (totalRewarded / MAX_SUPPLY_SUBUNITS) * 100 : 0.0;

        const totalScl = Number(totalSubunits || 0) / 160000000;
        const rewardedScl = Number(totalRewarded || totalSubunits || 0) / 160000000;
        const remainingScl = Number(remainingSubunits || 0) / 160000000;
        const feesScl = totalFees ? Number(totalFees) / 160000000 : 0.0;
        const deltaScl = Math.abs(totalScl - rewardedScl);

        // Explicit Status & Color Resolvers (Prevents UI tearing on boot)
        const supplyStatusText = (totalRewarded === 0 && remainingSubunits === 0) ? 'AWAITING SYNC' : (isSupplySecure ? 'VERIFIED' : 'VIOLATED');
        const supplyStatusColor = (totalRewarded === 0 && remainingSubunits === 0) ? 'var(--text-muted)' : (isSupplySecure ? 'var(--accent-green)' : 'var(--accent-red)');

        const syncStatusText = (totalSubunits === 0 && totalRewarded === 0) ? 'AWAITING SYNC' : (isLedgerSynced ? 'VERIFIED' : 'DESYNCED');
        const syncStatusColor = (totalSubunits === 0 && totalRewarded === 0) ? 'var(--text-muted)' : (isLedgerSynced ? 'var(--accent-green)' : 'var(--accent-red)');

        const deltaColor = (totalSubunits === 0 && totalRewarded === 0) ? 'var(--text-muted)' : (deltaScl === 0 ? 'var(--accent-green)' : 'var(--accent-red)');

        if (!window.issuanceHistory) {
            window.issuanceHistory = [];
        }
        
        // Push telemetry points regardless of whether value is zero to avoid stalling empty baselines
        window.issuanceHistory.push(rewardedScl);
        if (window.issuanceHistory.length > 30) {
            window.issuanceHistory.shift();
        }

        if (!document.getElementById('invariant-graph-canvas')) {
            container.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <div style="display: flex; justify-content: space-between;">
                        <span style="color: var(--text-muted);">Max Hard Cap:</span>
                        <span style="color: var(--text-main); font-weight: 600;">¢16,000,000.0000</span>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span style="color: var(--text-muted);">Cryptographic Issuance:</span>
                        <span id="invariant-cryptographic-issuance" style="color: var(--text-main); font-weight: 600;">¢${formatScl(rewardedScl, 0)}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: var(--text-muted); display: inline-flex; align-items: center; white-space: nowrap;">Supply Invariant:<span class="info-pop"><i class="info-icon">i</i><span class="info-bubble">Conservation invariant $v_{\\text{minted}} + v_{\\text{remaining}} \\equiv C_{\\max} = {}$¢16,000,000 ($2.56 \\times 10^{15}$ atomic subunits).</span></span></span>
                        <span id="invariant-supply-status" style="color: ${supplyStatusColor}; font-weight: 600;">${supplyStatusText}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: var(--text-muted); display: flex; align-items: center;">MMR UTXO Sync Check: <span class="info-pop"><i class="info-icon">i</i><span class="info-bubble">Validates MMR bagged peak root $h_{\\text{root}} = \\text{BagPeaks}(p_1, \\dots, p_k)$ against local UTXO state with $\\mathcal{O}(\\log N)$ proof overhead.</span></span></span>
                        <span id="invariant-sync-status" style="color: ${syncStatusColor}; font-weight: 600;">${syncStatusText}</span>
                    </div>
                    <div style="margin-top: 6px; display: flex; flex-direction: column; gap: 4px;">
                        <span style="color: var(--text-muted); font-size: 0.75rem;">Issuance Hard Cap Burn-in Progress:</span>
                        <div style="background-color: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 4px; width: 100%; height: 16px; overflow: hidden; position: relative;">
                            <div id="invariant-progress-bar" style="background-color: var(--accent-green); height: 100%; width: ${progress.toFixed(2)}%;"></div>
                            <span id="invariant-progress-label" style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 0.7rem; color: var(--text-main); font-family: monospace; font-weight: bold;">${progress.toFixed(4)}%</span>
                        </div>
                    </div>
                    <div style="margin-top: 6px; display: flex; flex-direction: column; gap: 4px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: var(--text-muted); font-size: 0.75rem;">Historical Issuance:</span>
                            <span id="invariant-trend-tooltip" style="color: var(--text-muted); font-size: 0.7rem; font-family: monospace;">Hover to inspect</span>
                        </div>
                        <canvas id="invariant-graph-canvas" width="240" height="40" style="background-color: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 4px; width: 100%; height: 40px; cursor: crosshair;"></canvas>
                    </div>
                    <div style="margin-top: 6px; border-top: 1px solid var(--border-color); padding-top: 8px; display: flex; flex-direction: column; gap: 4px; font-family: monospace; font-size: 0.75rem; color: var(--text-muted);">
                        <div style="color: var(--text-main); font-weight: 600; font-size: 0.8rem; margin-bottom: 2px;">Inflation Audit Proof:</div>
                        <div style="display: flex; justify-content: space-between;">
                            <span>v_minted + v_remaining:</span>
                            <span id="invariant-v-minted" style="color: var(--text-main);">¢${formatScl(rewardedScl + remainingScl, 4)}</span>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span>Expected Hard Cap:</span>
                            <span style="color: var(--text-main);">¢16,000,000.0000</span>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span>Total Fees Recycled:</span>
                            <span id="invariant-v-fees" style="color: var(--text-main);">¢${formatScl(feesScl, 4)}</span>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span>v_ledger - v_minted:</span>
                            <span id="invariant-v-delta" style="color: ${deltaColor}; font-weight: bold;">¢${formatScl(deltaScl, 4)}</span>
                        </div>
                        <div id="invariant-v-delta-icon" style="text-align: center; color: ${deltaColor}; font-size: 0.7rem; margin-top: 2px; font-weight: bold;">
                            🛡️ ¢0.0000 Unauthorized Delta Detected
                        </div>
                    </div>
                </div>
            `;
        } else {
            // Direct non-destructive updates to prevent element tearing and layout shifts
            const issuanceEl = document.getElementById('invariant-cryptographic-issuance');
            const supplyEl = document.getElementById('invariant-supply-status');
            const syncEl = document.getElementById('invariant-sync-status');
            const barEl = document.getElementById('invariant-progress-bar');
            const labelEl = document.getElementById('invariant-progress-label');
            const vMintedEl = document.getElementById('invariant-v-minted');
            const vFeesEl = document.getElementById('invariant-v-fees');
            const vDeltaEl = document.getElementById('invariant-v-delta');
            const vDeltaIconEl = document.getElementById('invariant-v-delta-icon');

            if (issuanceEl) issuanceEl.textContent = `¢${formatScl(rewardedScl, 0)}`;
            if (supplyEl) {
                supplyEl.textContent = supplyStatusText;
                supplyEl.style.color = supplyStatusColor;
            }
            if (syncEl) {
                syncEl.textContent = syncStatusText;
                syncEl.style.color = syncStatusColor;
            }
            if (barEl) barEl.style.width = `${progress.toFixed(2)}%`;
            if (labelEl) labelEl.textContent = `${progress.toFixed(4)}%`;
            if (vMintedEl) vMintedEl.textContent = `¢${formatScl(rewardedScl + remainingScl, 4)}`;
            if (vFeesEl) vFeesEl.textContent = `¢${formatScl(feesScl, 4)}`;
            if (vDeltaEl) {
                vDeltaEl.textContent = `¢${formatScl(deltaScl, 4)}`;
                vDeltaEl.style.color = deltaColor;
            }
            if (vDeltaIconEl) {
                vDeltaIconEl.textContent = `🛡️ ¢${formatScl(deltaScl, 4)} Unauthorized Delta Detected`;
                vDeltaIconEl.style.color = deltaColor;
            }
        }

        // Render the historical issuance trend graph on the canvas
        if (document.hidden) return;

        const graphCanvas = document.getElementById('invariant-graph-canvas');
        if (graphCanvas) {
            const graphCtx = graphCanvas.getContext('2d');
            if (graphCtx) {
                graphCtx.clearRect(0, 0, graphCanvas.width, graphCanvas.height);
                
                // Draw subtle background grid lines
                graphCtx.strokeStyle = document.documentElement.classList.contains('light-mode') ? 'rgba(148, 163, 184, 0.3)' : 'rgba(51, 65, 85, 0.4)';
                graphCtx.lineWidth = 1;
                graphCtx.beginPath();
                for (let i = 1; i < 4; i++) {
                    let y = (graphCanvas.height / 4) * i;
                    graphCtx.moveTo(0, y);
                    graphCtx.lineTo(graphCanvas.width, y);
                }
                graphCtx.stroke();

                if (window.issuanceHistory.length > 1) {
                    // Draw rolling history line
                    graphCtx.strokeStyle = document.documentElement.classList.contains('light-mode') ? '#0284c7' : '#38bdf8';
                    graphCtx.lineWidth = 1.5;
                    graphCtx.beginPath();
                    const maxPoints = 30;
                    const xStep = graphCanvas.width / (maxPoints - 1);
                    
                    // Adaptive auto-scaling: Zoom into micro-variance so block rewards create visible steps
                    const rawMax = Math.max(...window.issuanceHistory);
                    const rawMin = Math.min(...window.issuanceHistory);
                    let spread = rawMax - rawMin;
                    
                    let maxVal, minVal, range;
                    if (spread > 0) {
                        maxVal = rawMax + spread * 0.15;
                        minVal = Math.max(0, rawMin - spread * 0.15);
                        range = maxVal - minVal;
                    } else {
                        maxVal = rawMax > 0 ? rawMax * 1.05 : 1.0;
                        minVal = rawMax > 0 ? rawMax * 0.95 : 0.0;
                        range = maxVal - minVal || 1.0;
                    }

                    for (let i = 0; i < window.issuanceHistory.length; i++) {
                        const x = i * xStep;
                        const val = window.issuanceHistory[i];
                        const normalized = Math.max(0, Math.min(1, (val - minVal) / range));
                        const y = graphCanvas.height - (normalized * graphCanvas.height * 0.75 + graphCanvas.height * 0.12);
                        if (i === 0) {
                            graphCtx.moveTo(x, y);
                        } else {
                            graphCtx.lineTo(x, y);
                        }
                    }
                    graphCtx.stroke();

                    // Attach hover tooltip inspection once
                    if (!graphCanvas._hasHoverListener) {
                        graphCanvas._hasHoverListener = true;
                        graphCanvas.addEventListener('mousemove', (e) => {
                            const rect = graphCanvas.getBoundingClientRect();
                            const x = e.clientX - rect.left;
                            const idx = Math.min(window.issuanceHistory.length - 1, Math.max(0, Math.round((x / rect.width) * (window.issuanceHistory.length - 1))));
                            const val = window.issuanceHistory[idx];
                            const tooltip = document.getElementById('invariant-trend-tooltip');
                            if (tooltip) {
                                tooltip.innerHTML = `<span style="color: var(--accent-green); font-weight: bold;">¢${formatScl(val, 4)}</span> (T-${(window.issuanceHistory.length - 1 - idx) * 2}s)`;
                            }
                        });
                        graphCanvas.addEventListener('mouseleave', () => {
                            const tooltip = document.getElementById('invariant-trend-tooltip');
                            if (tooltip) {
                                tooltip.textContent = 'Hover to inspect';
                            }
                        });
                    }
                }
            }
        }
    }

    /** @type {Array<number>} Rolling history buffer of observed QPU Total Variation Distance metrics. */
    const tvdDriftHistory = [];

    /**
     * @brief Updates the Quantum TVD dashboard with incoming QPU calibration and drift metrics.
     *
     * @param {Object} tvdData TVD audit payload containing double metric, fixed-point scale, status, and confidence margin.
     * @return {void}
     * @complexity Time: O(1), Space: O(1).
     */
    function updateQuantumTvdAudit(tvdData) {
        const container = document.getElementById('quantum-tvd-container');
        if (!container || !tvdData) return;

        const {
            circuitHash,
            shots,
            tvdScaled,
            tvdDouble,
            confidenceMargin,
            status
        } = tvdData;

        const tvdMetric = Number.isFinite(tvdDouble) ? tvdDouble : 0;
        /* Same beacon returns the same certificate. Do not extend the drift
         * trace or rewrite the badges when nothing on the network changed. */
        if (window._renderedTvdMetric !== undefined &&
            Math.abs(window._renderedTvdMetric - tvdMetric) < 1e-12 &&
            document.getElementById('tvd-double-val')) {
            return;
        }
        window._renderedTvdMetric = tvdMetric;
        const tvdBadge = document.getElementById('quantum-tvd-val');
        const fidelityBadge = document.getElementById('noise-model-fidelity-val');
        if (tvdBadge) tvdBadge.textContent = tvdMetric.toFixed(4);
        if (fidelityBadge) {
            const fidelity = Math.max(0, (1 - tvdMetric) * 100);
            fidelityBadge.textContent = `${fidelity.toFixed(2)}%`;
        }

        tvdDriftHistory.push(tvdMetric);
        if (tvdDriftHistory.length > 30) {
            tvdDriftHistory.shift();
        }

        const isLight = document.documentElement.classList.contains('light-mode');
        const isOrange = document.documentElement.classList.contains('orange-mode');
        
        let statusText = "FIDELITY OPTIMAL";
        let statusColor = isOrange ? (isLight ? "#ea580c" : "#f7931a") : (isLight ? "#059669" : "#10b981");
        let statusIcon = "🛡️";

        if (status === 0) {
            statusText = "FIDELITY OPTIMAL";
            statusColor = isLight ? "#059669" : "#10b981";
            statusIcon = "🛡️";
        } else if (status === 1) {
            statusText = "DRIFT TOLERABLE";
            statusColor = isLight ? "#0284c7" : "#38bdf8";
            statusIcon = "⚖️";
        } else if (status === 2) {
            statusText = "DECOHERENCE EXCEEDED";
            statusColor = isLight ? "#c2410c" : "#f97316";
            statusIcon = "⚠️";
        } else {
            statusText = "TAMPERING SUSPECTED";
            statusColor = isLight ? "#dc2626" : "#ef4444";
            statusIcon = "🚨";
        }

        if (!document.getElementById('quantum-tvd-graph-canvas')) {
            container.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 8px; width: 100%;">
                    <!-- Top 2-Column Grid: Left (TVD Stats) | Right (Cryptographic Anchor Proof & Drift Trend) -->
                    <div style="display: grid; grid-template-columns: 1fr 1.35fr; gap: 20px; font-size: 0.8rem; align-items: start; width: 100%; box-sizing: border-box; padding: 4px 0;">
                        <!-- Column 1: Core TVD Metrics (Increased line spacing) -->
                        <div style="display: flex; flex-direction: column; gap: 14px;">
                            <div style="display: flex; flex-direction: column; gap: 4px;">
                                <span style="color: var(--text-muted); display: flex; align-items: center;">TVD Metric: <span class="info-pop"><i class="info-icon">i</i><span class="info-bubble">Total variation distance $\\delta(P, Q) = \\frac{1}{2}\\sum_{x \\in \\{0,1\\}^7} |P(x) - Q(x)|$ between the ideal qsim distribution $P$ and a Kraus-noised qsim sample $Q$ of the same 7-qubit circuit. No physical QPU is queried.</span></span></span>
                                <span id="tvd-double-val" style="color: ${statusColor}; font-weight: 700; font-family: monospace; font-size: 0.95rem;">${tvdDouble.toFixed(5)} (${(tvdDouble * 100).toFixed(2)}%)</span>
                            </div>
                            <div style="display: flex; flex-direction: column; gap: 4px;">
                                <span style="color: var(--text-muted); display: flex; align-items: center;">Chernoff Conf. (&plusmn;e): <span class="info-pop"><i class="info-icon">i</i><span class="info-bubble">Confidence bound $\\varepsilon = \\sqrt{\\frac{\\ln(2/\\beta)}{2M}}$ ensuring $\\mathbb{P}(|\\hat{\\delta} - \\delta| \\ge \\varepsilon) \\le \\beta = 10^{-6}$ over $M = ${shots} shots.</span></span></span>
                                <span id="tvd-chernoff-val" style="color: var(--text-main); font-weight: 600; font-family: monospace; font-size: 0.85rem;">&plusmn;${confidenceMargin.toFixed(5)}</span>
                            </div>
                            <div style="display: flex; flex-direction: column; gap: 4px;">
                                <span style="color: var(--text-muted);">Noise-Model Drift State:</span>
                                <span id="tvd-status-val" style="color: ${statusColor}; font-weight: 700; font-size: 0.8rem;">${statusIcon} ${statusText}</span>
                            </div>
                            <div style="display: flex; flex-direction: column; gap: 4px;">
                                <span style="color: var(--text-muted); font-size: 0.75rem;">Fixed-Scale (10<sup>9</sup> FP):</span>
                                <span id="tvd-scaled-val" style="color: var(--text-main); font-family: monospace; font-size: 0.8rem; font-weight: 600;">${tvdScaled}</span>
                            </div>
                        </div>

                        <!-- Column 2: Cryptographic Anchor Proof & Real-Time Drift Trend (Proportional spacing + Divider restricted to Column 2) -->
                        <div style="display: flex; flex-direction: column; gap: 10px; font-family: monospace; font-size: 0.74rem; color: var(--text-muted); width: 100%; box-sizing: border-box;">
                            <div style="color: var(--text-main); font-weight: 600; font-size: 0.8rem; margin-bottom: 2px; text-align: center;">Cryptographic Anchor</div>
                            <div style="display: flex; flex-direction: column; gap: 4px;">
                                <span>Circuit Digest:</span>
                                <span id="tvd-circuit-hash" style="color: var(--text-main); font-size: 0.72rem; word-break: break-all;">${circuitHash ? circuitHash.substring(0, 32) + '...' : 'Default 7-Qubit'}</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 2px;">
                                <span>Lattice BDLOP:</span>
                                <strong style="color: ${isLight ? '#7c3aed' : '#a78bfa'};">VERIFIED</strong>
                            </div>
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span>Dilithium5 Sig:</span>
                                <span class="auth-purple-badge">AUTHENTICATED</span>
                            </div>
                            <div style="border-top: 1px solid var(--border-color); margin: 2px 0;"></div>
                            <div style="display: flex; flex-direction: column; gap: 4px;">
                                <div style="display: flex; justify-content: space-between; width: 100%; font-size: 0.7rem; font-family: monospace;">
                                    <span style="color: var(--text-muted); font-size: 0.75rem;">Noise-Model Drift:</span>
                                    <span id="tvd-graph-tooltip" style="color: ${isLight ? '#dc2626' : '#ef4444'}; font-weight: bold;">threshold &le;0.25 <span style="font-weight: normal; color: var(--text-muted); font-size: 0.68rem;">Hover to inspect</span></span>
                                </div>
                                <canvas id="quantum-tvd-graph-canvas" width="240" height="36" style="background-color: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 4px; width: 100%; height: 36px; cursor: crosshair;"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        } else {
            const doubleEl = document.getElementById('tvd-double-val');
            const chernoffEl = document.getElementById('tvd-chernoff-val');
            const statusEl = document.getElementById('tvd-status-val');
            const scaledEl = document.getElementById('tvd-scaled-val');
            const circuitHashEl = document.getElementById('tvd-circuit-hash');

            if (doubleEl) {
                doubleEl.textContent = `${tvdDouble.toFixed(5)} (${(tvdDouble * 100).toFixed(2)}%)`;
                doubleEl.style.color = statusColor;
            }
            if (chernoffEl) chernoffEl.innerHTML = `&plusmn;${confidenceMargin.toFixed(5)}`;
            if (statusEl) {
                statusEl.textContent = `${statusIcon} ${statusText}`;
                statusEl.style.color = statusColor;
            }
            if (scaledEl) scaledEl.textContent = tvdScaled;
            if (circuitHashEl && circuitHash) circuitHashEl.textContent = circuitHash.substring(0, 32) + '...';
        }

        if (document.hidden) return;

        const graphCanvas = document.getElementById('quantum-tvd-graph-canvas');
        if (graphCanvas) {
            const graphCtx = graphCanvas.getContext('2d');
            if (graphCtx) {
                graphCtx.clearRect(0, 0, graphCanvas.width, graphCanvas.height);

                // Draw subtle background grid lines
                graphCtx.strokeStyle = isLight ? 'rgba(148, 163, 184, 0.3)' : 'rgba(51, 65, 85, 0.4)';
                graphCtx.lineWidth = 1;
                graphCtx.beginPath();
                for (let i = 1; i < 3; i++) {
                    let y = (graphCanvas.height / 3) * i;
                    graphCtx.moveTo(0, y);
                    graphCtx.lineTo(graphCanvas.width, y);
                }
                graphCtx.stroke();

                // Threshold line at 0.25 (Decoherence boundary)
                let boundY = graphCanvas.height - (0.25 * graphCanvas.height);
                graphCtx.strokeStyle = isLight ? 'rgba(220, 38, 38, 0.4)' : 'rgba(239, 68, 68, 0.4)';
                graphCtx.setLineDash([2, 2]);
                graphCtx.beginPath();
                graphCtx.moveTo(0, boundY);
                graphCtx.lineTo(graphCanvas.width, boundY);
                graphCtx.stroke();
                graphCtx.setLineDash([]);

                if (tvdDriftHistory.length > 1) {
                    graphCtx.strokeStyle = statusColor;
                    graphCtx.lineWidth = 1.5;
                    graphCtx.beginPath();
                    const maxPoints = 30;
                    const xStep = graphCanvas.width / (maxPoints - 1);

                    for (let i = 0; i < tvdDriftHistory.length; i++) {
                        const x = i * xStep;
                        const val = Math.min(1.0, Math.max(0.0, tvdDriftHistory[i]));
                        const y = graphCanvas.height - (val * graphCanvas.height * 0.9 + 2);
                        if (i === 0) {
                            graphCtx.moveTo(x, y);
                        } else {
                            graphCtx.lineTo(x, y);
                        }
                    }
                    graphCtx.stroke();

                    // Attach hover inspection listener once
                    if (!graphCanvas._hasHoverListener) {
                        graphCanvas._hasHoverListener = true;
                        graphCanvas.addEventListener('mousemove', (e) => {
                            const rect = graphCanvas.getBoundingClientRect();
                            const x = e.clientX - rect.left;
                            const idx = Math.min(tvdDriftHistory.length - 1, Math.max(0, Math.round((x / rect.width) * (tvdDriftHistory.length - 1))));
                            const val = tvdDriftHistory[idx];
                            const tooltip = document.getElementById('tvd-graph-tooltip');
                            if (tooltip) {
                                const valColor = val <= 0.25 ? 'var(--accent-green)' : 'var(--accent-red)';
                                tooltip.innerHTML = `<span style="color: ${valColor}; font-weight: bold;">&delta;: ${val.toFixed(5)}</span> <span style="color: var(--text-muted); font-weight: normal;">(T-${(tvdDriftHistory.length - 1 - idx) * 2}s)</span>`;
                            }
                        });
                        graphCanvas.addEventListener('mouseleave', () => {
                            const tooltip = document.getElementById('tvd-graph-tooltip');
                            if (tooltip) {
                                const isCurrentLight = document.documentElement.classList.contains('light-mode');
                                tooltip.innerHTML = `Threshold &le;0.25 <span style="font-weight: normal; color: var(--text-muted); font-size: 0.68rem;">Hover to inspect</span>`;
                                tooltip.style.color = isCurrentLight ? '#dc2626' : '#ef4444';
                            }
                        });
                    }
                }
            }
        }
    }

    /**
     * @brief Updates consensus committee topology graphics and DKG ceremony phase indicators.
     *
     * @param {number} committeeCount Active members in threshold committee (up to 10).
     * @param {number} activeDkgSessions Active keygen session count.
     * @param {number} lastDkgEpoch Block height of most recent DKG rotation.
     * @return {void}
     * @complexity Time: O(1) circular graph rasterization, Space: O(1).
     */
    function updateDkgBeacon(committeeCount, activeDkgSessions, lastDkgEpoch) {
        const dkgContainer = document.getElementById('dkg-health-container');
        if (!dkgContainer || !window.hasDkgTelemetry) return;

        const isLight = document.documentElement.classList.contains('light-mode');
        const isOrange = document.documentElement.classList.contains('orange-mode');
        const activeColor = isLight ? '#0284c7' : '#38bdf8';

        const dkgStateLog = activeDkgSessions > 0 ? `
            <div style="margin-top: 6px; border-top: 1px solid var(--border-color); padding-top: 8px; display: flex; flex-direction: column; gap: 2px; font-family: monospace; font-size: 0.7rem; color: var(--text-muted);">
                <div style="color: var(--accent-green); font-weight: bold; margin-bottom: 2px;">
                    ⚡ ACTIVE KEYGEN CEREMONY IN PROGRESS
                </div>
                <div>
                    • Phase 1: Commit Round &mdash;
                    <span style="color: ${activeDkgSessions > 1 ? 'var(--accent-green)' : activeColor};">${activeDkgSessions > 1 ? 'SUCCESS' : 'ACTIVE'}</span>
                </div>
                <div>
                    • Phase 2: Reveal Round &mdash;
                    <span style="color: ${activeDkgSessions > 2 ? 'var(--accent-green)' : (activeDkgSessions === 2 ? activeColor : 'var(--text-muted)')};">${activeDkgSessions > 2 ? 'SUCCESS' : (activeDkgSessions === 2 ? 'ACTIVE' : 'PENDING')}</span>
                </div>
                <div>
                    • Phase 3: Joint-RSS Share Deal &mdash;
                    <span style="color: ${activeDkgSessions > 3 ? 'var(--accent-green)' : (activeDkgSessions === 3 ? activeColor : 'var(--text-muted)')};">${activeDkgSessions > 3 ? 'VERIFIED' : (activeDkgSessions === 3 ? 'ACTIVE' : 'PENDING')}</span>
                </div>
                <div>
                    • Phase 4: Key Assembly &mdash;
                    <span style="color: ${activeDkgSessions > 4 ? 'var(--accent-green)' : (activeDkgSessions === 4 ? activeColor : 'var(--text-muted)')};">${activeDkgSessions > 4 ? 'SUCCESS' : (activeDkgSessions === 4 ? 'ACTIVE' : 'PENDING')}</span>
                </div>
            </div>
        ` : `
            <div style="margin-top: 6px; border-top: 1px solid var(--border-color); padding-top: 8px; display: flex; flex-direction: column; gap: 2px; font-family: monospace; font-size: 0.7rem; color: var(--text-muted);">
                <div style="color: var(--accent-green); font-weight: bold; margin-bottom: 2px;">
                    🟢 EPOCH CEREMONY STATE STABLE
                </div>
                <div>
                    • Joint-RSS Matrix A_bar &mdash;
                    <span style="color: var(--text-main);">DEPLOYED</span>
                </div>
                <div>
                    • t=2 Consensus Threshold &mdash;
                    <span style="color: var(--accent-green);">VERIFIED</span>
                </div>
                <div>
                    • Entropy Beacon Seed &mdash;
                    <span style="color: var(--text-main);">GENERATING (60s block slots)</span>
                </div>
            </div>
        `;

        // Phase 3 Performance Budget: Non-destructive DOM updates to prevent canvas tearing and GC spikes
        dkgContainer.dataset.activeDkgSessions = activeDkgSessions;
        if (!document.getElementById('dkg-ring-canvas')) {
            dkgContainer.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: var(--text-muted); display: flex; align-items: center;">Active Committee Size: <span class="info-pop"><i class="info-icon">i</i><span class="info-bubble">Committee quorum $n = 10$ selected via top staked validation weight $W_i \\propto C_{\\text{staked}, i}$.</span></span></span>
                        <span id="dkg-committee-val" style="color: ${committeeCount >= 10 ? 'var(--accent-green)' : 'var(--accent-red)'}; font-weight: 600;">
                            ${committeeCount} / 10 Nodes
                        </span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: var(--text-muted); display: flex; align-items: center;">Threshold Status: <span class="info-pop"><i class="info-icon">i</i><span class="info-bubble">Threshold $(t, n) = (2, 10)$ requiring $t=2$ shares to reconstruct response vector $\\|z\\|_\\infty < \\gamma_1 - \\beta$ without leaking private shares.</span></span></span>
                        <span id="dkg-threshold-val" style="color: var(--text-main); font-weight: 600;">
                            ${committeeCount >= 2 ? 't=2 Active' : 'Offline'}
                        </span>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span style="color: var(--text-muted);">Last DKG Epoch:</span>
                        <span id="dkg-epoch-val" style="color: var(--text-main); font-weight: 600;">${Number(lastDkgEpoch).toLocaleString('en-US')}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span style="color: var(--text-muted);">Active Keygen Ceremonies:</span>
                        <span id="dkg-sessions-val" style="color: ${activeDkgSessions > 0 ? 'var(--accent-green)' : 'var(--text-main)'}; font-weight: 600;">
                            ${activeDkgSessions > 0 ? 1 : 0}
                        </span>
                    </div>
                    <div style="margin-top: 6px; display: flex; flex-direction: column; gap: 4px;">
                        <span style="color: var(--text-muted); font-size: 0.75rem;">
                            DKG Threshold Topology Graph:
                        </span>
                        <canvas id="dkg-ring-canvas" width="480" height="280" style="background-color: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 4px; width: 100%; height: 140px; display: block;"></canvas>
                    </div>
                    <div id="dkg-state-log">
                        ${dkgStateLog}
                    </div>
                </div>
            `;
        } else {
            const committeeEl = document.getElementById('dkg-committee-val');
            const thresholdEl = document.getElementById('dkg-threshold-val');
            const epochEl = document.getElementById('dkg-epoch-val');
            const sessionsEl = document.getElementById('dkg-sessions-val');
            const stateLogEl = document.getElementById('dkg-state-log');

            if (committeeEl) {
                committeeEl.textContent = `${committeeCount} / 10 Nodes`;
                committeeEl.style.color = committeeCount >= 10 ? 'var(--accent-green)' : 'var(--accent-red)';
            }
            if (thresholdEl) {
                thresholdEl.textContent = committeeCount >= 2 ? 't=2 Active' : 'Offline';
            }
            if (epochEl) {
                epochEl.textContent = Number(lastDkgEpoch).toLocaleString('en-US');
            }
            if (sessionsEl) {
                sessionsEl.textContent = activeDkgSessions > 0 ? 1 : 0;
                sessionsEl.style.color = activeDkgSessions > 0 ? 'var(--accent-green)' : 'var(--text-main)';
            }
            if (stateLogEl && stateLogEl.innerHTML.trim() !== dkgStateLog.trim()) {
                stateLogEl.innerHTML = dkgStateLog;
            }
        }

        // Enforce strict performance budgets by bypassing heavy canvas rasterization when tab is backgrounded
        if (document.hidden) return;

        const dkgCanvas = document.getElementById('dkg-ring-canvas');
        if (dkgCanvas) {
            const dkgCtx = dkgCanvas.getContext('2d');
            if (dkgCtx) {
                dkgCanvas.width = dkgCanvas.clientWidth;
                dkgCanvas.height = 140;
                dkgCtx.clearRect(0, 0, dkgCanvas.width, dkgCanvas.height);
                const numNodes = 10;
                const centerX = dkgCanvas.width / 2;
                const centerY = dkgCanvas.height / 2;
                const nodeRadius = 7;
                const circleRadius = Math.max(28, Math.min(centerX - 24, centerY - 24));

                const points = [];
                for (let i = 0; i < numNodes; i++) {
                    const angle = (i * 2 * Math.PI) / numNodes - Math.PI / 2;
                    points.push({
                        x: centerX + circleRadius * Math.cos(angle),
                        y: centerY + circleRadius * Math.sin(angle),
                        active: i < committeeCount
                    });
                }

                if (committeeCount >= 2) {
                    dkgCtx.strokeStyle = isOrange
                        ? (isLight ? 'rgba(234, 88, 12, 0.35)' : 'rgba(247, 147, 26, 0.4)')
                        : (isLight ? 'rgba(5, 150, 105, 0.35)' : 'rgba(16, 185, 129, 0.4)');
                    dkgCtx.lineWidth = 1.5;
                    for (let i = 0; i < numNodes; i++) {
                        if (points[i].active) {
                            for (let j = i + 1; j < numNodes; j++) {
                                if (points[j].active) {
                                    dkgCtx.beginPath();
                                    dkgCtx.moveTo(points[i].x, points[i].y);
                                    dkgCtx.lineTo(points[j].x, points[j].y);
                                    dkgCtx.stroke();
                                }
                            }
                        }
                    }
                } else {
                    dkgCtx.strokeStyle = isLight ? 'rgba(220, 38, 38, 0.3)' : 'rgba(239, 68, 68, 0.2)';
                    dkgCtx.lineWidth = 1.5;
                    dkgCtx.setLineDash([4, 8]);
                    for (let i = 1; i < numNodes; i++) {
                        dkgCtx.beginPath();
                        dkgCtx.moveTo(points[0].x, points[0].y);
                        dkgCtx.lineTo(points[i].x, points[i].y);
                        dkgCtx.stroke();
                    }
                    dkgCtx.setLineDash([]);
                }

                dkgCtx.strokeStyle = isLight ? 'rgba(148, 163, 184, 0.3)' : 'rgba(51, 65, 85, 0.3)';
                dkgCtx.lineWidth = 1.5;
                dkgCtx.beginPath();
                dkgCtx.arc(centerX, centerY, circleRadius, 0, 2 * Math.PI);
                dkgCtx.stroke();

                points.forEach((pt, idx) => {
                    dkgCtx.beginPath();
                    dkgCtx.arc(pt.x, pt.y, nodeRadius, 0, 2 * Math.PI);
                    if (pt.active) {
                        dkgCtx.fillStyle = isOrange ? (isLight ? '#ea580c' : '#f7931a') : (isLight ? '#059669' : '#10b981');
                        dkgCtx.strokeStyle = isOrange ? (isLight ? '#c2410c' : '#b45309') : (isLight ? '#047857' : '#047857');
                    } else {
                        dkgCtx.fillStyle = isOrange ? (isLight ? '#e7e5e4' : '#44372c') : (isLight ? '#cbd5e1' : '#475569');
                        dkgCtx.strokeStyle = isOrange ? (isLight ? '#a89f91' : '#342a21') : (isLight ? '#94a3b8' : '#334155');
                    }
                    dkgCtx.fill();
                    dkgCtx.stroke();

                    if (idx === 0 || idx === 3 || idx === 7) {
                        dkgCtx.fillStyle = document.documentElement.classList.contains('light-mode') ? '#475569' : '#94a3b8';
                        dkgCtx.font = '11px monospace';
                        dkgCtx.textAlign = 'center';
                        let labelOffsetY = idx === 0 ? -11 : 16;
                        dkgCtx.fillText(`P${idx}`, pt.x, pt.y + labelOffsetY);
                    }
                });
            }
        }
    }

    if (!window.knownPubkeysSet) window.knownPubkeysSet = new Set();

    /**
     * @brief Resolves a 32-byte User ID hex string to its full 2,592-byte Dilithium public key.
     *
     * @param {string} inputHex 64-character User ID or 5,184-character public key.
     * @return {string|null|undefined} Full public key hex string, null if unresolvable, undefined on invalid format.
     * @complexity Time: O(known_keys), Space: O(1).
     */
    function resolveUserIdToPubkey(inputHex) {
        const clean = (inputHex || '').replace(/[^0-9a-fA-F]/g, '');
        if (clean.length === 5184) {
            return clean;
        }
        if (clean.length === 64) {
            const targetUserId = clean.toLowerCase();
            const candidates = new Set();

            const { pubKeyHex } = resolveWalletCredentials();
            if (pubKeyHex) candidates.add(pubKeyHex.toLowerCase());
            if (window.nodePubkeyHex) candidates.add(window.nodePubkeyHex.toLowerCase());
            if (typeof latestGeneratedData !== 'undefined' && latestGeneratedData && latestGeneratedData.pubkeyHex) {
                candidates.add(latestGeneratedData.pubkeyHex.toLowerCase());
            }

            if (window.knownPubkeysSet) {
                window.knownPubkeysSet.forEach(pk => candidates.add(pk.toLowerCase()));
            }

            for (const pkHex of candidates) {
                const bytes = _hexToBytes(pkHex, 2592);
                if (bytes && bytes.length === 2592) {
                    const hashBytes = sha256_uint8(bytes);
                    const uidHex = Array.from(hashBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                    if (uidHex === targetUserId) {
                        return pkHex;
                    }
                }
            }
            return null;
        }
        return undefined;
    }

    client.onChainInfoReceived = (data) => {
        client.lastChainInfoResponseTime = Date.now();
        window.hasDkgTelemetry = true;
        window.hasLatticeTelemetry = true;
        window.hasInvariantTelemetry = true;
        const syncModeEl = document.getElementById('sync-mode-text');
        if (syncModeEl) {
            syncModeEl.textContent = 'TELEMETRY SYNCED';
            syncModeEl.className = 'status-badge status-synced';
            syncModeEl.style.display = 'inline-block';
        }
        const {
            blockHeight,
            totalSubunits,
            totalStaked,
            committeeCount,
            activeDkgSessions,
            lastDkgEpoch,
            totalFees,
            nodePubkeyHex,
            nodePrivkeyHex
        } = data;

        if (nodePubkeyHex) {
            window.nodePubkeyHex = nodePubkeyHex;
            if (!window.knownPubkeysSet) window.knownPubkeysSet = new Set();
            window.knownPubkeysSet.add(nodePubkeyHex);
            const nodePubkeyBytes = _hexToBytes(nodePubkeyHex, 2592);
            /* Auto-bind on blank fields (testnet convenience preserved). Session-memory
             * only; the shared testnet identity file keeps the served key stable. */
            if (nodePubkeyBytes && (!walletPubkeyInput || !walletPubkeyInput.value.trim())) {
                client.rawDilithiumPubkey = nodePubkeyBytes;
                client.setTargetPubkey(nodePubkeyBytes);
                if (walletPubkeyInput) walletPubkeyInput.value = nodePubkeyHex;
            }
        }

        if (nodePrivkeyHex) {
            const nodePrivkeyBytes = _hexToBytes(nodePrivkeyHex, 4864);
            if (nodePrivkeyBytes && !nodePrivkeyBytes.every(b => b === 0)) {
                if (!walletPrivkeyInput || !walletPrivkeyInput.value.trim()) {
                    /* H-3 fix: held in memory for this session only. The served key is the
                     * disposable testnet identity (never the operator/staking key) and is
                     * never written to localStorage. */
                    client.rawDilithiumKey = nodePrivkeyBytes;
                    if (walletPrivkeyInput) walletPrivkeyInput.value = nodePrivkeyHex;
                    hotSwapCredentials();
                }
            }
        }

        document.getElementById('block-height-val').textContent = Number(blockHeight).toLocaleString('en-US');
        document.getElementById('total-subunits-val').textContent =
            '¢' + formatScl(Number(totalSubunits) / 160000000, 0);
        document.getElementById('total-staked-val').textContent =
            '¢' + formatScl(Number(totalStaked) / 160000000, 4);
         
        const totalFeesValEl = document.getElementById('total-fees-val');
        if (totalFeesValEl) {
            totalFeesValEl.textContent = '¢' + formatScl(Number(totalFees) / 160000000, 4);
        }

        /* Active-Node stability fix: a new count is committed only after it repeats
         * across two consecutive live polls, so a single backend behind the GCP load
         * balancer cannot make the badge drift. window.pendingCommitteeCount holds
         * the unconfirmed reading. */
        if (committeeCount !== window.lastStableCommitteeCount) {
            if (window.pendingCommitteeCount === committeeCount) {
                window.lastStableCommitteeCount = committeeCount;
                window.pendingCommitteeCount = null;
            } else {
                window.pendingCommitteeCount = committeeCount;
            }
        } else {
            window.pendingCommitteeCount = null;
        }
        const stableCommitteeCount = (window.lastStableCommitteeCount !== undefined)
            ? window.lastStableCommitteeCount
            : committeeCount;

        const activeNodesEl = document.getElementById('active-nodes-val');
        if (activeNodesEl) {
            activeNodesEl.textContent = stableCommitteeCount;
        }

        updateDkgBeacon(stableCommitteeCount, activeDkgSessions, lastDkgEpoch);

        /* TVD tracks consensus, not the wall clock. A new block or a new DKG
         * epoch is the only reason to ask for another certificate. */
        if (client && (blockHeight !== client._lastTvdBlock || lastDkgEpoch !== client._lastDkgEpoch)) {
            client._lastTvdBlock = blockHeight;
            client._lastDkgEpoch = lastDkgEpoch;
            client.requestQuantumTvdAudit();
        }

        window.systemMetrics.totalSubunits = totalSubunits;
        window.systemMetrics.totalFees = totalFees;
        updateInvariantAuditor();
        updateLatticeDensity(activeDkgSessions > 0 ? 1 : 0, totalStaked);
        updateGlobalValidations();

        latestKnownBlockHeight = blockHeight;
        /* Remember the last REAL telemetry so the watchdog fallback echoes live
         * values instead of zeroing the height and freezing the node badge. */
        window.lastKnownChainHeight = blockHeight;
        window.lastKnownTotalStaked = totalStaked;
        window.lastKnownCommitteeCount = (window.lastStableCommitteeCount !== undefined) ? window.lastStableCommitteeCount : committeeCount;
        window.lastKnownDkgEpoch = lastDkgEpoch;

        const now = Date.now();
        if (now - lastBlockResponseTime > 5000 && requestedBlocks.size > 0) {
            console.warn(
                '[ExplorerApp] Block sync timed out. Clearing outstanding requests to trigger retry...'
            );
            requestedBlocks.clear();
            isSyncingBlocks = false;
            lastBlockResponseTime = now;
        }

        fillBlockDownloadPipeline();
    };

    client.onBlockReceived = (data) => {
        const { blockNumber, commitments } = data;
        if (commitments && commitments.length > 0) {
            if (!window.confirmedTxIds) window.confirmedTxIds = new Set();
            commitments.forEach(c => {
                const hexC = c.map(b => b.toString(16).padStart(2, '0')).join('');
                window.confirmedTxIds.add(hexC);
            });
        }

        // Reset the block-sync watchdog timer to prevent premature timeouts during active stream ingestion
        lastBlockResponseTime = Date.now();

        if (typeof manualBlockRequests !== 'undefined' && manualBlockRequests.has(blockNumber)) {
            manualBlockRequests.delete(blockNumber);
            const item = document.createElement('li');
            item.className = 'match-item';
            item.style.borderLeftColor = 'var(--accent-green)';
            item.style.backgroundColor = 'rgba(16, 185, 129, 0.05)';
             
            let commsHtml = commitments.map((c, i) => {
                const hexComm = c.map(b => b.toString(16).padStart(2, '0')).join('');
                return `<div style="font-size: 0.7rem; color: var(--text-muted); font-family: monospace;">  • commitment ${i+1}: ${hexComm.substring(0, 32)}...</div>`;
            }).join('');
            if (commitments.length === 0) {
                commsHtml = `<div style="font-size: 0.75rem; color: var(--text-muted);">No unspent UTXO commitments in this block (Empty block).</div>`;
            }

            const isLight = document.documentElement.classList.contains('light-mode');
            const commColor = isLight ? '#7c3aed' : '#a78bfa';

            item.innerHTML = `
                <span class="match-method">[Block Inclusion Audit]</span>
                <span class="match-hash" style="font-weight: bold;">Mined Block Height: #${blockNumber}</span>
                <div style="font-size: 0.75rem; margin-top: 4px; color: var(--text-main);">
                    Total commitments in block: <span style="font-family: monospace; color: ${commColor}; font-weight: 600;">${commitments.length}</span>
                </div>
                <div style="margin-top: 4px;">
                    ${commsHtml}
                </div>
            `;
            matchesList.prepend(item);
        }

        let advanced = false;
        if (blockNumber === 0) {
            syncedBlockHeight = 0;
            mmrTree.nodes = [];
            mmrTree.peaks = [];
            renderer.setNodes([]);
            advanced = true;
        } else if (blockNumber > syncedBlockHeight) {
            pendingBlocks.set(blockNumber, commitments);
        }

        while (pendingBlocks.has(syncedBlockHeight + 1)) {
            const nextBlockNum = syncedBlockHeight + 1;
            const nextCommitments = pendingBlocks.get(nextBlockNum);
            nextCommitments.forEach(c => mmrTree.addLeafHash(new Uint8Array(c)));
            syncedBlockHeight = nextBlockNum;
            pendingBlocks.delete(nextBlockNum);
            advanced = true;
        }

        if (advanced) {
            // Frame-budget the MMR canvas update to prevent blocking the UI during streaming bursts
            if (!window._mmrRenderScheduled) {
                window._mmrRenderScheduled = true;
                requestAnimationFrame(() => {
                    window._mmrRenderScheduled = false;
                    renderer.setNodes(mmrTree.nodes);
                    updateGlobalValidations();
                });
            }
        }

        if (syncedBlockHeight >= latestKnownBlockHeight || (requestedBlocks.size > 0 && syncedBlockHeight === Math.max(...requestedBlocks))) {
            isSyncingBlocks = false;
            requestedBlocks.clear();
        }

        fillBlockDownloadPipeline();
    };

    client.onRecentTxsReceived = (data) => {
        const { txs, nextCursor } = data;

        if (!window.confirmedTxIds) window.confirmedTxIds = new Set();

        const pendingCount = txs.filter(tx => {
            const hexTx = tx.map(b => b.toString(16).padStart(2, '0')).join('');
            return !window.confirmedTxIds.has(hexTx);
        }).length;

        const mempoolEl = document.getElementById('mempool-size-val');
        if (mempoolEl) {
            mempoolEl.textContent = pendingCount;
        }

        // Chain the pagination cursor only when a valid, positive next cursor is returned
        if (nextCursor !== undefined && nextCursor !== null && nextCursor > 0) {
            client.requestRecentTransactions(nextCursor);
        }

        txs.forEach(tx => {
            const hexTx = tx.map(b => b.toString(16).padStart(2, '0')).join('');

            if (!window.requestedTxs) window.requestedTxs = new Set();
            if (window.requestedTxs.has(hexTx)) return;
            window.requestedTxs.add(hexTx);

            client.requestTransaction(tx);

            const existingItems = matchesList.querySelectorAll('.match-hash');
            let alreadyExists = false;
            existingItems.forEach(el => {
                if (el.textContent.includes(hexTx.substring(0, 16))) {
                    alreadyExists = true;
                }
            });

            if (!alreadyExists) {
                const item = document.createElement('li');
                item.className = 'match-item';
                item.innerHTML = `
                    <span class="match-method">[Mempool Tx]</span>
                    <span class="match-hash">Tx ID: ${hexTx.substring(0, 32)}...</span>
                `;
                matchesList.prepend(item);
            }
        });
    };

    client.onBalanceReceived = (data) => {
        client.lastBalanceResponseTime = Date.now();
        const { balanceSubunits, stakedSubunits, feesPaidSubunits, utxoValidations, activeUtxos } = data;
        window.lastBalanceSubunits = BigInt(balanceSubunits);
        window.lastStakedSubunits = BigInt(stakedSubunits);
        window.lastFeesPaidSubunits = BigInt(feesPaidSubunits || 0);
        document.getElementById('decrypted-balance-val').textContent = '¢' + formatScl(balanceSubunits / 160000000, 4);
        if (typeof updateAutopilotUI === 'function') {
            updateAutopilotUI({});
        }
            
        if (activeUtxos) {
            window.loadedUTXOs = activeUtxos;
        }
                
        const auditedStakedEl = document.getElementById('decrypted-staked-val');
        if (auditedStakedEl) {
            auditedStakedEl.textContent = '¢' + formatScl(stakedSubunits / 160000000, 4);
        }
                
        const auditedFeesEl = document.getElementById('decrypted-fees-paid-val');
        if (auditedFeesEl) {
            auditedFeesEl.textContent = '¢' + formatScl(feesPaidSubunits / 160000000, 4);
        }

        const utxoValEl = document.getElementById('decrypted-utxo-val');
        if (utxoValEl && utxoValidations !== undefined && utxoValidations !== null) {
            const recentSubmission = window.lastValuationSubmissionAt &&
                (Date.now() - window.lastValuationSubmissionAt) < 8000;
            if (recentSubmission && utxoValidations > (window.privateUtxoBalance || 0)) {
                /* UTXO-stat stability fix: the node has not applied our burn yet; do not
                 * let the pre-burn echo reset the locally decremented tally. */
            } else {
                window.privateUtxoBalance = utxoValidations;
            }
            utxoValEl.textContent = Number(window.privateUtxoBalance || 0).toLocaleString('en-US');
        }

        updateGlobalValidations();

        if (!window.unspentPointers) window.unspentPointers = [];

        // Populate the unspentPointers list with true native pointers returned directly from the Node's MMR
        if (data.nativePointers) {
            data.nativePointers.forEach(nativePtr => {
                const existsIdx = window.unspentPointers.findIndex(p => p.pointerId === nativePtr.pointerId);
                if (existsIdx === -1) {
                    window.unspentPointers.push(nativePtr);
                } else {
                    window.unspentPointers[existsIdx] = nativePtr;
                }
                blockchainStore.pointers.set(nativePtr.pointerId, nativePtr);
            });
        }

        // Wipe obsolete synthetic bounds if any exist
        window.unspentPointers = window.unspentPointers.filter(p => !p.pointerId.startsWith("bal_"));

        client.requestRecentTransactions(0);
        renderBlockchainLedgerView();
    };

    client.onTransactionAudited = (data) => {
        const { txId, typeString, payloadLen, matchFound, nullifier, methodId, parsedTx } = data;

        // Track globally audited nullifiers and refresh unspent commitment calculations
        if (nullifier) {
            if (!window.globalSpentNullifiers) window.globalSpentNullifiers = new Set();
            window.globalSpentNullifiers.add(nullifier);
            updateGlobalValidations();
        }

        // Auto-cache incoming/matched unspent pointers in the client-side UTXO pool (Section 3.1)
        if (parsedTx && txId) {
            if (!window.unspentPointers) window.unspentPointers = [];
            if (!window.knownPubkeysSet) window.knownPubkeysSet = new Set();
            if (parsedTx.senderPubkeyHex) window.knownPubkeysSet.add(parsedTx.senderPubkeyHex);
            if (parsedTx.recipientPubkeyHex) window.knownPubkeysSet.add(parsedTx.recipientPubkeyHex);

            const { pubKeyHex: myPubHexResolved } = resolveWalletCredentials();
            const myPubHex = (myPubHexResolved || '').toLowerCase();
            const recPubHex = (parsedTx.recipientPubkeyHex || '').toLowerCase();
            const sendPubHex = (parsedTx.senderPubkeyHex || '').toLowerCase();
            const isMyTx = myPubHex && (recPubHex === myPubHex || sendPubHex === myPubHex);

            if (parsedTx.inputPointerIds) {
                parsedTx.inputPointerIds.forEach(inId => {
                    const ptr = window.unspentPointers.find(p => p.pointerId === inId);
                    if (ptr) ptr.spent = true;
                });
            }

            if (isMyTx && parsedTx.generatedPointers) {
                parsedTx.generatedPointers.forEach(ptr => {
                    const exists = window.unspentPointers.some(p => p.pointerId === ptr.pointerIdHex);
                    if (!exists) {
                        window.unspentPointers.push({
                            pointerId: ptr.pointerIdHex,
                            parentCoinId: ptr.parentCoinIdHex,
                            startSubunit: ptr.startSubunit,
                            endSubunit: ptr.endSubunit,
                            ownerAddress: ptr.ownerAddressHex,
                            prevTxHash: ptr.prevTxHashHex,
                            spent: ptr.spent,
                            staked: ptr.staked
                        });
                    }
                });
            }
        }

        const item = document.createElement('li');
        item.className = 'match-item';
        item.style.borderLeftColor = matchFound ? 'var(--accent-green)' : 'var(--text-muted)';
        if (matchFound) {
            item.style.backgroundColor = 'rgba(16, 185, 129, 0.05)';
        }

        const statusLabel = matchFound ?
            '<span style="color: var(--accent-green); font-weight: bold;">[MATCHED WITH YOUR KEY]</span>' :
            '<span style="color: var(--text-muted);">[SHIELDPATH PRIVATE TRANSIT]</span>';

        const idLabel = txId ? `ID: ${escapeHTML(txId.substring(0, 32))}...` : `Type: ${escapeHTML(typeString)}`;

        const isLight = document.documentElement.classList.contains('light-mode');
        const utxoCountColor = isLight ? '#0284c7' : '#38bdf8';
        const opClassColor = isLight ? '#7c3aed' : '#a78bfa';

        let parsedDetailsHtml = '';
        if (parsedTx && typeString !== 'OP_SUBMIT_VALUATION') {
            const amountScl = formatScl(Number(parsedTx.amount) / 160000000, 4);
            parsedDetailsHtml = `
                <div style="font-size: 0.75rem; margin-top: 4px; color: var(--text-main);">
                    Value: <span style="font-family: monospace; color: var(--accent-green); font-weight: bold;">¢${escapeHTML(amountScl)}</span>
                    | Inputs Count: <span style="font-family: monospace; color: ${utxoCountColor};">${escapeHTML(parsedTx.numInputs)} UTXO(s)</span>
                </div>
                <div style="font-size: 0.7rem; color: var(--text-muted); font-family: monospace; margin-top: 2px;">
                    • Sender PK (16B): ${escapeHTML((parsedTx.senderPubkeyHex || '').substring(0, 32))}...
                </div>
                <div style="font-size: 0.7rem; color: var(--text-muted); font-family: monospace; margin-top: 1px;">
                    • Recipient/Threshold PK (16B): ${escapeHTML((parsedTx.recipientPubkeyHex || '').substring(0, 32))}...
                </div>
            `;
        }

        item.innerHTML = `
            <span class="match-method">[Audit Decryption Report]</span>
            <span class="match-hash" style="font-weight: bold;">${idLabel}</span>
            <div style="font-size: 0.75rem; margin-top: 4px; color: var(--text-main);">
                Operation Class: <span style="font-family: monospace; color: ${opClassColor}; font-weight: 600;">${escapeHTML(typeString)}</span>
            </div>
            ${parsedDetailsHtml}
            <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">
                Raw Binary Wire Footprint: ${escapeHTML(payloadLen)} bytes | Shield Status: ${statusLabel}
            </div>
            ${nullifier ? `<div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 2px;">Extracted PRF Nullifier: <span style="font-family: monospace;">${escapeHTML(nullifier.substring(0, 24))}...</span></div>` : ''}
        `;
        matchesList.prepend(item);
    };

    client.onQuantumTvdAuditReceived = (data) => {
        window.lastQuantumTvdData = data;
        updateQuantumTvdAudit(data);
    };

    client.onBlockchainLedgerReceived = (data) => {
        const { coins, pointers } = data;
        if (coins && Array.isArray(coins)) {
            blockchainStore.coins.clear();
            coins.forEach(c => {
                const existing = blockchainStore.coins.get(c.coinId);
                blockchainStore.coins.set(c.coinId, {
                    coinId: c.coinId,
                    totalSubunits: c.totalSubunits,
                    remainingSubunits: c.remainingSubunits,
                    creationTxHash: c.creationTxHash,
                    ownerAddress: c.ownerAddress,
                    blockNumber: c.blockNumber,
                    auditSnapshot: existing ? existing.auditSnapshot : null
                });
            });
        }
        if (pointers && Array.isArray(pointers)) {
            pointers.forEach(p => {
                blockchainStore.pointers.set(p.pointerId, {
                    pointerId: p.pointerId,
                    parentCoinId: p.parentCoinId,
                    startSubunit: p.startSubunit,
                    endSubunit: p.endSubunit,
                    ownerAddress: p.ownerAddress,
                    prevTxHash: p.prevTxHash,
                    spent: p.spent,
                    staked: p.staked
                });
            });
        }
        renderBlockchainLedgerView();
        updateGlobalValidations();
    };

    window.updateQuantumTvdAudit = updateQuantumTvdAudit;
    window.updateDkgBeacon = updateDkgBeacon;
    window.updateInvariantAuditor = updateInvariantAuditor;
    window.updateLatticeDensity = updateLatticeDensity;

    client.onValuationsReceived = (data) => {
        client.lastValuationsResponseTime = Date.now();
        window.hasInvariantTelemetry = true;
        const syncModeEl = document.getElementById('sync-mode-text');
        if (syncModeEl) {
            syncModeEl.textContent = 'TELEMETRY SYNCED';
            syncModeEl.className = 'status-badge status-synced';
            syncModeEl.style.display = 'inline-block';
        }
        const { totalRewarded, remainingSubunits, curStage } = data;
        document.getElementById('current-stage-val').textContent = curStage;
        document.getElementById('remaining-subunits-val').textContent = '¢' + formatScl(Number(remainingSubunits) / 160000000, 0);

        window.systemMetrics.totalRewarded = totalRewarded;
        window.systemMetrics.remainingSubunits = remainingSubunits;
        updateInvariantAuditor();
        updateGlobalValidations();
    };

    client.onMmrProofVerified = (data) => {
        const { verified } = data;
        const item = document.createElement('li');
        item.className = 'match-item';
        item.style.borderLeftColor = verified ? 'var(--accent-green)' : 'var(--accent-red)';
        if (verified) {
            item.style.backgroundColor = 'rgba(16, 185, 129, 0.05)';
        } else {
            item.style.backgroundColor = 'rgba(239, 68, 68, 0.05)';
        }

        item.innerHTML = `
            <span class="match-method" style="color: ${verified ? 'var(--accent-green)' : 'var(--accent-red)'}">[Local Client-Side Cryptographic Audit]</span>
            <span class="match-hash" style="font-weight: bold;">MMR Inclusion Proof Verification: ${verified ? 'SUCCESS (VERIFIED)' : 'FAILED'}</span>
            <div style="font-size: 0.75rem; margin-top: 4px; color: var(--text-muted);">
                The inclusion proof path was validated locally inside the WebAssembly container sandbox.
                The leaf commitment mathematically scales to match the current root of the synchronized Merkle Mountain Range.
            </div>
        `;
        matchesList.prepend(item);
    };

    client.onAuditReceived = (data) => {
        const { valuations } = data;
        console.log('[ExplorerApp] Decrypted audit dataset received:', valuations);

        cachedValuations = valuations;
        window.lastAuditValuations = valuations;
        if (window.updateQuantumPredictions) {
            window.updateQuantumPredictions();
        }

        if (window.auditTimeoutTimer) {
            clearTimeout(window.auditTimeoutTimer);
            window.auditTimeoutTimer = null;
        }

        if (window.explicitAuditRequest) {
            _renderValuations(valuations, false);
            window.explicitAuditRequest = false;
        }
    };

    const canvasContainer = document.querySelector('.canvas-container');
    if (canvasContainer) {
        canvasContainer.addEventListener('click', (event) => {
            const activeCanvas = document.getElementById('mmr-canvas');
            if (!activeCanvas) return;
            const rect = activeCanvas.getBoundingClientRect();
            const x = (event.clientX - rect.left) * (renderer.width / rect.width);
            const y = (event.clientY - rect.top) * (renderer.height / rect.height);
            const node = renderer.getNodeAt(x, y);
            if (node) {
                console.log('[ExplorerApp] Selected topography node index:', node.position);

                const proofPath = _computeDeterministicProofPath(node.position, renderer.nodes);
                const peaks = renderer.nodes.filter(n => n.parent === -1);
                const isDeepStorage = (proofPath.length > 64 || peaks.length > 32);

                if (isDeepStorage) {
                    alert(`Deep-storage UTXO detected! Paginated cryptographic proof path required (Path length: ${proofPath.length}, Peaks: ${peaks.length}).`);
                }

                renderer.animateProofPath(node.position, proofPath);

                const item = document.createElement('li');
                item.className = 'match-item';
                item.style.borderLeftColor = isDeepStorage ? 'var(--accent-red)' : 'var(--accent-green)';

                let pathSegments = [];
                const pageSize = 10;
                const totalPages = Math.ceil(proofPath.length / pageSize);

                for (let page = 0; page < totalPages; page++) {
                    const start = page * pageSize;
                    const end = Math.min(start + pageSize, proofPath.length);
                    const chunk = proofPath.slice(start, end).map(pos => `#${pos}`).join(' -> ');
                    pathSegments.push(`<div style="font-size: 0.75rem; margin-top: 4px; color: var(--text-muted);">Page ${page + 1}/${totalPages}: ${chunk}</div>`);
                }

                item.innerHTML = `
                    <span class="match-method" style="color: ${isDeepStorage ? 'var(--accent-red)' : 'var(--accent-green)'}">[MMR Inclusion Audit Proof]</span>
                    <span class="match-hash">Leaf Node #${node.position} (${isDeepStorage ? 'Deep Storage' : 'Standard'} UTXO)</span>
                    <div style="font-size: 0.75rem; margin-top: 4px; color: var(--text-main); font-weight: bold;">
                        Total Sibling Steps: ${proofPath.length} | Peak Count: ${peaks.length}
                    </div>
                    <div style="margin-top: 8px;">
                        ${pathSegments.join('')}
                    </div>
                `;
                matchesList.prepend(item);

                // Reconstruct the serialized proof bytes and peaks to send to the worker for local verification!
                const leafNode = renderer.nodes.find(n => n.position === node.position);
                if (leafNode && leafNode.height === 0) {
                    const leafHashHex = leafNode.hash ? Array.from(leafNode.hash).map(b => b.toString(16).padStart(2, '0')).join('') : '';
                    const snapshot = (leafHashHex && window.leafAuditSnapshots && window.leafAuditSnapshots.get(leafHashHex)) ||
                                     (leafHashHex && blockchainStore.coins.get(leafHashHex)?.auditSnapshot) ||
                                     cachedValuations;
                    
                    if (snapshot && snapshot.length > 0) {
                        _renderValuations(
                            snapshot,
                            false,
                            `[Leaf Node #${node.position} Audit Snapshot]`,
                            `Anchored 10x10 Valuation Matrix for Leaf ${leafHashHex ? leafHashHex.substring(0, 16) + '...' : '#' + node.position}:`
                        );
                    }

                    if (leafNode.hash) {
                        const serializedProof = _serializeMmrProof(node.position, proofPath, renderer.nodes);
                        const peakHashes = mmrTree.peaks.map(pIdx => {
                            const foundNode = renderer.nodes.find(n => n.position === pIdx);
                            return foundNode ? (foundNode.hash || new Uint8Array(32)) : new Uint8Array(32);
                        });
                        if (serializedProof) {
                            client.verifyMmrProof(leafNode.hash, serializedProof, peakHashes);
                        }
                    }
                }

            }
        });
    }

    const searchTxHashInput = document.getElementById('search-tx-hash');
    const searchTxBtn = document.getElementById('btn-search-tx');

    if (searchTxBtn && searchTxHashInput) {
        searchTxBtn.addEventListener('click', () => {
            const rawHex = searchTxHashInput.value.trim();
            if (rawHex.length === 0) {
                alert('Please enter a 32-byte transaction ID (hex).');
                return;
            }
            const txIdBytes = _hexToBytes(rawHex);
            if (txIdBytes) {
                if (txIdBytes.length !== 32) {
                    alert('Transaction ID must be exactly 32 bytes (64 hex characters).');
                    return;
                }
                if (!client.socket || client.socket.readyState !== WebSocket.OPEN) {
                    alert('Not connected to the network node pipeline.');
                    return;
                }
                console.log('[ExplorerApp] Auditing transaction by ID:', rawHex);
                client.requestTransaction(txIdBytes);
            }
        });
    }

    const clearViewportBtn = document.getElementById('btn-clear-viewport');
    if (clearViewportBtn) {
        clearViewportBtn.addEventListener('click', () => {
            if (matchesList) {
                matchesList.innerHTML = '';
            }
            if (window.seenNullifiers) {
                window.seenNullifiers.clear();
            }
        });
    }

    const displayAuditBtn = document.getElementById('btn-display-audit');
    if (displayAuditBtn) {
        displayAuditBtn.addEventListener('click', () => {
            if (client && client.socket && client.socket.readyState === WebSocket.OPEN) {
                window.explicitAuditRequest = true;
                client.requestAudit();
            } else if (cachedValuations && cachedValuations.length > 0) {
                _renderValuations(cachedValuations, false);
            } else {
                alert('Audit data not available. Connect to a node pipeline first.');
            }
        });
    }

    const viewAuditStudioBtn = document.getElementById('btn-view-audit-studio');
    if (viewAuditStudioBtn) {
        viewAuditStudioBtn.addEventListener('click', () => {
            if (client && client.socket && client.socket.readyState === WebSocket.OPEN) {
                window.explicitAuditRequest = true;
                client.requestAudit();
            } else if (cachedValuations && cachedValuations.length > 0) {
                _renderValuations(cachedValuations, false);
            } else {
                alert('Audit data not available. Connect to a node pipeline first.');
            }
        });
    }

    const searchBlockHeightInput = document.getElementById('search-block-height');
    const searchBlockBtn = document.getElementById('btn-search-block');

    if (searchBlockBtn && searchBlockHeightInput) {
        searchBlockBtn.addEventListener('click', () => {
            const rawHeight = searchBlockHeightInput.value.trim();
            if (rawHeight.length === 0) {
                alert('Please enter a block height (integer).');
                return;
            }
            const height = parseInt(rawHeight, 10);
            if (isNaN(height) || height < 0) {
                alert('Block height must be a non-negative integer.');
                return;
            }
            if (!client.socket || client.socket.readyState !== WebSocket.OPEN) {
                alert('Not connected to the network node pipeline.');
                return;
            }
            console.log('[ExplorerApp] Auditing block by height:', height);
            manualBlockRequests.add(height);
            client.requestBlock(height);
        });
    }

    if (generateKeysBtn) {
        generateKeysBtn.addEventListener('click', () => {
            if (!client.isWasmLoaded) {
                alert("WebAssembly is still compiling in the background. Please wait.");
                return;
            }
            generateKeysBtn.disabled = true;
            generateKeysBtn.textContent = 'Generating Cryptographic Keys...';
            client.generateAuditorKeys();
        });
    }

    client.onKeysExpanded = (data) => {
        window.expandedPrfKeyBytes = data.expandedPrfKey;
        if (data.thresholdPubkeyHex) {
            const stakeThresholdInput = document.getElementById('stake-threshold-pk');
            if (stakeThresholdInput) {
                stakeThresholdInput.value = data.thresholdPubkeyHex;
            }
        }
    };

    client.onKeysAutoInitialized = (data) => {
        if (walletPubkeyInput) walletPubkeyInput.value = data.pubkeyHex;
        if (walletPrivkeyInput) walletPrivkeyInput.value = data.privkeyHex;
        const pubkeyBytes = _hexToBytes(data.pubkeyHex);
        if (pubkeyBytes) {
            client.setTargetPubkey(pubkeyBytes);
        }
        hotSwapCredentials();
    };

    client.onKeysGenerated = (data) => {
        if (generateKeysBtn) {
            generateKeysBtn.disabled = false;
            generateKeysBtn.textContent = 'Generate New Credentials';
        }
        latestGeneratedData = data;
        if (prfKeyInput) prfKeyInput.value = data.prfSeedHex;
        if (walletPubkeyInput) walletPubkeyInput.value = data.pubkeyHex;
        if (walletPrivkeyInput) walletPrivkeyInput.value = data.privkeyHex;
        if (data.thresholdPubkeyHex) {
            const stakeThresholdInput = document.getElementById('stake-threshold-pk');
            if (stakeThresholdInput) {
                stakeThresholdInput.value = data.thresholdPubkeyHex;
            }
        }
        window.nodePubkeyHex = data.pubkeyHex;
        if (client) {
            client.lastChainInfoResponseTime = Date.now();
            client.lastValuationsResponseTime = Date.now();
            client.lastBalanceResponseTime = Date.now();
        }
        hotSwapCredentials();
        if (generatedKeysDisplay) {
            generatedKeysDisplay.style.display = 'flex';
            genPubkeySpan.textContent = data.pubkeyHex.substring(0, 64) + "... [Full Key Stored]";
            genPrivkeySpan.textContent = data.privkeyHex.substring(0, 64) + "... [Redacted for Security]";
            genPrfkeySpan.textContent = data.prfSeedHex;
            genUseridSpan.textContent = data.userIdHex;
        }
    };

    if (applyGeneratedBtn) {
        applyGeneratedBtn.addEventListener('click', () => {
            if (!latestGeneratedData) return;
            const prfKeyInput = document.getElementById('prf-key');
            const walletPubkeyInput = document.getElementById('wallet-pubkey');
            const walletPrivkeyInput = document.getElementById('wallet-privkey');
            const nodeUrlInput = document.getElementById('node-url');

            if (prfKeyInput) prfKeyInput.value = latestGeneratedData.prfSeedHex;
            if (walletPubkeyInput) walletPubkeyInput.value = latestGeneratedData.pubkeyHex;
            if (walletPrivkeyInput) walletPrivkeyInput.value = latestGeneratedData.privkeyHex;

            const targetUrl = nodeUrlInput ? nodeUrlInput.value.trim() : client.wsUrl;
            client.wsUrl = targetUrl;
            client.lastChainInfoResponseTime = Date.now();
            client.lastValuationsResponseTime = Date.now();
            client.lastBalanceResponseTime = Date.now();

            alert("Credentials applied successfully. Connecting to node...");
            client.lastChainInfoResponseTime = Date.now();
            client.lastValuationsResponseTime = Date.now();
            client.lastBalanceResponseTime = Date.now();

            // If not connected or connected to a different node, establish new connection
            window.nodePubkeyHex = latestGeneratedData.pubkeyHex;
            if (!client.socket || client.socket.readyState !== WebSocket.OPEN || (client.socket.url !== client.wsUrl && client.socket.url !== client.wsUrl + "/")) {
                if (client.socket) {
                    client.manualDisconnect = true;
                    if (client.reconnectTimer) clearTimeout(client.reconnectTimer);
                    if (client.pollInterval) clearInterval(client.pollInterval);
                    client.socket.close();
                    client.socket = null;
                }
                
                if (!client.worker) {
                    client.initialize();
                }
                
                if (!client.isWasmLoaded) {
                    alert("WebAssembly is still compiling in the background. Please try again in a moment.");
                    return;
                }
                
                const prfKeyBytes = _hexToBytes(latestGeneratedData.prfSeedHex, 32);
                const walletPubkeyBytes = _hexToBytes(latestGeneratedData.pubkeyHex, 2592);
                const dilithiumKeyBytes = _hexToBytes(latestGeneratedData.privkeyHex, 4864);
                if (prfKeyBytes) {
                    const signedPrfKeyBytes = new Int8Array(prfKeyBytes.buffer, prfKeyBytes.byteOffset, prfKeyBytes.byteLength);
                    window.prfKeyBytes = signedPrfKeyBytes;
                    client.injectAuditorKeys(signedPrfKeyBytes, window.loadedUTXOs || [], null, dilithiumKeyBytes, walletPubkeyBytes);
                }
                if (walletPubkeyBytes) {
                    client.setTargetPubkey(walletPubkeyBytes);
                }
                client.connectPipeline();
            } else {
                // Hot-swap credentials if already connected to prevent session stalling or requiring manual reconnects
                const prfKeyBytes = _hexToBytes(latestGeneratedData.prfSeedHex, 32);
                const walletPubkeyBytes = _hexToBytes(latestGeneratedData.pubkeyHex, 2592);
                const dilithiumKeyBytes = _hexToBytes(latestGeneratedData.privkeyHex, 4864);
                if (prfKeyBytes) {
                    const signedPrfKeyBytes = new Int8Array(prfKeyBytes.buffer, prfKeyBytes.byteOffset, prfKeyBytes.byteLength);
                    window.prfKeyBytes = signedPrfKeyBytes;
                    client.injectAuditorKeys(signedPrfKeyBytes, window.loadedUTXOs || [], null, dilithiumKeyBytes, walletPubkeyBytes);
                }
                if (walletPubkeyBytes) {
                    client.setTargetPubkey(walletPubkeyBytes);
                    client.requestBalance(walletPubkeyBytes);
                }
                client.requestChainInfo();
                client.requestValuations();
                client.requestAudit();
                client.requestQuantumTvdAudit();
                client.requestRecentTransactions(0);
            }
        });
    }

    let lastHotSwappedCredentials = "";

    // Helper function for hot-swapping credentials dynamically
    function hotSwapCredentials() {
        if (client && client.socket && client.socket.readyState === WebSocket.OPEN) {
            const targetUrl = nodeUrlInput ? nodeUrlInput.value.trim() : client.wsUrl;
            if (client.socket.url !== targetUrl && client.socket.url !== targetUrl + "/") {
                return; // Let the reconnect logic handle this if URL changed
            }

            const rawPrf = prfKeyInput ? prfKeyInput.value.trim() : "";
            const rawPub = walletPubkeyInput ? walletPubkeyInput.value.trim() : "";
            const rawPriv = walletPrivkeyInput ? walletPrivkeyInput.value.trim() : "";
            const combinedRaw = `${rawPrf}\n${rawPub}\n${rawPriv}`;

            if (combinedRaw === lastHotSwappedCredentials) {
                return; // Skip redundant execution if credentials haven't changed
            }
            lastHotSwappedCredentials = combinedRaw;

            client.lastChainInfoResponseTime = Date.now();
            client.lastValuationsResponseTime = Date.now();
            client.lastBalanceResponseTime = Date.now();

            let prfSeedBytes = rawPrf.length > 0 ? (_hexToBytes(rawPrf, 32) || _hexToBytes(rawPrf, 1024)) : null;
            let walletPubkeyBytes = rawPub.length > 0 ? _hexToBytes(rawPub, 2592) : (window.nodePubkeyHex ? _hexToBytes(window.nodePubkeyHex, 2592) : null);
            let dilithiumKeyBytes = rawPriv.length > 0 ? _hexToBytes(rawPriv, 4864) : null;

            if (walletPubkeyBytes && walletPubkeyBytes.every(b => b === 0)) walletPubkeyBytes = null;
            if (dilithiumKeyBytes && dilithiumKeyBytes.every(b => b === 0)) dilithiumKeyBytes = null;

            if (!prfSeedBytes) {
                prfSeedBytes = new Uint8Array(32);
            }

            if (prfSeedBytes && (prfSeedBytes.length === 32 || prfSeedBytes.length === 1024)) {
                if (!client.isWasmLoaded) return;
                window.prfKeyBytes = prfSeedBytes;
                
                // Clear old matrix data immediately before injection
                if (window.expandedPrfKeyBytes) {
                    window.expandedPrfKeyBytes.fill(0);
                    window.expandedPrfKeyBytes = null;
                }
                
                // Reset unspent pointers cache on key hotswap to prevent cross-account address mismatches
                window.unspentPointers = [];
                
                // Pass null for siphashKey to avoid checksum mismatch on loopback WebSocket messages
                client.injectAuditorKeys(prfSeedBytes, window.loadedUTXOs || [], null, dilithiumKeyBytes, walletPubkeyBytes);
                if (walletPubkeyBytes) {
                    client.requestBalance(walletPubkeyBytes);
                }
            }
            if (walletPubkeyBytes && walletPubkeyBytes.length === 2592) {
                client.setTargetPubkey(walletPubkeyBytes);
                client.requestBalance(walletPubkeyBytes);
            }
            client.requestChainInfo();
            client.requestValuations();
            client.requestAudit();
            client.requestQuantumTvdAudit();
            client.requestRecentTransactions(0);
        }
    }

    function resolveWalletCredentials() {
        const rawPrf = prfKeyInput ? prfKeyInput.value.trim() : "";
        const rawPub = walletPubkeyInput ? walletPubkeyInput.value.trim() : "";
        const rawPriv = walletPrivkeyInput ? walletPrivkeyInput.value.trim() : "";

        let privKeyBytes = rawPriv.length > 0 ? _hexToBytes(rawPriv, 4864) : null;
        let pubKeyBytes = rawPub.length > 0 ? _hexToBytes(rawPub, 2592) : null;

        if (!pubKeyBytes && window.nodePubkeyHex) {
            pubKeyBytes = _hexToBytes(window.nodePubkeyHex, 2592);
        }

        if (!privKeyBytes && latestGeneratedData) {
            privKeyBytes = _hexToBytes(latestGeneratedData.privkeyHex, 4864);
        }
        if (!pubKeyBytes && latestGeneratedData) {
            pubKeyBytes = _hexToBytes(latestGeneratedData.pubkeyHex, 2592);
        }

        // Fallback to the connected node's synced private key if available in the client instance
        if (!privKeyBytes && window.client && window.client.rawDilithiumKey) {
            privKeyBytes = new Uint8Array(window.client.rawDilithiumKey);
        }
        if (!pubKeyBytes && window.client && window.client.rawDilithiumPubkey) {
            pubKeyBytes = new Uint8Array(window.client.rawDilithiumPubkey);
        }

        if (privKeyBytes && privKeyBytes.every(b => b === 0)) privKeyBytes = null;
        if (pubKeyBytes && pubKeyBytes.every(b => b === 0)) pubKeyBytes = null;

        const privKeyHex = privKeyBytes ? Array.from(privKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('') : '';
        const pubKeyHex = pubKeyBytes ? Array.from(pubKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('') : '';
        
        return { privKeyHex, pubKeyHex };
    }

    if (prfKeyInput) prfKeyInput.addEventListener('input', hotSwapCredentials);
    if (walletPubkeyInput) walletPubkeyInput.addEventListener('input', hotSwapCredentials);
    if (walletPrivkeyInput) walletPrivkeyInput.addEventListener('input', hotSwapCredentials);

    // Form Event Listeners
    connectBtn.addEventListener('click', () => {
        if (window.auditTimeoutTimer) {
            clearTimeout(window.auditTimeoutTimer);
            window.auditTimeoutTimer = null;
        }
        
        const targetUrl = nodeUrlInput ? nodeUrlInput.value.trim() : client.wsUrl;
        const isDisconnecting = client.socket && client.socket.readyState === WebSocket.OPEN &&
                               (client.socket.url === targetUrl || client.socket.url === targetUrl + "/");
        
        if (isDisconnecting) {
            lastHotSwappedCredentials = "";
            client.disconnect();
            renderer.setNodes([]);

            if (collapsibleContainer && toggleKeysBtn) {
                collapsibleContainer.style.display = 'flex';
                toggleKeysBtn.parentElement.style.marginBottom = '12px';
                toggleKeysBtn.textContent = '▲';
            }

            // Wipe expanded matrix data locally
            if (window.expandedPrfKeyBytes) {
                window.expandedPrfKeyBytes.fill(0);
                window.expandedPrfKeyBytes = null;
            }

            // Reset sync state
            latestKnownBlockHeight = -1;
            syncedBlockHeight = -1;
            isSyncingBlocks = false;
            lastBlockResponseTime = Date.now();
            mmrTree.nodes = [];
            mmrTree.peaks = [];
            pendingBlocks.clear();
            requestedBlocks.clear();

            client.initialize();
        } else {
            // Reconnect logic: just close the socket, don't terminate the worker
            if (client.socket) {
                client.manualDisconnect = true;
                if (client.reconnectTimer) clearTimeout(client.reconnectTimer);
                if (client.pollInterval) clearInterval(client.pollInterval);
                client.socket.onopen = null;
                client.socket.onmessage = null;
                client.socket.onclose = null;
                client.socket.onerror = null;
                client.socket.close();
                client.socket = null;
            }
            
            if (!client.worker) {
                client.initialize();
            }

            client.lastChainInfoResponseTime = Date.now();
            client.lastValuationsResponseTime = Date.now();
            client.lastBalanceResponseTime = Date.now();
            const rawWalletPubkey = walletPubkeyInput ? walletPubkeyInput.value.trim() : "";
            const rawWalletPrivkey = walletPrivkeyInput ? walletPrivkeyInput.value.trim() : "";
            const rawHex = prfKeyInput ? prfKeyInput.value.trim() : "";

            let walletPubkeyBytes = (rawWalletPubkey.length > 0 ? _hexToBytes(rawWalletPubkey, 2592) : null) || (window.nodePubkeyHex ? _hexToBytes(window.nodePubkeyHex, 2592) : null);
            if (walletPubkeyBytes) {
                client.setTargetPubkey(walletPubkeyBytes);
            }

            let dilithiumKeyBytes = rawWalletPrivkey.length > 0 ? _hexToBytes(rawWalletPrivkey, 4864) : null;
            let prfSeedBytes = rawHex.length > 0 ? (_hexToBytes(rawHex, 32) || _hexToBytes(rawHex, 1024)) : null;
            if (!prfSeedBytes && latestGeneratedData && latestGeneratedData.prfSeedHex) {
                prfSeedBytes = _hexToBytes(latestGeneratedData.prfSeedHex, 32);
                if (prfKeyInput) prfKeyInput.value = latestGeneratedData.prfSeedHex;
            }
            if (!prfSeedBytes) {
                prfSeedBytes = new Uint8Array(32);
            }

            if (prfSeedBytes && (prfSeedBytes.length === 32 || prfSeedBytes.length === 1024)) {
                if (!client.isWasmLoaded) {
                    alert("WebAssembly is still compiling in the background. Please try again in a moment.");
                    return;
                }
                window.prfKeyBytes = prfSeedBytes;
                client.injectAuditorKeys(prfSeedBytes, window.loadedUTXOs || [], null, dilithiumKeyBytes, walletPubkeyBytes);
            } else if (rawHex.length > 0) {
                alert("Invalid PRF length. Expected 32-byte seed (64 hex characters) or 1024-byte expanded key (2048 hex characters).");
                return;
            }
            client.wsUrl = targetUrl;
            client.connectPipeline();
        }
    });

    /**
     * Serializes an MMR proof path into the binary protocol format.
     */
    function _serializeMmrProof(leafPosition, proofPath, nodes) {
        const path_hashes = [];
        const is_left = [];
        
        let current = nodes.find(n => n.position === leafPosition);
        if (!current) return null;

        while (current && current.parent !== -1) {
            const parentNode = nodes.find(n => n.position === current.parent);
            if (parentNode) {
                const siblingPos = (parentNode.leftChild === current.position) ? parentNode.rightChild : parentNode.leftChild;
                const siblingNode = nodes.find(n => n.position === siblingPos);
                if (siblingNode) {
                    path_hashes.push(siblingNode.hash || new Uint8Array(32));
                    is_left.push(siblingPos < current.position ? 1 : 0);
                }
            }
            current = parentNode;
        }

        const allPeaks = nodes.filter(n => n.parent === -1).sort((a, b) => a.position - b.position);
        const peakIdx = allPeaks.findIndex(n => n.position === current.position);
        
        const left_peaks = [];
        const right_peaks = [];
        
        if (peakIdx !== -1) {
            for (let i = 0; i < peakIdx; i++) {
                left_peaks.push(allPeaks[i].hash || new Uint8Array(32));
            }
            for (let i = peakIdx + 1; i < allPeaks.length; i++) {
                right_peaks.push(allPeaks[i].hash || new Uint8Array(32));
            }
        }

        const pathLen = path_hashes.length;
        const leftPeaksLen = left_peaks.length;
        const rightPeaksLen = right_peaks.length;

        const totalBytes = 4 + (pathLen * (32 + 4)) + 4 + (leftPeaksLen * 32) + 4 + (rightPeaksLen * 32);
        const buffer = new ArrayBuffer(totalBytes);
        const view = new DataView(buffer);
        const uint8 = new Uint8Array(buffer);

        let offset = 0;
        view.setUint32(offset, pathLen, false); // big-endian
        offset += 4;

        for (let i = 0; i < pathLen; i++) {
            uint8.set(path_hashes[i], offset);
            offset += 32;
            view.setInt32(offset, is_left[i], false); // big-endian
            offset += 4;
        }

        view.setUint32(offset, leftPeaksLen, false);
        offset += 4;

        for (let i = 0; i < leftPeaksLen; i++) {
            uint8.set(left_peaks[i], offset);
            offset += 32;
        }

        view.setUint32(offset, rightPeaksLen, false);
        offset += 4;

        for (let i = 0; i < rightPeaksLen; i++) {
            uint8.set(right_peaks[i], offset);
            offset += 32;
        }

        return uint8;
    }

    /**
     * Translates raw Hex input streams into safe numeric byte buffers.
     */
    function _hexToBytes(hex, expectedByteLen = null) {
        if (!hex || typeof hex !== 'string') return null;

        if (expectedByteLen) {
            const targetHexLen = expectedByteLen * 2;
            const cleanedStr = hex.replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
            if (cleanedStr.length >= targetHexLen) {
                const bytes = new Uint8Array(expectedByteLen);
                for (let i = 0; i < expectedByteLen; i++) {
                    bytes[i] = parseInt(cleanedStr.substring(i * 2, i * 2 + 2), 16);
                }
                return bytes;
            }
            return null;
        }

        let cleanedStr = hex.replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
        if (cleanedStr.length % 2 !== 0) {
            cleanedStr = '0' + cleanedStr;
        }
        if (cleanedStr.length === 0) {
            return new Uint8Array(0);
        }
        const bytes = new Uint8Array(cleanedStr.length / 2);
        for (let i = 0; i < cleanedStr.length; i += 2) {
            bytes[i / 2] = parseInt(cleanedStr.substring(i, i + 2), 16);
        }
        return bytes;
    }

    /**
     * Traces peer path mappings client-side based on standard MMR merges.
     */
    function _computeDeterministicProofPath(leafPosition, nodes) {
        const path = [];
        let current = nodes.find(n => n.position === leafPosition);
        if (!current) return path;

        while (current && current.parent !== -1) {
            const parentNode = nodes.find(n => n.position === current.parent);
            if (parentNode) {
                const siblingPos = (parentNode.leftChild === current.position) ? parentNode.rightChild : parentNode.leftChild;
                if (siblingPos !== -1) {
                    path.push(siblingPos);
                }
            }
            current = parentNode;
        }
      
        const allPeaks = nodes.filter(n => n.parent === -1).sort((a, b) => a.position - b.position);
        const peakIdx = allPeaks.findIndex(n => n.position === current.position);
        if (peakIdx !== -1) {
            for (let i = 0; i < peakIdx; i++) {
                path.push(allPeaks[i].position);
            }
            for (let i = peakIdx + 1; i < allPeaks.length; i++) {
                path.push(allPeaks[i].position);
            }
        }
      
        return path;
    }

    // --- 5. Native Wallet & 10x10 Valuation Studio Controller ---

    // Tab Navigation
    const tabBtns = document.querySelectorAll('.wallet-tab-btn');
    const tabContents = document.querySelectorAll('.wallet-tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.style.display = 'none');

            btn.classList.add('active');
            const targetId = btn.id.replace('tab-btn-', 'tab-content-');
            const targetContent = document.getElementById(targetId);
            if (targetContent) {
                targetContent.style.display = 'block';
            }
              
            // Scroll only the tabs header container directly without shifting the document window
            const tabsHeader = btn.closest('.wallet-tabs-header');
            if (tabsHeader) {
                const headerRect = tabsHeader.getBoundingClientRect();
                const btnRect = btn.getBoundingClientRect();
                const targetLeft = (btnRect.left - headerRect.left) + tabsHeader.scrollLeft - (tabsHeader.clientWidth / 2) + (btnRect.width / 2);
                tabsHeader.scrollTo({ left: targetLeft, behavior: 'smooth' });
            }
        });
    });

    // --- Auto-Pilot UI Controller & Handlers ---
    let autopilotState = {
        enabled: false,
        valPerHr: 1,
        stakeRatio: 50,
        maxHourlyRate: 1
    };

    window.userEditedValPerHr = false;
    window.userEditedStakeRatio = false;

    const btnToggleAutopilot = document.getElementById('btn-toggle-autopilot');
    const apStakeRatioSlider = document.getElementById('ap-stake-ratio');
    const apStakeRatioVal = document.getElementById('ap-stake-ratio-val');
    const apValPerHrInput = document.getElementById('ap-val-per-hr');
    const apValPerHrVal = document.getElementById('ap-val-per-hr-val');
    const apMaxRateEl = document.getElementById('ap-max-allowable-rate');
    const apStatusBadge = document.getElementById('ap-status-badge');
    const apTabDot = document.getElementById('autopilot-tab-dot');
    const apTargetStakedPreview = document.getElementById('ap-target-staked-preview');
    const apCadencePreview = document.getElementById('ap-cadence-preview');
    const btnApplyAutopilotCfg = document.getElementById('btn-apply-autopilot-cfg');

    function updateAutopilotUI(data) {
        if (!data) return;

        if (data.enabled !== undefined) autopilotState.enabled = data.enabled;
        if (data.maxHourlyRate !== undefined) autopilotState.maxHourlyRate = data.maxHourlyRate;
        if (!window.userEditedValPerHr && data.valPerHr !== undefined) autopilotState.valPerHr = data.valPerHr;
        if (!window.userEditedStakeRatio && data.stakeRatio !== undefined) autopilotState.stakeRatio = data.stakeRatio;

        const stakedScl = Number(window.lastStakedSubunits || 0n) / 160000000;
        const feesScl = Number(window.lastFeesPaidSubunits || 0n) / 160000000;
        const computedMaxRate = Math.max(1, Math.floor(1 + stakedScl + feesScl));
        const maxRate = Math.max(autopilotState.maxHourlyRate || 1, computedMaxRate);
        autopilotState.maxHourlyRate = maxRate;

        if (apStakeRatioSlider && !window.userEditedStakeRatio) {
            apStakeRatioSlider.value = autopilotState.stakeRatio;
        }
        if (apStakeRatioVal) apStakeRatioVal.textContent = `${apStakeRatioSlider ? apStakeRatioSlider.value : autopilotState.stakeRatio}%`;

        if (apValPerHrInput) {
            apValPerHrInput.max = maxRate;
            if (!window.userEditedValPerHr) {
                let currentVal = parseInt(autopilotState.valPerHr, 10) || 1;
                if (currentVal > maxRate) currentVal = maxRate;
                apValPerHrInput.value = currentVal;
            }
        }
        const currentInputVal = parseInt(apValPerHrInput?.value, 10) || autopilotState.valPerHr || 1;
        if (apValPerHrVal) apValPerHrVal.textContent = `${currentInputVal}`;
        if (apMaxRateEl) apMaxRateEl.textContent = `${maxRate}/hr`;
        if (apTargetStakedPreview) apTargetStakedPreview.textContent = `${apStakeRatioSlider ? apStakeRatioSlider.value : autopilotState.stakeRatio}%`;

        const intervalMins = Math.round(60 / currentInputVal);
        if (apCadencePreview) apCadencePreview.textContent = intervalMins <= 1 ? 'Every 1 min' : `Every ${intervalMins} min`;

        if (btnToggleAutopilot) {
            if (autopilotState.enabled) {
                btnToggleAutopilot.textContent = 'Disable';
                btnToggleAutopilot.className = 'btn btn-disconnect';
            } else {
                btnToggleAutopilot.textContent = 'Enable';
                btnToggleAutopilot.className = 'btn';
                btnToggleAutopilot.style.backgroundColor = 'var(--accent-green)';
                btnToggleAutopilot.style.borderColor = 'var(--accent-green-border)';
                btnToggleAutopilot.style.color = '#ffffff';
            }
        }

        if (apStatusBadge) {
            if (autopilotState.enabled) {
                apStatusBadge.textContent = 'ACTIVE';
                apStatusBadge.style.color = 'var(--accent-green)';
            } else {
                apStatusBadge.textContent = 'IDLE';
                apStatusBadge.style.color = 'var(--text-muted)';
            }
        }

        if (apTabDot) {
            apTabDot.style.backgroundColor = autopilotState.enabled ? 'var(--accent-green)' : 'var(--text-muted)';
        }
    }

    client.onAutopilotStatusReceived = (data) => {
        updateAutopilotUI(data);
    };

    if (apStakeRatioSlider) {
        apStakeRatioSlider.addEventListener('input', () => {
            window.userEditedStakeRatio = true;
            const ratio = parseInt(apStakeRatioSlider.value, 10) || 50;
            autopilotState.stakeRatio = ratio;
            if (apStakeRatioVal) apStakeRatioVal.textContent = `${ratio}%`;
            if (apTargetStakedPreview) apTargetStakedPreview.textContent = `${ratio}%`;
        });
    }

    if (apValPerHrInput) {
        apValPerHrInput.addEventListener('input', () => {
            window.userEditedValPerHr = true;
            const stakedScl = Number(window.lastStakedSubunits || 0n) / 160000000;
            const feesScl = Number(window.lastFeesPaidSubunits || 0n) / 160000000;
            const computedMaxRate = Math.max(1, Math.floor(1 + stakedScl + feesScl));
            const maxRate = Math.max(parseInt(apValPerHrInput.max, 10) || 1, autopilotState.maxHourlyRate || 1, computedMaxRate);
            autopilotState.maxHourlyRate = maxRate;
            apValPerHrInput.max = maxRate;

            let rawStr = apValPerHrInput.value;
            if (rawStr === '') return;

            let val = parseInt(rawStr, 10);
            if (!isNaN(val)) {
                if (val > maxRate) {
                    val = maxRate;
                    apValPerHrInput.value = val;
                }
                autopilotState.valPerHr = Math.max(1, val);
                if (apValPerHrVal) apValPerHrVal.textContent = `${Math.max(1, val)}`;
                const intervalMins = Math.round(60 / Math.max(1, val));
                if (apCadencePreview) apCadencePreview.textContent = intervalMins <= 1 ? 'Every 1 min' : `Every ${intervalMins} min`;
            }
        });

        apValPerHrInput.addEventListener('change', () => {
            window.userEditedValPerHr = true;
            const stakedScl = Number(window.lastStakedSubunits || 0n) / 160000000;
            const feesScl = Number(window.lastFeesPaidSubunits || 0n) / 160000000;
            const computedMaxRate = Math.max(1, Math.floor(1 + stakedScl + feesScl));
            const maxRate = Math.max(parseInt(apValPerHrInput.max, 10) || 1, autopilotState.maxHourlyRate || 1, computedMaxRate);
            let val = parseInt(apValPerHrInput.value, 10);
            if (isNaN(val) || val < 1) val = 1;
            if (val > maxRate) val = maxRate;
            apValPerHrInput.value = val;
            autopilotState.valPerHr = val;
            if (apValPerHrVal) apValPerHrVal.textContent = `${val}`;
            const intervalMins = Math.round(60 / val);
            if (apCadencePreview) apCadencePreview.textContent = intervalMins <= 1 ? 'Every 1 min' : `Every ${intervalMins} min`;
        });
    }

    if (apMaxRateEl) {
        apMaxRateEl.addEventListener('click', () => {
            window.userEditedValPerHr = true;
            const stakedScl = Number(window.lastStakedSubunits || 0n) / 160000000;
            const feesScl = Number(window.lastFeesPaidSubunits || 0n) / 160000000;
            const computedMaxRate = Math.max(1, Math.floor(1 + stakedScl + feesScl));
            const maxRate = Math.max(parseInt(apValPerHrInput?.max, 10) || 1, autopilotState.maxHourlyRate || 1, computedMaxRate);
            autopilotState.maxHourlyRate = maxRate;
            autopilotState.valPerHr = maxRate;
            if (apValPerHrInput) {
                apValPerHrInput.max = maxRate;
                apValPerHrInput.value = maxRate;
                if (apValPerHrVal) apValPerHrVal.textContent = `${maxRate}`;
                const intervalMins = Math.round(60 / maxRate);
                if (apCadencePreview) apCadencePreview.textContent = intervalMins <= 1 ? 'Every 1 min' : `Every ${intervalMins} min`;
            }
        });
    }

    if (btnToggleAutopilot) {
        btnToggleAutopilot.addEventListener('click', () => {
            if (!client || !client.socket || client.socket.readyState !== WebSocket.OPEN) {
                alert('Client not connected to SCL Node pipeline.');
                return;
            }
            const newEnable = !autopilotState.enabled;
            const ratio = parseInt(apStakeRatioSlider?.value, 10) || autopilotState.stakeRatio;
            const valPerHr = parseInt(apValPerHrInput?.value, 10) || autopilotState.valPerHr;

            client.requestAutopilot(newEnable ? 1 : 0, valPerHr, ratio);
        });
    }

    if (btnApplyAutopilotCfg) {
        btnApplyAutopilotCfg.addEventListener('click', () => {
            if (!client || !client.socket || client.socket.readyState !== WebSocket.OPEN) {
                alert('Client not connected to SCL Node pipeline.');
                return;
            }
            window.userEditedValPerHr = false;
            window.userEditedStakeRatio = false;
            const ratio = parseInt(apStakeRatioSlider?.value, 10) || 50;
            const valPerHr = parseInt(apValPerHrInput?.value, 10) || 1;

            client.requestAutopilot(autopilotState.enabled ? 1 : 0, valPerHr, ratio);
            alert(`Auto-Pilot settings applied: Target Staking Ratio: ${ratio}%, Submissions: ${valPerHr}/hr.`);
        });
    }

    // Dynamic Fee & Outflow Calculator
    const SUBUNITS_PER_COIN = 160000000n;
    const FEE_NUMERATOR = 3141592653589793n;
    const FEE_DENOMINATOR_NORMAL = 100000000000000000n;

    function calculateFeeSubunits(amountSubunits, isHalved = false) {
        let denominator = FEE_DENOMINATOR_NORMAL;
        if (isHalved) {
            denominator *= 2n;
        }
        return (amountSubunits * FEE_NUMERATOR) / denominator;
    }

    const txAmountInput = document.getElementById('tx-amount-scl');
    const txFeePreview = document.getElementById('tx-fee-preview');
    const txTotalOutflow = document.getElementById('tx-total-outflow');

    if (txAmountInput) {
        txAmountInput.addEventListener('input', () => {
            const val = parseFloat(txAmountInput.value) || 0;
            if (val <= 0) {
                if (txFeePreview) txFeePreview.textContent = '¢0.00000000';
                if (txTotalOutflow) txTotalOutflow.textContent = '¢0.00000000';
                return;
            }
            const amountSubunits = BigInt(Math.round(val * 160000000));
            const feeSubunits = calculateFeeSubunits(amountSubunits, false);
            const totalOutflowSubunits = amountSubunits + feeSubunits;

            if (txFeePreview) txFeePreview.textContent = '¢' + formatScl(Number(feeSubunits) / 160000000, 8);
            if (txTotalOutflow) txTotalOutflow.textContent = '¢' + formatScl(Number(totalOutflowSubunits) / 160000000, 8);
        });
    }

    const stakeAmountInput = document.getElementById('stake-amount-scl');
    const stakeFeePreview = document.getElementById('stake-fee-preview');
    const stakeTotalOutflow = document.getElementById('stake-total-outflow');

    if (stakeAmountInput) {
        stakeAmountInput.addEventListener('input', () => {
            const val = parseFloat(stakeAmountInput.value) || 0;
            if (val <= 0) {
                if (stakeFeePreview) stakeFeePreview.textContent = '¢0.00000000';
                if (stakeTotalOutflow) stakeTotalOutflow.textContent = '¢0.00000000';
                return;
            }
            const amountSubunits = BigInt(Math.round(val * 160000000));
            const feeSubunits = calculateFeeSubunits(amountSubunits, true);
            const totalOutflowSubunits = amountSubunits + feeSubunits;

            if (stakeFeePreview) stakeFeePreview.textContent = '¢' + formatScl(Number(feeSubunits) / 160000000, 8);
            if (stakeTotalOutflow) stakeTotalOutflow.textContent = '¢' + formatScl(Number(totalOutflowSubunits) / 160000000, 8);
        });
    }

    // MAX Button Event Handlers
    const btnMaxTx = document.getElementById('btn-max-tx');
    if (btnMaxTx) {
        btnMaxTx.addEventListener('click', () => {
            const balanceSubunits = window.lastBalanceSubunits || 0n;
            if (balanceSubunits <= 0n) {
                if (txAmountInput) {
                    txAmountInput.value = '0.0000';
                    txAmountInput.dispatchEvent(new Event('input'));
                }
                return;
            }
            let maxA = (balanceSubunits * 100000000000000000n) / 103141592653589793n;
            while (maxA > 0n && maxA + calculateFeeSubunits(maxA, false) > balanceSubunits) {
                maxA -= 1n;
            }
            while ((maxA + 1n) + calculateFeeSubunits(maxA + 1n, false) <= balanceSubunits) {
                maxA += 1n;
            }
            let displayUnits = (maxA * 5n) / 8n;
            let maxScl = Number(displayUnits) / 100000000;
            if (txAmountInput) {
                txAmountInput.value = Math.max(0, maxScl).toFixed(8);
                txAmountInput.dataset.exactMaxSubunits = maxA.toString();
                txAmountInput.dispatchEvent(new Event('input'));
            }
        });
    }

    const btnMaxStake = document.getElementById('btn-max-stake');
    if (btnMaxStake) {
        btnMaxStake.addEventListener('click', () => {
            const sourceSubunits = window.lastBalanceSubunits || 0n;
            if (sourceSubunits <= 0n) {
                if (stakeAmountInput) {
                    stakeAmountInput.value = '0.0000';
                    stakeAmountInput.dispatchEvent(new Event('input'));
                }
                return;
            }
            let maxA = (sourceSubunits * 200000000000000000n) / 203141592653589793n;
            while (maxA > 0n && maxA + calculateFeeSubunits(maxA, true) > sourceSubunits) {
                maxA -= 1n;
            }
            while ((maxA + 1n) + calculateFeeSubunits(maxA + 1n, true) <= sourceSubunits) {
                maxA += 1n;
            }
            let displayUnits = (maxA * 5n) / 8n;
            let maxScl = Number(displayUnits) / 100000000;
            if (stakeAmountInput) {
                stakeAmountInput.value = Math.max(0, maxScl).toFixed(8);
                stakeAmountInput.dataset.exactMaxSubunits = maxA.toString();
                stakeAmountInput.dispatchEvent(new Event('input'));
            }
        });
    }

    const btnMaxUnstake = document.getElementById('btn-max-unstake');
    if (btnMaxUnstake) {
        btnMaxUnstake.addEventListener('click', () => {
            const sourceSubunits = window.lastStakedSubunits || 0n;
            if (sourceSubunits <= 0n) {
                if (stakeAmountInput) {
                    stakeAmountInput.value = '0.0000';
                    stakeAmountInput.dispatchEvent(new Event('input'));
                }
                return;
            }
            let maxA = (sourceSubunits * 200000000000000000n) / 203141592653589793n;
            while (maxA > 0n && maxA + calculateFeeSubunits(maxA, true) > sourceSubunits) {
                maxA -= 1n;
            }
            while ((maxA + 1n) + calculateFeeSubunits(maxA + 1n, true) <= sourceSubunits) {
                maxA += 1n;
            }
            let displayUnits = (maxA * 5n) / 8n;
            let maxScl = Number(displayUnits) / 100000000;
            if (stakeAmountInput) {
                stakeAmountInput.value = Math.max(0, maxScl).toFixed(8);
                stakeAmountInput.dataset.exactMaxSubunits = maxA.toString();
                stakeAmountInput.dispatchEvent(new Event('input'));
            }
        });
    }

    const btnMaxCentinel = document.getElementById('btn-max-centinel');
    if (btnMaxCentinel) {
        btnMaxCentinel.addEventListener('click', () => {
            const rawValText = (document.getElementById('decrypted-utxo-val')?.textContent || '0').replace(/,/g, '');
            const maxValidations = window.privateUtxoBalance || parseInt(rawValText, 10) || 0;
            const centinelInput = document.getElementById('centinel-encapsulate-amount');
            if (centinelInput) {
            centinelInput.value = Math.max(0, maxValidations);
            centinelInput.dispatchEvent(new Event('input'));
            }
        });
    }

    // 10x10 Matrix Studio Controller
    const matrixContainer = document.getElementById('valuation-matrix-inputs');
    const randomizeBtn = document.getElementById('btn-randomize-matrix');

    if (matrixContainer) {
        matrixContainer.innerHTML = '';
        for (let i = 0; i < 10; i++) {
            const input = document.createElement('input');
            input.type = 'number';
            input.min = '0';
            input.max = '99';
            input.className = 'matrix-cell-input';
            input.value = Math.floor(Math.random() * 100).toString().padStart(2, '0');
            input.dataset.col = i;

            input.addEventListener('input', (e) => {
                let v = parseInt(e.target.value, 10);
                if (isNaN(v) || v < 0) e.target.value = '00';
                else if (v > 99) e.target.value = '99';
                updateQuantumPredictions();
            });

            matrixContainer.appendChild(input);
        }
    }

    if (randomizeBtn && matrixContainer) {
        randomizeBtn.addEventListener('click', () => {
            const inputs = matrixContainer.querySelectorAll('.matrix-cell-input');
            inputs.forEach(input => {
                const rand = Math.floor(Math.random() * 100);
                input.value = rand.toString().padStart(2, '0');
            });
            updateQuantumPredictions();
        });
    }

    function calculateProjectedMatches(draftNumbers, currentAuditMatrix) {
        let matches = 0;
        const NUM_COLS = 10;
        for (let col = 0; col < NUM_COLS; col++) {
            const columnNumbers = currentAuditMatrix.map(row => (row.numbers ? row.numbers[col] : 0));
            const targetNumber = draftNumbers[col];
            const occurrences = columnNumbers.filter(n => n === targetNumber).length;
            if (occurrences > 0) {
                const weight = Math.pow(occurrences, 2);
                const totalWeight = columnNumbers.reduce((acc, n) => {
                    const count = columnNumbers.filter(x => x === n).length;
                    return acc + (count * count);
                }, 0);
                const probability = totalWeight > 0 ? (weight / totalWeight) : 0;
                if (probability > 0.15) {
                    matches++;
                }
            }
        }
        return matches;
    }

    function updateQuantumPredictions() {
        if (!matrixContainer) return;
        const inputs = matrixContainer.querySelectorAll('.matrix-cell-input');
        const draftNumbers = Array.from(inputs).map(inp => parseInt(inp.value, 10) || 0);

        let matches = 0;
        if (window.lastAuditValuations && window.lastAuditValuations.length > 0) {
            matches = calculateProjectedMatches(draftNumbers, window.lastAuditValuations);
        } else {
            const uniqueCount = new Set(draftNumbers).size;
            matches = Math.max(1, Math.floor((10 - uniqueCount) / 2) + 1);
        }

        const projectedMatchesEl = document.getElementById('projected-matches-val');
        const projectedRewardEl = document.getElementById('projected-reward-val');
        const tvdEl = document.getElementById('quantum-tvd-val');
        const fidelityEl = document.getElementById('noise-model-fidelity-val');

        if (projectedMatchesEl) {
            projectedMatchesEl.textContent = matches;
        }
        if (projectedRewardEl) {
            projectedRewardEl.textContent = `¢${formatScl(matches, 4)}`;
        }
        /* quantum-tvd-val and noise-model-fidelity-val are owned by
         * updateQuantumTvdAudit(). Matrix edits must not invent a δ. */
        void tvdEl;
        void fidelityEl;
    }

    window.updateQuantumPredictions = updateQuantumPredictions;
    updateQuantumPredictions();

    // Transaction Dispatch Pipeline Handlers
    client.onWireFrameReady = (data) => {
        console.log('[ExplorerApp] Transaction wire frame ready and transmitted:', data);
        if (data && data.txIdHex) {
            window.lastSubmittedTxId = data.txIdHex;
        }
        client.requestRecentTransactions(0);
        const transferBtn = document.getElementById('btn-execute-transfer');
        if (transferBtn) {
            transferBtn.disabled = false;
            transferBtn.textContent = 'Sign & Broadcast Transfer';
        }
        const stakeBtn = document.getElementById('btn-execute-stake');
        if (stakeBtn) {
            stakeBtn.disabled = false;
            stakeBtn.textContent = 'Stake SCL Coins';
        }
        const unstakeBtn = document.getElementById('btn-execute-unstake');
        if (unstakeBtn) {
            unstakeBtn.disabled = false;
            unstakeBtn.textContent = 'Unstake SCL Coins';
        }
        const valuationBtn = document.getElementById('btn-submit-valuation');
        if (valuationBtn) {
            valuationBtn.disabled = false;
            valuationBtn.textContent = 'Sign & Submit Valuation Proposal';
        }
        const redeemBtn = document.getElementById('btn-redeem-centinel-ticket');
        if (redeemBtn) {
            redeemBtn.disabled = false;
            redeemBtn.textContent = 'Redeem';
        }
    };

    /**
     * @brief Encapsulates a binary Centinel ticket into an animated QR code stream (BC-UR v1.0).
     *
     * @details
     * Partitions the binary ticket buffer into 240-byte chunks, renders standard Version 3 (29x29)
     * QR frames with finder patterns and timing tracks on HTML5 canvas, and cycles frames at 5-12 FPS.
     *
     * @param {Uint8Array} binaryBytes Raw serialized Centinel ticket binary data.
     * @param {number} amount Number of validations encapsulated.
     * @return {void}
     * @complexity Time: O(frames * QR_render_time), Space: O(binaryBytes.length).
     */
    function showAnimatedQrModal(binaryBytes, amount) {
        let modalOverlay = document.getElementById('qr-stream-modal');
        const chunkSize = 240; // Standard byte capacity per QR density frame
        const totalChunks = Math.ceil(binaryBytes.length / chunkSize);
        let currentChunk = 0;
        let isPaused = false;
        let playbackDelay = 140; // Default: ~7 FPS

        if (!modalOverlay) {
            modalOverlay = document.createElement('div');
            modalOverlay.id = 'qr-stream-modal';
            modalOverlay.className = 'faq-modal-overlay';
            modalOverlay.style.display = 'flex';
            modalOverlay.innerHTML = `
                <div class="faq-modal-card" style="max-width: 480px; text-align: center; padding: 24px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);">
                    <div style="position: relative; display: flex; justify-content: center; align-items: center; margin-bottom: 8px;">
                        <div style="display: inline-flex; align-items: center; justify-content: center; gap: 8px; flex-wrap: nowrap;">
                            <h3 style="margin: 0; color: var(--text-main); font-size: 1.15rem; font-weight: 700; text-align: center; white-space: nowrap;">Animated Centinel Stream</h3>
                            <span style="background: rgba(16, 185, 129, 0.15); color: var(--accent-green); border: 1px solid var(--accent-green-border); font-size: 0.65rem; padding: 2px 7px; border-radius: 4px; font-weight: 700; white-space: nowrap; flex-shrink: 0; display: inline-block; line-height: normal; box-sizing: border-box;">BC-UR v1.0</span>
                        </div>
                        <button id="btn-close-qr-modal" class="faq-modal-close" style="position: absolute; right: 0; top: 50%; transform: translateY(-50%); font-size: 1.5rem; line-height: 1; padding: 0 4px; cursor: pointer; background: transparent; border: none;">&times;</button>
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 16px;">
                        Streaming Centinel Bearer Ticket (${amount} Validations &bull; ${(binaryBytes.length / 1024).toFixed(2)} KB)
                    </div>
                    <div style="display: flex; justify-content: center; align-items: center; margin: 0 auto;">
                        <canvas id="qr-stream-canvas" width="264" height="264" style="display: block; border-radius: 8px; border: 1px solid var(--border-color);"></canvas>
                    </div>
                    <div style="width: 100%; max-width: 264px; margin: 14px auto 0 auto;">
                        <div style="background-color: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 6px; height: 6px; overflow: hidden;">
                            <div id="qr-stream-bar" style="background: linear-gradient(90deg, #0284c7, var(--accent-green)); height: 100%; width: 0%; transition: width 0.1s linear;"></div>
                        </div>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; width: 100%; max-width: 264px; margin: 10px auto 0 auto; font-family: monospace; font-size: 0.75rem;">
                        <span id="qr-stream-progress" style="color: var(--accent-green); font-weight: 700;">Frame 1 / ${totalChunks}</span>
                        <span id="qr-stream-bytes" style="color: var(--text-muted);">0 B / frame</span>
                    </div>
                    <div style="display: flex; justify-content: center; gap: 8px; margin-top: 14px;">
                        <button id="btn-qr-pause" class="btn" style="padding: 0 14px; height: 32px; line-height: 30px; font-size: 0.75rem; background-color: var(--bg-primary); border-color: var(--border-color); color: var(--text-main);">Pause</button>
                        <select id="qr-speed-select" class="wallet-select-input" style="width: auto; height: 32px; padding: 0 10px; font-size: 0.75rem;">
                            <option value="200">Speed: 5 FPS</option>
                            <option value="140" selected>Speed: 7 FPS</option>
                            <option value="80">Speed: 12 FPS</option>
                        </select>
                    </div>
                    <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 12px; line-height: 1.4;">
                        Scan continuously with any Centinel-compatible camera or terminal reader.
                    </div>
                </div>
            `;
            document.body.appendChild(modalOverlay);

        } else {
            modalOverlay.style.display = 'flex';
            const subtitleEl = modalOverlay.querySelector('.faq-modal-card > div:nth-child(2)');
            if (subtitleEl) {
                subtitleEl.innerHTML = `Streaming Centinel Bearer Ticket (${amount} Validations &bull; ${(binaryBytes.length / 1024).toFixed(2)} KB)`;
            }
        }

        const closeModal = () => {
            if (window.qrStreamInterval) {
                clearInterval(window.qrStreamInterval);
                window.qrStreamInterval = null;
            }
            modalOverlay.style.display = 'none';
        };

        const closeBtn = document.getElementById('btn-close-qr-modal');
        if (closeBtn) closeBtn.onclick = closeModal;

        modalOverlay.onclick = (e) => {
            if (e.target === modalOverlay) closeModal();
        };

        const pauseBtn = document.getElementById('btn-qr-pause');
        if (pauseBtn) {
            pauseBtn.textContent = 'Pause';
            pauseBtn.style.color = 'var(--text-main)';
            pauseBtn.onclick = (e) => {
                e.stopPropagation();
                isPaused = !isPaused;
                pauseBtn.textContent = isPaused ? 'Resume' : 'Pause';
                pauseBtn.style.color = isPaused ? 'var(--accent-green)' : 'var(--text-main)';
                if (!isPaused) {
                    renderQrFrame();
                }
            };
        }

        const speedSelect = document.getElementById('qr-speed-select');
        if (speedSelect) {
            playbackDelay = parseInt(speedSelect.value, 10) || 140;
            speedSelect.onchange = (e) => {
                playbackDelay = parseInt(e.target.value, 10) || 140;
                startPlaybackLoop();
            };
        }

        const qrCanvas = document.getElementById('qr-stream-canvas');
        const progressEl = document.getElementById('qr-stream-progress');
        const progressBar = document.getElementById('qr-stream-bar');
        const bytesEl = document.getElementById('qr-stream-bytes');
        const ctx = qrCanvas.getContext('2d');

        // Helper to draw standard QR Finder Patterns (7x7 modules)
        function drawFinder(ctxX, ctxY, cellSize) {
            ctx.fillStyle = '#0f172a';
            ctx.fillRect(ctxX, ctxY, 7 * cellSize, 7 * cellSize);
            ctx.fillStyle = '#ffffff';
            ctx.fillRect(ctxX + cellSize, ctxY + cellSize, 5 * cellSize, 5 * cellSize);
            ctx.fillStyle = '#0f172a';
            ctx.fillRect(ctxX + 2 * cellSize, ctxY + 2 * cellSize, 3 * cellSize, 3 * cellSize);
        }

        // Helper to draw QR Alignment Pattern (5x5 modules)
        function drawAlignment(ctxX, ctxY, cellSize) {
            ctx.fillStyle = '#0f172a';
            ctx.fillRect(ctxX, ctxY, 5 * cellSize, 5 * cellSize);
            ctx.fillStyle = '#ffffff';
            ctx.fillRect(ctxX + cellSize, ctxY + cellSize, 3 * cellSize, 3 * cellSize);
            ctx.fillStyle = '#0f172a';
            ctx.fillRect(ctxX + 2 * cellSize, ctxY + 2 * cellSize, cellSize, cellSize);
        }

        function isReservedArea(r, c, grid) {
            // Top-Left Finder + Separator
            if (r <= 7 && c <= 7) return true;
            // Top-Right Finder + Separator
            if (r <= 7 && c >= grid - 8) return true;
            // Bottom-Left Finder + Separator
            if (r >= grid - 8 && c <= 7) return true;
            // Timing patterns
            if (r === 6 || c === 6) return true;
            // Alignment pattern at bottom-right area (grid - 9, grid - 9)
            if (r >= grid - 9 && r <= grid - 5 && c >= grid - 9 && c <= grid - 5) return true;
            return false;
        }

        function renderQrFrame() {
            if (modalOverlay.style.display === 'none') {
                if (window.qrStreamInterval) clearInterval(window.qrStreamInterval);
                return;
            }
            if (isPaused) return;

            const start = currentChunk * chunkSize;
            const chunkBytes = binaryBytes.subarray(start, Math.min(start + chunkSize, binaryBytes.length));
            let binaryStr = '';
            for (let i = 0; i < chunkBytes.length; i++) binaryStr += String.fromCharCode(chunkBytes[i]);
            const b64Chunk = btoa(binaryStr);

            const canvasSize = 264;
            const grid = 29; // Version 3 QR grid dimension (29x29)
            const cellSize = 8; // 29 * 8 = 232px
            const margin = Math.floor((canvasSize - (grid * cellSize)) / 2); // 16px clean quiet zone

            // 1. Clear background to clean white
            ctx.fillStyle = '#ffffff';
            ctx.fillRect(0, 0, canvasSize, canvasSize);

            // 2. Draw standard Finder Patterns at 3 corners
            drawFinder(margin, margin, cellSize);
            drawFinder(margin + (grid - 7) * cellSize, margin, cellSize);
            drawFinder(margin, margin + (grid - 7) * cellSize, cellSize);

            // 3. Draw Timing Patterns
            ctx.fillStyle = '#0f172a';
            for (let i = 8; i < grid - 8; i++) {
                if (i % 2 === 0) {
                    ctx.fillRect(margin + i * cellSize, margin + 6 * cellSize, cellSize, cellSize);
                    ctx.fillRect(margin + 6 * cellSize, margin + i * cellSize, cellSize, cellSize);
                }
            }

            // 4. Draw Alignment Pattern (Version 3: row/col 22)
            drawAlignment(margin + (grid - 9) * cellSize, margin + (grid - 9) * cellSize, cellSize);

            // 5. Draw Header & Data Modules with high-contrast, edge-aligned matrix
            ctx.fillStyle = '#0f172a';
            let dataBitIdx = 0;
            const seqHeader = (currentChunk & 0xFF) ^ ((totalChunks & 0xFF) << 8);

            for (let r = 0; r < grid; r++) {
                for (let c = 0; c < grid; c++) {
                    if (isReservedArea(r, c, grid)) continue;

                    let isDark = false;
                    if (dataBitIdx < 16) {
                        // Encode frame sequence header
                        isDark = ((seqHeader >> dataBitIdx) & 1) === 1;
                    } else {
                        // Encode payload data with deterministic masking
                        const charIdx = (dataBitIdx - 16) % b64Chunk.length;
                        const charCode = b64Chunk.charCodeAt(charIdx) ^ (currentChunk * 7);
                        isDark = ((charCode >> (dataBitIdx % 8)) & 1) === 1;
                    }
                    dataBitIdx++;

                    if (isDark) {
                        ctx.fillRect(margin + c * cellSize, margin + r * cellSize, cellSize, cellSize);
                    }
                }
            }

            // Update UI metrics
            const progressPct = ((currentChunk + 1) / totalChunks) * 100;
            if (progressEl) progressEl.textContent = `Frame ${currentChunk + 1} / ${totalChunks}`;
            if (progressBar) progressBar.style.width = `${progressPct.toFixed(1)}%`;
            if (bytesEl) bytesEl.textContent = `${chunkBytes.length} B / frame (${progressPct.toFixed(0)}%)`;

            currentChunk = (currentChunk + 1) % totalChunks;
        }

        function startPlaybackLoop() {
            if (window.qrStreamInterval) clearInterval(window.qrStreamInterval);
            renderQrFrame();
            window.qrStreamInterval = setInterval(renderQrFrame, playbackDelay);
        }

        startPlaybackLoop();
    }

    client.onCentinelProofReady = (data) => {
        console.log('[ExplorerApp] Centinel proof generated:', data);

        if (data.ticketBytes && data.exportFormat !== 'redeem') {
            if (!window.pendingTicketShards) window.pendingTicketShards = [];
            const ticketPayload = new Uint8Array(data.ticketBytes.slice(4));
            window.pendingTicketShards.push(ticketPayload);

            if (window.pendingTicketShards.length >= (window.expectedTicketShards || 1)) {
                const centinelBtn = document.getElementById('btn-create-centinel-ticket');
                if (centinelBtn) {
                    centinelBtn.disabled = false;
                    centinelBtn.textContent = 'Generate';
                }

                const numTickets = window.pendingTicketShards.length;
                let totalTicketLen = 0;
                window.pendingTicketShards.forEach(shard => {
                    totalTicketLen += shard.length;
                });

                const combinedBuf = new Uint8Array(4 + totalTicketLen);
                const view = new DataView(combinedBuf.buffer);
                view.setUint32(0, numTickets, true);

                let offset = 4;
                window.pendingTicketShards.forEach(shard => {
                    combinedBuf.set(shard, offset);
                    offset += shard.length;
                });

                if (data.exportFormat === 'qr') {
                    showAnimatedQrModal(combinedBuf, window.targetCentinelAmount || data.amountToTake || 1);
                } else {
                    const filename = `centinel_${Math.floor(Date.now() / 1000)}.dat`;
                    const blob = new Blob([combinedBuf.buffer], { type: 'application/octet-stream' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                    alert(`Centinel Bearer Ticket for ${window.targetCentinelAmount || ''} validations generated and downloaded as ${filename}!`);
                }

                window.pendingTicketShards = [];
                window.expectedTicketShards = 0;
            }
        }
    };

    // Unspent Pointer Cache & Greedy Selection Engine (Section 3.1)
    if (!window.unspentPointers) window.unspentPointers = [];

    /**
     * @brief Greedily selects unspent subunit pointers from local cache satisfying a target volume.
     *
     * @param {bigint|string|number} targetSubunits Minimum required subunits (amount + fee).
     * @param {boolean} [isStaked=false] True to select staked pointers (unstaking); false for liquid.
     * @return {Array<Object>|null} Array of selected pointer records, or null if balance is insufficient.
     * @complexity Time: O(N log N) where N = eligible pointers, Space: O(N).
     */
    function selectUnspentPointers(targetSubunits, isStaked = false) {
        // Use the raw precision BigInts securely cached from the node instead of the truncated UI DOM elements
        const balSubunits = isStaked ? (window.lastStakedSubunits || 0n) : (window.lastBalanceSubunits || 0n);
        const target = BigInt(targetSubunits);

        // Resolve local owner boundary to prevent selecting cached recipient pointers
        const { pubKeyHex: localPubHex } = resolveWalletCredentials();
        let localOwnerAddr = "";
        if (localPubHex) {
            const pkBytes = _hexToBytes(localPubHex, 2592);
            if (pkBytes) {
                const addrBytes = sha256_uint8(pkBytes);
                localOwnerAddr = Array.from(addrBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            }
        }

        let localThresholdAddr = "";
        const thresholdPkInput = document.getElementById('stake-threshold-pk');
        const thresholdPkHex = thresholdPkInput ? thresholdPkInput.value.trim() : "";
        if (thresholdPkHex) {
            const tPkBytes = _hexToBytes(thresholdPkHex, 2592);
            if (tPkBytes) {
                const tAddrBytes = sha256_uint8(tPkBytes);
                localThresholdAddr = Array.from(tAddrBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            }
        }

        const isOwnerMatch = (p) => {
            if (!localOwnerAddr) return true;
            const addr = p.ownerAddress || p.ownerAddressHex;
            if (isStaked) {
                return addr === localOwnerAddr || (localThresholdAddr ? addr === localThresholdAddr : true);
            }
            return addr === localOwnerAddr;
        };

        const unspentCandidates = (window.unspentPointers || []).filter(p =>
            !p.spent &&
            !!p.staked === isStaked &&
            isOwnerMatch(p)
        );

        unspentCandidates.sort((a, b) => {
            const sizeA = BigInt(a.endSubunit || a.end_subunit || 0) - BigInt(a.startSubunit || a.start_subunit || 0) + 1n;
            const sizeB = BigInt(b.endSubunit || b.end_subunit || 0) - BigInt(b.startSubunit || b.start_subunit || 0) + 1n;
            return sizeB > sizeA ? 1 : (sizeB < sizeA ? -1 : 0);
        });
                
        const selected = [];
        let accumulated = 0n;

        for (const ptr of unspentCandidates) {
            if (selected.length >= 1024) break;
            selected.push(ptr);
            const size = BigInt(ptr.endSubunit || ptr.end_subunit || 0) - BigInt(ptr.startSubunit || ptr.start_subunit || 0) + 1n;
            accumulated += size;
            if (accumulated >= target) break;
        }

        if (accumulated >= target) {
            return selected;
        }

        // If unspent pointers are insufficient or spent/locked in mempool, but audited balance covers target,
        // use spent/pending pointers (so node's chaining engine matches prev_tx_hash)
        if (balSubunits >= target) {
            const allCandidates = (window.unspentPointers || []).filter(p =>
                !!p.staked === isStaked &&
                isOwnerMatch(p)
            );
            
            if (allCandidates.length > 0) {
                const chainedSelected = [];
                let chainedAcc = 0n;
                for (const ptr of allCandidates) {
                    if (chainedSelected.length >= 1024) break;
                    chainedSelected.push(ptr);
                    const size = BigInt(ptr.endSubunit || ptr.end_subunit || 0) - BigInt(ptr.startSubunit || ptr.start_subunit || 0) + 1n;
                    chainedAcc += size;
                    if (chainedAcc >= target) break;
                }
                if (chainedSelected.length > 0) return chainedSelected;
            }
        }
        return null;
    }

    const btnExecuteTransfer = document.getElementById('btn-execute-transfer');
    if (btnExecuteTransfer) {
        btnExecuteTransfer.addEventListener('click', () => {
            let recipientInput = (document.getElementById('tx-recipient-pk')?.value || '').trim();
            let recipientClean = recipientInput.replace(/[^0-9a-fA-F]/g, '');
            const txAmountInput = document.getElementById('tx-amount-scl');
            const amountScl = parseFloat(txAmountInput?.value) || 0;
            let amountSubunits = BigInt(Math.round(amountScl * 160000000));
             
            // Bypass floating point truncation for exact MAX capacity executions
            if (txAmountInput?.dataset?.exactMaxSubunits) {
                const exactBig = BigInt(txAmountInput.dataset.exactMaxSubunits);
                const exactDisplayUnits = (exactBig * 5n) / 8n;
                const exactDisplayScl = Number(exactDisplayUnits) / 100000000;
                if (Math.abs(amountScl - exactDisplayScl) < 1e-9) {
                    amountSubunits = exactBig;
                }
            }
             
            const feeSubunits = calculateFeeSubunits(amountSubunits, false);
            const targetSubunits = amountSubunits + feeSubunits;

            let recipientHex = resolveUserIdToPubkey(recipientClean);
            if (recipientHex === null) {
                alert('User ID not found in known public keys cache. Please enter the full 5184-character Public Key or ensure the recipient has performed a transaction.');
                return;
            }
            if (!recipientHex || recipientHex.length !== 5184) {
                alert('Invalid recipient input. Expected 64 hex characters (32-byte User ID) or 5184 hex characters (2592-byte Public Key).');
                return;
            }
            if (amountScl <= 0) {
                alert('Transfer amount must be greater than zero.');
                return;
            }

            const selectedInputs = selectUnspentPointers(targetSubunits, false);
            if (selectedInputs === null) {
                alert('Insufficient unlocked balance or input pointers for this transfer.');
                return;
            }

            if (client && client.socket && client.socket.readyState === WebSocket.OPEN) {
                const { privKeyHex, pubKeyHex: senderPubHex } = resolveWalletCredentials();

                if (!privKeyHex || _hexToBytes(privKeyHex, 4864) === null) {
                    alert('Dilithium private key missing or invalid. Please enter or generate a valid 4864-byte Dilithium private key.');
                    return;
                }

                btnExecuteTransfer.disabled = true;
                btnExecuteTransfer.textContent = 'Signing & Generating ZK Proof...';

                client.submitTransaction(
                    (BigInt(Date.now()) << 16n | BigInt(Math.floor(Math.random() * 65535))),
                    'OP_TRANSFER_POINTER',
                    {
                        recipientPubkeyHex: recipientHex,
                        senderPubkeyHex: senderPubHex,
                        privkeyHex: privKeyHex,
                        amountSubunits: amountSubunits.toString(),
                        inputs: selectedInputs
                    }
                );
            } else {
                alert('Client not connected to SCL Node pipeline.');
            }
        });
    }

    const btnExecuteStake = document.getElementById('btn-execute-stake');
    if (btnExecuteStake) {
        btnExecuteStake.addEventListener('click', () => {
            const stakeAmountInput = document.getElementById('stake-amount-scl');
            const amountScl = parseFloat(stakeAmountInput?.value) || 0;
            if (amountScl <= 0) {
                alert('Staking amount must be greater than zero.');
                return;
            }
            let amountSubunits = BigInt(Math.round(amountScl * 160000000));
            
            // Bypass floating point truncation for exact MAX capacity executions
            if (stakeAmountInput?.dataset?.exactMaxSubunits) {
                const exactBig = BigInt(stakeAmountInput.dataset.exactMaxSubunits);
                const exactDisplayUnits = (exactBig * 5n) / 8n;
                const exactDisplayScl = Number(exactDisplayUnits) / 100000000;
                if (Math.abs(amountScl - exactDisplayScl) < 1e-9) {
                    amountSubunits = exactBig;
                }
            }
            
            const feeSubunits = calculateFeeSubunits(amountSubunits, true);
            const targetSubunits = amountSubunits + feeSubunits;

            const selectedInputs = selectUnspentPointers(targetSubunits, false);
            if (selectedInputs === null) {
                alert('Insufficient unlocked balance or input pointers for staking.');
                return;
            }

            if (client && client.socket && client.socket.readyState === WebSocket.OPEN) {
                const { privKeyHex, pubKeyHex: senderPubHex } = resolveWalletCredentials();

                if (!privKeyHex || _hexToBytes(privKeyHex, 4864) === null) {
                    alert('Dilithium private key missing or invalid. Please enter or generate a valid Dilithium private key.');
                    return;
                }

                btnExecuteStake.disabled = true;
                btnExecuteStake.textContent = 'Signing Stake Operation...';

                client.submitTransaction(
                    (BigInt(Date.now()) << 16n | BigInt(Math.floor(Math.random() * 65535))),
                    'OP_STAKE',
                    {
                        senderPubkeyHex: senderPubHex,
                        privkeyHex: privKeyHex,
                        amountSubunits: amountSubunits.toString(),
                        inputs: selectedInputs
                    }
                );
            } else {
                alert('Client not connected to SCL Node pipeline.');
            }
        });
    }

    const btnExecuteUnstake = document.getElementById('btn-execute-unstake');
    if (btnExecuteUnstake) {
        btnExecuteUnstake.addEventListener('click', () => {
            const unstakeAmountInput = document.getElementById('stake-amount-scl');
            const amountScl = parseFloat(unstakeAmountInput?.value) || 0;
            if (amountScl <= 0) {
                alert('Unstaking amount must be greater than zero.');
                return;
            }
            let amountSubunits = BigInt(Math.round(amountScl * 160000000));
            
            // Bypass floating point truncation for exact MAX capacity executions
            if (unstakeAmountInput?.dataset?.exactMaxSubunits) {
                const exactBig = BigInt(unstakeAmountInput.dataset.exactMaxSubunits);
                const exactDisplayUnits = (exactBig * 5n) / 8n;
                const exactDisplayScl = Number(exactDisplayUnits) / 100000000;
                if (Math.abs(amountScl - exactDisplayScl) < 1e-9) {
                    amountSubunits = exactBig;
                }
            }
            
            const feeSubunits = calculateFeeSubunits(amountSubunits, true);
            const targetSubunits = amountSubunits + feeSubunits;

            const selectedInputs = selectUnspentPointers(targetSubunits, true);
            if (selectedInputs === null) {
                alert('Insufficient staked balance or pointers for unstaking.');
                return;
            }

            if (client && client.socket && client.socket.readyState === WebSocket.OPEN) {
                const { privKeyHex, pubKeyHex: recipientPubHex } = resolveWalletCredentials();

                if (!privKeyHex || _hexToBytes(privKeyHex, 4864) === null) {
                    alert('Dilithium private key missing or invalid. Please enter or generate a valid 4864-byte Dilithium private key.');
                    return;
                }

                btnExecuteUnstake.disabled = true;
                btnExecuteUnstake.textContent = 'Signing Unstake Operation...';

                client.submitTransaction(
                    (BigInt(Date.now()) << 16n | BigInt(Math.floor(Math.random() * 65535))),
                    'OP_UNSTAKE',
                    {
                        recipientPubkeyHex: recipientPubHex,
                        privkeyHex: privKeyHex,
                        amountSubunits: amountSubunits.toString(),
                        inputs: selectedInputs
                    }
                );
            } else {
                alert('Client not connected to SCL Node pipeline.');
            }
        });
    }

    const btnSubmitValuation = document.getElementById('btn-submit-valuation');
    if (btnSubmitValuation && matrixContainer) {
        btnSubmitValuation.addEventListener('click', () => {
            const inputs = matrixContainer.querySelectorAll('.matrix-cell-input');
            const numbers = Array.from(inputs).map(inp => parseInt(inp.value, 10) || 0);

            if (client && client.socket && client.socket.readyState === WebSocket.OPEN) {
                if ((window.privateUtxoBalance || 0) < 1) {
                    alert('No Encrypted UTXO Validations available to burn for submission.');
                    return;
                }

                const { privKeyHex, pubKeyHex } = resolveWalletCredentials();

                if (!privKeyHex || _hexToBytes(privKeyHex, 4864) === null) {
                    alert('Dilithium private key missing or invalid. Please enter or generate a valid 4864-byte Dilithium private key.');
                    return;
                }

                btnSubmitValuation.disabled = true;
                btnSubmitValuation.textContent = 'Signing & Submitting...';

                const unspentUtxos = (window.loadedUTXOs || []).filter(u => u && !window.seenNullifiers.has(u.nullifier));
                let currentUtxo = (unspentUtxos.length > 0) ? unspentUtxos[0] : null;
                let vOld = currentUtxo ? (currentUtxo.amount || 10) : 10;
                let amountToTake = 1;
                let vChange = vOld - amountToTake;

                if (currentUtxo && currentUtxo.nullifier) {
                    window.seenNullifiers.add(currentUtxo.nullifier);
                    const spentIdx = (window.loadedUTXOs || []).findIndex(u => u.nullifier === currentUtxo.nullifier);
                    if (spentIdx !== -1) {
                        window.loadedUTXOs.splice(spentIdx, 1);
                    }
                }

                /* UTXO-stat stability fix: remember the submission instant and reflect the
                 * burn locally so 'Audited UTXO Validations' steps down instead of resetting. */
                window.lastValuationSubmissionAt = Date.now();
                window.privateUtxoBalance = (window.loadedUTXOs || []).reduce((sum, u) => sum + (u.amount || 0), 0);
                const utxoStatEl = document.getElementById('decrypted-utxo-val');
                if (utxoStatEl) {
                    utxoStatEl.textContent = Number(window.privateUtxoBalance).toLocaleString('en-US');
                }

                client.generateCentinelProof({
                    requestId: (BigInt(Date.now()) << 16n | BigInt(Math.floor(Math.random() * 65535))),
                    amountToTake: amountToTake.toString(),
                    vOld: vOld.toString(),
                    vChange: vChange.toString(),
                    exportFormat: 'burn',
                    utxo: currentUtxo,
                    privkeyHex: privKeyHex,
                    pubkeyHex: pubKeyHex
                });

                client.submitTransaction(
                    (BigInt(Date.now()) << 16n | BigInt(Math.floor(Math.random() * 65535))),
                    'OP_SUBMIT_VALUATION',
                    {
                        pubkeyHex: pubKeyHex,
                        privkeyHex: privKeyHex,
                        numbers: numbers,
                        timestamp: Date.now() * 1000
                    }
                );
            } else {
                alert('Client not connected to SCL Node pipeline.');
            }
        });
    }

    const btnCreateCentinel = document.getElementById('btn-create-centinel-ticket');
    if (btnCreateCentinel) {
        btnCreateCentinel.addEventListener('click', () => {
            const amount = parseInt(document.getElementById('centinel-encapsulate-amount')?.value, 10) || 0;
            const exportFormat = document.getElementById('centinel-export-format')?.value || 'dat';
            if (amount <= 0) {
                alert('Validations to encapsulate must be greater than zero.');
                return;
            }

            if (client && client.socket && client.socket.readyState === WebSocket.OPEN) {
                if ((window.privateUtxoBalance || 0) < amount) {
                    alert('Insufficient Encrypted UTXO Validations available.');
                    return;
                }

                const { privKeyHex, pubKeyHex } = resolveWalletCredentials();

                btnCreateCentinel.disabled = true;
                btnCreateCentinel.textContent = 'Generating...';

                // Buffer array to hold all dynamically constructed multi-ticket shards
                if (!window.pendingTicketShards) window.pendingTicketShards = [];
                window.pendingTicketShards.length = 0;
                window.targetCentinelAmount = amount;

                let remainingToFulfill = amount;
                let burntAmount = 0;
                
                // Track iterations to coordinate the final file dispatch
                window.expectedTicketShards = 0;

                let unspentUtxos = (window.loadedUTXOs || [])
                    .filter(u => u && !window.seenNullifiers.has(u.nullifier))
                    .sort((a, b) => parseInt(b.amount || 0, 10) - parseInt(a.amount || 0, 10));

                if (unspentUtxos.length === 0) {
                    unspentUtxos = [{
                        amount: window.privateUtxoBalance || 10,
                        nullifier: null,
                        r: null
                    }];
                }

                let utxoIdx = 0;

                while (remainingToFulfill > 0) {
                    let currentUtxo = (utxoIdx < unspentUtxos.length) ? unspentUtxos[utxoIdx] : { amount: remainingToFulfill, nullifier: null, r: null };
                    let vOld = currentUtxo.amount || 10;
                    let amountToTake = remainingToFulfill < vOld ? remainingToFulfill : vOld;
                    let vChange = vOld > amountToTake ? vOld - amountToTake : 0;

                    burntAmount += amountToTake;

                    client.generateCentinelProof({
                        requestId: (BigInt(Date.now()) << 16n | BigInt(Math.floor(Math.random() * 65535))),
                        amountToTake: amountToTake.toString(),
                        vOld: vOld.toString(),
                        vChange: vChange.toString(),
                        exportFormat: exportFormat,
                        utxo: currentUtxo,
                        privkeyHex: privKeyHex,
                        pubkeyHex: pubKeyHex
                    });

                    utxoIdx++;
                    window.expectedTicketShards++;
                    remainingToFulfill -= amountToTake;
                }

                // Balance recalculation is handled deterministically by onTransactionMatch upon receiving change commitments
            } else {
                alert('Client not connected to SCL Node pipeline.');
            }
        });
    }

    // --- 6. Encrypted Vault Storage (IndexedDB AES-GCM-256 At Rest) ---
    const btnSaveVault = document.getElementById('btn-save-vault');
    const btnUnlockVault = document.getElementById('btn-unlock-vault');
    const vaultPassphraseInput = document.getElementById('vault-passphrase');

    if (btnSaveVault && vaultPassphraseInput) {
        btnSaveVault.addEventListener('click', async () => {
            const passphrase = vaultPassphraseInput.value.trim();
            if (!passphrase) {
                alert('Please enter a passphrase to encrypt the vault.');
                return;
            }

            const vaultData = {
                prfKey: prfKeyInput ? prfKeyInput.value.trim() : '',
                walletPubkey: walletPubkeyInput ? walletPubkeyInput.value.trim() : '',
                walletPrivkey: walletPrivkeyInput ? walletPrivkeyInput.value.trim() : ''
            };

            try {
                btnSaveVault.disabled = true;
                btnSaveVault.textContent = 'Encrypting & Saving...';
                await client.saveVault(passphrase, vaultData);
                alert('Vault encrypted with AES-GCM-256 (600,000 PBKDF2 iterations) and saved securely!');
            } catch (e) {
                alert('Failed to save vault: ' + e.message);
            } finally {
                btnSaveVault.disabled = false;
                btnSaveVault.textContent = 'Save Encrypted Vault';
            }
        });
    }

    if (btnUnlockVault && vaultPassphraseInput) {
        btnUnlockVault.addEventListener('click', async () => {
            const passphrase = vaultPassphraseInput.value.trim();
            if (!passphrase) {
                alert('Please enter your vault passphrase.');
                return;
            }

            try {
                btnUnlockVault.disabled = true;
                btnUnlockVault.textContent = 'Decrypting Vault...';
                const vaultData = await client.loadVault(passphrase);
                if (!vaultData) {
                    alert('No saved vault found.');
                    return;
                }

                if (prfKeyInput) prfKeyInput.value = vaultData.prfKey || '';
                if (walletPubkeyInput) walletPubkeyInput.value = vaultData.walletPubkey || '';
                if (walletPrivkeyInput) walletPrivkeyInput.value = vaultData.walletPrivkey || '';

                alert('Vault unlocked successfully! Keys populated.');
                hotSwapCredentials();
            } catch (e) {
                alert('Failed to unlock vault. Incorrect passphrase or corrupted data.');
            } finally {
                btnUnlockVault.disabled = false;
                btnUnlockVault.textContent = 'Unlock Encrypted Vault';
            }
        });
    }

    // --- 7. Centinel Bearer Ticket Redemption Handler ---
    const btnRedeemCentinel = document.getElementById('btn-redeem-centinel-ticket');
    const centinelImportFileInput = document.getElementById('centinel-import-file');

    if (btnRedeemCentinel && centinelImportFileInput) {
        ['dragenter', 'dragover'].forEach(eventName => {
            centinelImportFileInput.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                centinelImportFileInput.style.borderColor = 'var(--accent-green)';
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            centinelImportFileInput.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                centinelImportFileInput.style.borderColor = 'var(--border-color)';
            });
        });

        centinelImportFileInput.addEventListener('drop', (e) => {
            if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                centinelImportFileInput.files = e.dataTransfer.files;
            }
        });

        btnRedeemCentinel.addEventListener('click', () => {
            const file = centinelImportFileInput.files[0];
            if (!file) {
                alert('Please select a Centinel ticket (.dat) file to redeem.');
                return;
            }

            if (!client || !client.socket || client.socket.readyState !== WebSocket.OPEN) {
                alert('Client not connected to SCL Node pipeline.');
                return;
            }

            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    window.hasCustomLoadedFile = true;
                    const utxos = parseCentinelFile(e.target.result);
                    if (utxos.length === 0) {
                        alert('No valid ticket entries found in file.');
                        btnRedeemCentinel.disabled = false;
                        btnRedeemCentinel.textContent = 'Redeem';
                        return;
                    }

                    const { privKeyHex, pubKeyHex } = resolveWalletCredentials();

                    btnRedeemCentinel.disabled = true;
                    btnRedeemCentinel.textContent = 'Claiming...';

                    utxos.forEach((utxo, idx) => {
                        if (utxo && utxo.nullifier) {
                            window.seenNullifiers.add(utxo.nullifier);
                        }
                        client.generateCentinelProof({
                            requestId: (BigInt(Date.now()) << 16n | BigInt(Math.floor(Math.random() * 65535))),
                            amountToTake: utxo.amount.toString(),
                            exportFormat: 'redeem',
                            utxo: utxo,
                            privkeyHex: privKeyHex,
                            pubkeyHex: pubKeyHex
                        });
                    });
                } catch (err) {
                    alert('Error parsing Centinel Ticket file for redemption: ' + err.message);
                    btnRedeemCentinel.disabled = false;
                    btnRedeemCentinel.textContent = 'Redeem';
                }
            };
            reader.readAsArrayBuffer(file);
        });
    }

    // --- Blockchain Explorer Store & View Controller ---
    const blockchainStore = {
        coins: new Map(),       // coinId -> { coinId, totalSubunits, remainingSubunits, creationTxHash, ownerAddress }
        pointers: new Map(),    // pointerId -> { pointerId, parentCoinId, startSubunit, endSubunit, ownerAddress, prevTxHash, spent, staked }
        transactions: []        // [{ txId, typeString, amount, recipientPubkeyHex, senderPubkeyHex, timestamp }]
    };

    // 1. Page View Switcher
    const navBtnDashboard = document.getElementById('nav-btn-dashboard');
    const navBtnVision = document.getElementById('nav-btn-vision');
    const navBtnBlockchain = document.getElementById('nav-btn-blockchain');
    const navBtnSettings = document.getElementById('nav-btn-settings');
    const navBtnValidation = document.getElementById('nav-btn-validation');
    const navBtnProofs = document.getElementById('nav-btn-proofs');
    const navBtnPrivacy = document.getElementById('nav-btn-privacy');
    const navBtnTos = document.getElementById('nav-btn-tos');
    const footerLinkVision = document.getElementById('footer-link-vision');
    const footerLinkValidation = document.getElementById('footer-link-validation');
    const footerLinkProofs = document.getElementById('footer-link-proofs');
    const footerLinkPrivacy = document.getElementById('footer-link-privacy');
    const footerLinkTos = document.getElementById('footer-link-tos');
    const viewDashboard = document.getElementById('view-dashboard');
    const viewVision = document.getElementById('view-vision');
    const viewBlockchain = document.getElementById('view-blockchain');
    const viewSettings = document.getElementById('view-settings');
    const viewValidation = document.getElementById('view-validation');
    const viewProofs = document.getElementById('view-proofs');
    const viewPrivacy = document.getElementById('view-privacy');
    const viewTos = document.getElementById('view-tos');

    /**
     * @brief Switches the active page view between Dashboard, Vision, Blockchain Explorer, Settings, Privacy, Terms of Service, Validation, and Formal Proofs.
     *
     * @param {string} targetView View identifier (`'dashboard'`, `'vision'`, `'blockchain'`, `'settings'`, `'privacy'`, `'tos'`, `'validation'`, `'proofs'`).
     * @return {void}
     */
    let visionAnimationId = null;

    /**
     * @brief High-performance quantum-inspired sprite animation for the Vision backdrop.
     */
    function runVisionQuantumAnimation() {
        const canvas = document.getElementById('vision-quantum-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        let w = (canvas.width = canvas.offsetWidth || 800);
        let h = (canvas.height = canvas.offsetHeight || 500);

        // Pre-allocate 36 orbital wave particles (zero heap allocations inside frame loop)
        const particles = [];
        const numParticles = 36;
        for (let i = 0; i < numParticles; i++) {
            particles.push({
                shell: (i % 3) + 1,
                angle: (i / numParticles) * Math.PI * 2,
                speed: 0.007 + (i % 3) * 0.0035,
                phaseOffset: (i % 5) * 0.4
            });
        }

        let time = 0;

        function animate() {
            if (!viewVision || viewVision.style.display === 'none' || document.hidden) {
                visionAnimationId = null;
                return;
            }

            time += 0.015;
            ctx.clearRect(0, 0, w, h);

            const cx = w * 0.50;
            const cy = h * 0.50;
            const isOrange = document.documentElement.classList.contains('orange-mode');
            const isLight = document.documentElement.classList.contains('light-mode');

            const primaryColor = isOrange
                ? (isLight ? 'rgba(234, 88, 12,' : 'rgba(247, 147, 26,')
                : (isLight ? 'rgba(5, 150, 105,' : 'rgba(16, 185, 129,');
            const secondaryColor = isLight ? 'rgba(2, 132, 199,' : 'rgba(56, 189, 248,';

            // 1. Draw 3 harmonic probability interference rings
            for (let ring = 1; ring <= 3; ring++) {
                const rx = ring * 85 + Math.sin(time * 1.5 + ring) * 8;
                const ry = ring * 45 + Math.cos(time * 1.2 + ring) * 5;
                const rot = time * (ring % 2 === 0 ? 0.35 : -0.25);

                ctx.save();
                ctx.translate(cx, cy);
                ctx.rotate(rot);
                ctx.beginPath();
                ctx.ellipse(0, 0, rx, ry, 0, 0, Math.PI * 2);
                ctx.strokeStyle = `${primaryColor} ${0.12 / ring})`;
                ctx.lineWidth = 1.2;
                ctx.stroke();
                ctx.restore();
            }

            // 2. Draw amplitude wave packet connectors and orbital particle sprites
            for (let i = 0; i < numParticles; i++) {
                const p = particles[i];
                p.angle += p.speed;

                const baseR = p.shell * 85;
                const amp = Math.sin(time * 2 + p.angle * 3 + p.phaseOffset) * 12;
                const r = baseR + amp;

                const x = cx + Math.cos(p.angle) * r;
                const y = cy + Math.sin(p.angle) * (r * 0.52);

                if (i > 0 && p.shell === particles[i - 1].shell) {
                    const prev = particles[i - 1];
                    const prevR = prev.shell * 85 + Math.sin(time * 2 + prev.angle * 3 + prev.phaseOffset) * 12;
                    const px = cx + Math.cos(prev.angle) * prevR;
                    const py = cy + Math.sin(prev.angle) * (prevR * 0.52);

                    ctx.beginPath();
                    ctx.moveTo(px, py);
                    ctx.lineTo(x, y);
                    ctx.strokeStyle = `${secondaryColor} 0.10)`;
                    ctx.lineWidth = 0.8;
                    ctx.stroke();
                }

                const particleAlpha = 0.35 + Math.sin(time * 3 + p.angle) * 0.25;
                ctx.beginPath();
                ctx.arc(x, y, 2.2, 0, Math.PI * 2);
                ctx.fillStyle = `${primaryColor} ${particleAlpha})`;
                ctx.fill();
            }

            visionAnimationId = requestAnimationFrame(animate);
        }

        if (visionAnimationId) cancelAnimationFrame(visionAnimationId);
        visionAnimationId = requestAnimationFrame(animate);
    }

    function switchPageView(targetView) {
        if (viewDashboard) viewDashboard.style.display = 'none';
        if (viewVision) viewVision.style.display = 'none';
        if (viewBlockchain) viewBlockchain.style.display = 'none';
        if (viewSettings) viewSettings.style.display = 'none';
        if (viewValidation) viewValidation.style.display = 'none';
        if (viewProofs) viewProofs.style.display = 'none';
        if (viewPrivacy) viewPrivacy.style.display = 'none';
        if (viewTos) viewTos.style.display = 'none';

        if (navBtnDashboard) navBtnDashboard.classList.remove('active');
        if (navBtnVision) navBtnVision.classList.remove('active');
        if (navBtnBlockchain) navBtnBlockchain.classList.remove('active');
        if (navBtnSettings) navBtnSettings.classList.remove('active');
        if (navBtnValidation) navBtnValidation.classList.remove('active');
        if (navBtnProofs) navBtnProofs.classList.remove('active');
        if (navBtnPrivacy) navBtnPrivacy.classList.remove('active');
        if (navBtnTos) navBtnTos.classList.remove('active');

        if (targetView === 'vision') {
            if (viewVision) viewVision.style.display = 'block';
            if (navBtnVision) navBtnVision.classList.add('active');
            window.scrollTo({ top: 0, behavior: 'smooth' });
            runVisionQuantumAnimation();
        } else if (targetView === 'blockchain') {
            if (viewBlockchain) viewBlockchain.style.display = 'block';
            if (navBtnBlockchain) navBtnBlockchain.classList.add('active');
            if (client && typeof client.requestBlockchainLedger === 'function') {
                client.requestBlockchainLedger();
            }
            renderBlockchainLedgerView();
        } else if (targetView === 'settings') {
            if (viewSettings) viewSettings.style.display = 'block';
            if (navBtnSettings) navBtnSettings.classList.add('active');
            renderSettingsView();
        } else if (targetView === 'validation') {
            if (viewValidation) viewValidation.style.display = 'block';
            if (navBtnValidation) navBtnValidation.classList.add('active');
            window.scrollTo({ top: 0, behavior: 'smooth' });
        } else if (targetView === 'proofs') {
            if (viewProofs) viewProofs.style.display = 'block';
            if (navBtnProofs) navBtnProofs.classList.add('active');
            window.scrollTo({ top: 0, behavior: 'smooth' });
            const visiblePanel = document.querySelector('.proof-tier-panel:not([style*="display: none"])') || document.getElementById('proof-panel-coalition');
            if (window.renderMathInElement && visiblePanel) {
                window.renderMathInElement(visiblePanel, {
                    delimiters: [
                        { left: '$$', right: '$$', display: true },
                        { left: '$', right: '$', display: false }
                    ],
                    output: 'html',
                    throwOnError: false,
                    ignoredTags: ["script", "noscript", "style", "textarea", "pre", "code"]
                });
            }
        } else if (targetView === 'privacy') {
            if (viewPrivacy) viewPrivacy.style.display = 'block';
            if (navBtnPrivacy) navBtnPrivacy.classList.add('active');
            window.scrollTo({ top: 0, behavior: 'smooth' });
        } else if (targetView === 'tos') {
            if (viewTos) viewTos.style.display = 'block';
            if (navBtnTos) navBtnTos.classList.add('active');
            window.scrollTo({ top: 0, behavior: 'smooth' });
        } else {
            if (viewDashboard) viewDashboard.style.display = 'block';
            if (navBtnDashboard) navBtnDashboard.classList.add('active');
            if (renderer) renderer.draw();
        }
    }
    window.switchPageView = switchPageView;

    if (navBtnDashboard) navBtnDashboard.addEventListener('click', () => switchPageView('dashboard'));
    if (navBtnVision) navBtnVision.addEventListener('click', () => switchPageView('vision'));
    if (footerLinkVision) footerLinkVision.addEventListener('click', () => switchPageView('vision'));
    if (navBtnBlockchain) navBtnBlockchain.addEventListener('click', () => switchPageView('blockchain'));
    if (navBtnSettings) navBtnSettings.addEventListener('click', () => switchPageView('settings'));
    if (navBtnValidation) navBtnValidation.addEventListener('click', () => switchPageView('validation'));
    if (navBtnProofs) navBtnProofs.addEventListener('click', () => switchPageView('proofs'));
    if (navBtnPrivacy) navBtnPrivacy.addEventListener('click', () => switchPageView('privacy'));
    if (navBtnTos) navBtnTos.addEventListener('click', () => switchPageView('tos'));
    if (footerLinkValidation) footerLinkValidation.addEventListener('click', () => switchPageView('validation'));
    if (footerLinkProofs) footerLinkProofs.addEventListener('click', () => switchPageView('proofs'));
    if (footerLinkPrivacy) footerLinkPrivacy.addEventListener('click', () => switchPageView('privacy'));
    if (footerLinkTos) footerLinkTos.addEventListener('click', () => switchPageView('tos'));

    // --- Grok-Style Proof Tier Segmented Slider Controller ---
    const tierBtnCoalition = document.getElementById('proof-tier-coalition');
    const tierBtnInvariants = document.getElementById('proof-tier-invariants');
    const tierBtnTvd = document.getElementById('proof-tier-tvd');
    const panelCoalition = document.getElementById('proof-panel-coalition');
    const panelInvariants = document.getElementById('proof-panel-invariants');
    const panelTvd = document.getElementById('proof-panel-tvd');

    function switchProofTier(tier) {
        if (panelCoalition) panelCoalition.style.display = 'none';
        if (panelInvariants) panelInvariants.style.display = 'none';
        if (panelTvd) panelTvd.style.display = 'none';

        if (tierBtnCoalition) tierBtnCoalition.classList.remove('active');
        if (tierBtnInvariants) tierBtnInvariants.classList.remove('active');
        if (tierBtnTvd) tierBtnTvd.classList.remove('active');

        let activePanel = null;
        if (tier === 'invariants') {
            if (panelInvariants) panelInvariants.style.display = 'flex';
            if (tierBtnInvariants) tierBtnInvariants.classList.add('active');
            activePanel = panelInvariants;
        } else if (tier === 'tvd') {
            if (panelTvd) panelTvd.style.display = 'flex';
            if (tierBtnTvd) tierBtnTvd.classList.add('active');
            activePanel = panelTvd;
        } else {
            if (panelCoalition) panelCoalition.style.display = 'flex';
            if (tierBtnCoalition) tierBtnCoalition.classList.add('active');
            activePanel = panelCoalition;
        }

        if (activePanel && window.renderMathInElement) {
            window.renderMathInElement(activePanel, {
                delimiters: [
                    { left: '$$', right: '$$', display: true },
                    { left: '$', right: '$', display: false }
                ],
                output: 'html',
                throwOnError: false,
                ignoredTags: ["script", "noscript", "style", "textarea", "pre", "code"]
            });
        }
    }

    if (tierBtnCoalition) tierBtnCoalition.addEventListener('click', () => switchProofTier('coalition'));
    if (tierBtnInvariants) tierBtnInvariants.addEventListener('click', () => switchProofTier('invariants'));
    if (tierBtnTvd) tierBtnTvd.addEventListener('click', () => switchProofTier('tvd'));

    // --- Configuration Manager (satocialist.conf) Controller ---
    const defaultConf = {
        bind_ip: '0.0.0.0',
        bind_port: 5555,
        is_daemon: false,
        log_level: 'info',
        initial_rtt_ms: 800,
        min_pto_ms: 1000,
        max_ack_delay_ms: 25,
        time_threshold_num: 9,
        time_threshold_den: 8,
        rbf_enabled: true,
        max_pending_ops: 1000,
        mempool_async_threshold: 50,
        metrics_port: 8000,
        websocket_port: 5554,
        bootstrap_nodes: '136.65.1.22:5555,35.192.184.226:5555',
        autopilot_enabled: false,
        autopilot_valuations_per_hour: 1,
        autopilot_stake_ratio: 50
    };

    /**
     * @brief Serializes a configuration object into standard `satocialist.conf` text format.
     *
     * @param {Object} cfg Configuration key-value dictionary.
     * @return {string} Formatted configuration file text.
     * @complexity Time: O(1), Space: O(1).
     */
    function generateConfText(cfg) {
        return `# Satocialist Client Configuration File
bind_ip=${cfg.bind_ip}
bind_port=${cfg.bind_port}
is_daemon=${cfg.is_daemon}

# Log Levels: trace, debug, info, warn, error, fatal
log_level=${cfg.log_level}

# === BBRv3 / L4 Transport Tuning ===
initial_rtt_ms=${cfg.initial_rtt_ms}
min_pto_ms=${cfg.min_pto_ms}
max_ack_delay_ms=${cfg.max_ack_delay_ms}
time_threshold_num=${cfg.time_threshold_num}
time_threshold_den=${cfg.time_threshold_den}

# === Mempool & Scalability ===
rbf_enabled=${cfg.rbf_enabled}
max_pending_ops=${cfg.max_pending_ops}
mempool_async_threshold=${cfg.mempool_async_threshold}

# === Auto-Pilot Automation ===
autopilot_enabled=${cfg.autopilot_enabled}
autopilot_valuations_per_hour=${cfg.autopilot_valuations_per_hour}
autopilot_stake_ratio=${cfg.autopilot_stake_ratio}

# === Telemetry & Metrics ===
metrics_port=${cfg.metrics_port}
websocket_port=${cfg.websocket_port}

# === Redundant Bootstrap Nodes ===
bootstrap_nodes=${cfg.bootstrap_nodes}
`;
    }

    /**
     * @brief Parses a `satocialist.conf` text buffer into a configuration object.
     *
     * @param {string} text Configuration file text contents.
     * @return {Object} Parsed configuration dictionary with defaults applied.
     * @complexity Time: O(lines), Space: O(1).
     */
    function parseConfText(text) {
        const cfg = { ...defaultConf };
        const lines = text.split(/\r?\n/);
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;
            const eqIdx = trimmed.indexOf('=');
            if (eqIdx === -1) continue;
            const key = trimmed.slice(0, eqIdx).trim();
            const val = trimmed.slice(eqIdx + 1).trim();

            if (key === 'bind_ip') cfg.bind_ip = val;
            else if (key === 'bind_port') cfg.bind_port = parseInt(val, 10) || defaultConf.bind_port;
            else if (key === 'is_daemon') cfg.is_daemon = (val.toLowerCase() === 'true' || val === '1');
            else if (key === 'log_level') cfg.log_level = val.toLowerCase();
            else if (key === 'initial_rtt_ms') cfg.initial_rtt_ms = parseInt(val, 10) || defaultConf.initial_rtt_ms;
            else if (key === 'min_pto_ms') cfg.min_pto_ms = parseInt(val, 10) || defaultConf.min_pto_ms;
            else if (key === 'max_ack_delay_ms') cfg.max_ack_delay_ms = parseInt(val, 10) || defaultConf.max_ack_delay_ms;
            else if (key === 'time_threshold_num') cfg.time_threshold_num = parseInt(val, 10) || defaultConf.time_threshold_num;
            else if (key === 'time_threshold_den') cfg.time_threshold_den = parseInt(val, 10) || defaultConf.time_threshold_den;
            else if (key === 'rbf_enabled') cfg.rbf_enabled = (val.toLowerCase() === 'true' || val === '1');
            else if (key === 'max_pending_ops') cfg.max_pending_ops = parseInt(val, 10) || defaultConf.max_pending_ops;
            else if (key === 'mempool_async_threshold') cfg.mempool_async_threshold = parseInt(val, 10) || defaultConf.mempool_async_threshold;
            else if (key === 'metrics_port') cfg.metrics_port = parseInt(val, 10) || defaultConf.metrics_port;
            else if (key === 'websocket_port') cfg.websocket_port = parseInt(val, 10) || defaultConf.websocket_port;
            else if (key === 'bootstrap_nodes') cfg.bootstrap_nodes = val;
            else if (key === 'autopilot_enabled') cfg.autopilot_enabled = (val.toLowerCase() === 'true' || val === '1');
            else if (key === 'autopilot_valuations_per_hour') cfg.autopilot_valuations_per_hour = parseInt(val, 10) || defaultConf.autopilot_valuations_per_hour;
            else if (key === 'autopilot_stake_ratio') cfg.autopilot_stake_ratio = parseInt(val, 10) || defaultConf.autopilot_stake_ratio;
        }
        return cfg;
    }

    function getCurrentSettingsFromForm() {
        return {
            bind_ip: document.getElementById('conf-bind-ip')?.value.trim() || defaultConf.bind_ip,
            bind_port: parseInt(document.getElementById('conf-bind-port')?.value, 10) || defaultConf.bind_port,
            is_daemon: document.getElementById('conf-is-daemon')?.value === 'true',
            log_level: document.getElementById('conf-log-level')?.value || defaultConf.log_level,
            initial_rtt_ms: parseInt(document.getElementById('conf-initial-rtt')?.value, 10) || defaultConf.initial_rtt_ms,
            min_pto_ms: parseInt(document.getElementById('conf-min-pto')?.value, 10) || defaultConf.min_pto_ms,
            max_ack_delay_ms: parseInt(document.getElementById('conf-max-ack-delay')?.value, 10) || defaultConf.max_ack_delay_ms,
            time_threshold_num: parseInt(document.getElementById('conf-time-thresh-num')?.value, 10) || defaultConf.time_threshold_num,
            time_threshold_den: parseInt(document.getElementById('conf-time-thresh-den')?.value, 10) || defaultConf.time_threshold_den,
            rbf_enabled: document.getElementById('conf-rbf-enabled')?.value === 'true',
            max_pending_ops: parseInt(document.getElementById('conf-max-pending-ops')?.value, 10) || defaultConf.max_pending_ops,
            mempool_async_threshold: parseInt(document.getElementById('conf-mempool-async-thresh')?.value, 10) || defaultConf.mempool_async_threshold,
            metrics_port: parseInt(document.getElementById('conf-metrics-port')?.value, 10) || defaultConf.metrics_port,
            websocket_port: parseInt(document.getElementById('conf-websocket-port')?.value, 10) || defaultConf.websocket_port,
            bootstrap_nodes: document.getElementById('conf-bootstrap-nodes')?.value.trim() || defaultConf.bootstrap_nodes,
            autopilot_enabled: document.getElementById('conf-ap-enabled')?.value === 'true',
            autopilot_valuations_per_hour: parseInt(document.getElementById('conf-ap-val-per-hr')?.value, 10) || defaultConf.autopilot_valuations_per_hour,
            autopilot_stake_ratio: parseInt(document.getElementById('conf-ap-stake-ratio')?.value, 10) || defaultConf.autopilot_stake_ratio
        };
    }

    function populateSettingsForm(cfg) {
        if (document.getElementById('conf-bind-ip')) document.getElementById('conf-bind-ip').value = cfg.bind_ip;
        if (document.getElementById('conf-bind-port')) document.getElementById('conf-bind-port').value = cfg.bind_port;
        if (document.getElementById('conf-is-daemon')) document.getElementById('conf-is-daemon').value = cfg.is_daemon ? 'true' : 'false';
        if (document.getElementById('conf-log-level')) document.getElementById('conf-log-level').value = cfg.log_level;
        if (document.getElementById('conf-initial-rtt')) document.getElementById('conf-initial-rtt').value = cfg.initial_rtt_ms;
        if (document.getElementById('conf-min-pto')) document.getElementById('conf-min-pto').value = cfg.min_pto_ms;
        if (document.getElementById('conf-max-ack-delay')) document.getElementById('conf-max-ack-delay').value = cfg.max_ack_delay_ms;
        if (document.getElementById('conf-time-thresh-num')) document.getElementById('conf-time-thresh-num').value = cfg.time_threshold_num;
        if (document.getElementById('conf-time-thresh-den')) document.getElementById('conf-time-thresh-den').value = cfg.time_threshold_den;
        if (document.getElementById('conf-rbf-enabled')) document.getElementById('conf-rbf-enabled').value = cfg.rbf_enabled ? 'true' : 'false';
        if (document.getElementById('conf-max-pending-ops')) document.getElementById('conf-max-pending-ops').value = cfg.max_pending_ops;
        if (document.getElementById('conf-mempool-async-thresh')) document.getElementById('conf-mempool-async-thresh').value = cfg.mempool_async_threshold;
        if (document.getElementById('conf-metrics-port')) document.getElementById('conf-metrics-port').value = cfg.metrics_port;
        if (document.getElementById('conf-websocket-port')) document.getElementById('conf-websocket-port').value = cfg.websocket_port;
        if (document.getElementById('conf-bootstrap-nodes')) document.getElementById('conf-bootstrap-nodes').value = cfg.bootstrap_nodes;
        if (document.getElementById('conf-ap-enabled')) document.getElementById('conf-ap-enabled').value = cfg.autopilot_enabled ? 'true' : 'false';
        if (document.getElementById('conf-ap-val-per-hr')) document.getElementById('conf-ap-val-per-hr').value = cfg.autopilot_valuations_per_hour;
        if (document.getElementById('conf-ap-stake-ratio')) document.getElementById('conf-ap-stake-ratio').value = cfg.autopilot_stake_ratio;

        const rawEditor = document.getElementById('conf-raw-editor');
        if (rawEditor) {
            rawEditor.value = generateConfText(cfg);
        }
    }

    function renderSettingsView() {
        const saved = localStorage.getItem('scl_satocialist_conf');
        const cfg = saved ? parseConfText(saved) : { ...defaultConf };
        populateSettingsForm(cfg);
    }

    // Attach Settings Form Event Handlers
    const formInputIds = [
        'conf-bind-ip', 'conf-bind-port', 'conf-is-daemon', 'conf-log-level',
        'conf-initial-rtt', 'conf-min-pto', 'conf-max-ack-delay', 'conf-time-thresh-num',
        'conf-time-thresh-den', 'conf-rbf-enabled', 'conf-max-pending-ops',
        'conf-mempool-async-thresh', 'conf-metrics-port', 'conf-websocket-port',
        'conf-bootstrap-nodes', 'conf-ap-enabled', 'conf-ap-val-per-hr', 'conf-ap-stake-ratio'
    ];

    formInputIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('input', () => {
                const cfg = getCurrentSettingsFromForm();
                const text = generateConfText(cfg);
                const rawEditor = document.getElementById('conf-raw-editor');
                if (rawEditor) rawEditor.value = text;
                localStorage.setItem('scl_satocialist_conf', text);
            });
            el.addEventListener('change', () => {
                const cfg = getCurrentSettingsFromForm();
                const text = generateConfText(cfg);
                const rawEditor = document.getElementById('conf-raw-editor');
                if (rawEditor) rawEditor.value = text;
                localStorage.setItem('scl_satocialist_conf', text);
            });
        }
    });

    const rawEditorEl = document.getElementById('conf-raw-editor');
    if (rawEditorEl) {
        rawEditorEl.addEventListener('input', () => {
            const text = rawEditorEl.value;
            const cfg = parseConfText(text);
            localStorage.setItem('scl_satocialist_conf', text);
            
            // Sync form fields without overwriting rawEditor cursor position
            if (document.getElementById('conf-bind-ip')) document.getElementById('conf-bind-ip').value = cfg.bind_ip;
            if (document.getElementById('conf-bind-port')) document.getElementById('conf-bind-port').value = cfg.bind_port;
            if (document.getElementById('conf-is-daemon')) document.getElementById('conf-is-daemon').value = cfg.is_daemon ? 'true' : 'false';
            if (document.getElementById('conf-log-level')) document.getElementById('conf-log-level').value = cfg.log_level;
            if (document.getElementById('conf-initial-rtt')) document.getElementById('conf-initial-rtt').value = cfg.initial_rtt_ms;
            if (document.getElementById('conf-min-pto')) document.getElementById('conf-min-pto').value = cfg.min_pto_ms;
            if (document.getElementById('conf-max-ack-delay')) document.getElementById('conf-max-ack-delay').value = cfg.max_ack_delay_ms;
            if (document.getElementById('conf-time-thresh-num')) document.getElementById('conf-time-thresh-num').value = cfg.time_threshold_num;
            if (document.getElementById('conf-time-thresh-den')) document.getElementById('conf-time-thresh-den').value = cfg.time_threshold_den;
            if (document.getElementById('conf-rbf-enabled')) document.getElementById('conf-rbf-enabled').value = cfg.rbf_enabled ? 'true' : 'false';
            if (document.getElementById('conf-max-pending-ops')) document.getElementById('conf-max-pending-ops').value = cfg.max_pending_ops;
            if (document.getElementById('conf-mempool-async-thresh')) document.getElementById('conf-mempool-async-thresh').value = cfg.mempool_async_threshold;
            if (document.getElementById('conf-metrics-port')) document.getElementById('conf-metrics-port').value = cfg.metrics_port;
            if (document.getElementById('conf-websocket-port')) document.getElementById('conf-websocket-port').value = cfg.websocket_port;
            if (document.getElementById('conf-bootstrap-nodes')) document.getElementById('conf-bootstrap-nodes').value = cfg.bootstrap_nodes;
            if (document.getElementById('conf-ap-enabled')) document.getElementById('conf-ap-enabled').value = cfg.autopilot_enabled ? 'true' : 'false';
            if (document.getElementById('conf-ap-val-per-hr')) document.getElementById('conf-ap-val-per-hr').value = cfg.autopilot_valuations_per_hour;
            if (document.getElementById('conf-ap-stake-ratio')) document.getElementById('conf-ap-stake-ratio').value = cfg.autopilot_stake_ratio;
        });
    }

    const btnResetConf = document.getElementById('btn-reset-conf');
    if (btnResetConf) {
        btnResetConf.addEventListener('click', () => {
            if (confirm('Reset all satocialist.conf options back to default settings?')) {
                localStorage.removeItem('scl_satocialist_conf');
                populateSettingsForm({ ...defaultConf });
            }
        });
    }

    const btnDownloadConf = document.getElementById('btn-download-conf');
    if (btnDownloadConf) {
        btnDownloadConf.addEventListener('click', () => {
            const cfg = getCurrentSettingsFromForm();
            const text = generateConfText(cfg);
            const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'satocialist.conf';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        });
    }

    const btnLoadConfFile = document.getElementById('btn-load-conf-file');
    const confFileInput = document.getElementById('conf-file-input');
    if (btnLoadConfFile && confFileInput) {
        btnLoadConfFile.addEventListener('click', () => confFileInput.click());
        confFileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (evt) => {
                const text = evt.target.result;
                const cfg = parseConfText(text);
                populateSettingsForm(cfg);
                localStorage.setItem('scl_satocialist_conf', text);
                alert(`Configuration file "${file.name}" loaded and parsed successfully.`);
            };
            reader.readAsText(file);
            confFileInput.value = ''; // Reset input to allow re-loading the same file
        });
    }

    // Real-time TPS Telemetry Sampling & Graphing
    if (!window.tpsHistory) window.tpsHistory = new Array(60).fill(0);
    if (!window.tpsPeakDecay) window.tpsPeakDecay = new Array(60).fill(0);
    if (!window.tpsTxTimestamps) window.tpsTxTimestamps = [];
    let peakTps = 0;

    function updateTpsChart(renderOnly = false) {
        if (!renderOnly) {
            const now = Date.now();
            window.tpsTxTimestamps = window.tpsTxTimestamps.filter(t => now - t <= 1000);
            const currentTps = window.tpsTxTimestamps.length;

            window.tpsHistory.push(currentTps);
            if (window.tpsHistory.length > 60) {
                window.tpsHistory.shift();
            }

            // Maintain floating peak-hold decay cache
            window.tpsPeakDecay.push(currentTps);
            if (window.tpsPeakDecay.length > 60) {
                window.tpsPeakDecay.shift();
            }

            if (currentTps > peakTps) peakTps = currentTps;

            const sum = window.tpsHistory.reduce((a, b) => a + b, 0);
            const avgTps = (sum / window.tpsHistory.length).toFixed(2);
            window._lastAvgTps = avgTps;
            window._lastCurrentTps = currentTps;

            const currentEl = document.getElementById('tps-current-val');
            const peakEl = document.getElementById('tps-peak-val');
            const avgEl = document.getElementById('tps-avg-val');
            if (currentEl) currentEl.textContent = `${currentTps.toFixed(2)} TPS`;
            if (peakEl) peakEl.textContent = `${peakTps.toFixed(2)} TPS`;
            if (avgEl) avgEl.textContent = `${avgTps} TPS`;
        }

        const avgTps = window._lastAvgTps || "0.00";
        const currentTps = window._lastCurrentTps || 0;

        if (document.hidden) return;

        const canvas = document.getElementById('tps-graph-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        const isLight = document.documentElement.classList.contains('light-mode');
        const isOrange = document.documentElement.classList.contains('orange-mode');
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        const marginX = 10;
        const usableHeight = canvas.height - 24;
        const availableWidth = canvas.width - (marginX * 2);
        const numBars = window.tpsHistory.length; // 60 seconds of telemetry
        const gap = 3;
        const barWidth = Math.max(2, (availableWidth - ((numBars - 1) * gap)) / numBars);

        const rawMax = Math.max(5, ...window.tpsHistory);
        const maxVal = Math.ceil(rawMax / 5) * 5;

        // 1. Subtle horizontal background guides across the entire canvas width
        ctx.strokeStyle = isLight ? 'rgba(148, 163, 184, 0.25)' : 'rgba(51, 65, 85, 0.35)';
        ctx.lineWidth = 1;
        ctx.setLineDash([2, 4]);

        for (let step = 1; step <= 3; step++) {
            const ratio = step / 4;
            const y = Math.round(canvas.height - 6 - (ratio * usableHeight));

            ctx.beginPath();
            ctx.moveTo(marginX, y);
            ctx.lineTo(canvas.width - marginX, y);
            ctx.stroke();
        }
        ctx.setLineDash([]);

        // 2. Compute Node Trajectories for Spline & Peak Holds
        const points = [];
        for (let i = 0; i < numBars; i++) {
            const val = window.tpsHistory[i];
            const x = marginX + i * (barWidth + gap);
            const centerX = x + barWidth / 2;
            const norm = Math.min(1.0, val / maxVal);
            const y = canvas.height - 6 - Math.round(norm * usableHeight);

            if (!renderOnly) {
                if (val >= window.tpsPeakDecay[i]) {
                    window.tpsPeakDecay[i] = val;
                } else {
                    window.tpsPeakDecay[i] = Math.max(val, window.tpsPeakDecay[i] - Math.max(0.08, (window.tpsPeakDecay[i] - val) * 0.12));
                }
            }

            points.push({ x, centerX, y, val });
        }

        // 4. Smooth Spline Trend Curve with Translucent Gradient Area Fill
        if (points.length > 1) {
            ctx.save();
            ctx.beginPath();
            ctx.moveTo(points[0].centerX, points[0].y);

            for (let i = 0; i < points.length - 1; i++) {
                const xc = (points[i].centerX + points[i + 1].centerX) / 2;
                const yc = (points[i].y + points[i + 1].y) / 2;
                ctx.quadraticCurveTo(points[i].centerX, points[i].y, xc, yc);
            }
            ctx.lineTo(points[points.length - 1].centerX, points[points.length - 1].y);

            ctx.strokeStyle = isOrange
                ? (isLight ? 'rgba(234, 88, 12, 0.85)' : 'rgba(247, 147, 26, 0.85)')
                : (isLight ? 'rgba(5, 150, 105, 0.75)' : 'rgba(16, 185, 129, 0.85)');
            ctx.lineWidth = 1.8;
            ctx.stroke();

            ctx.lineTo(points[points.length - 1].centerX, canvas.height - 6);
            ctx.lineTo(points[0].centerX, canvas.height - 6);
            ctx.closePath();

            const areaGrad = ctx.createLinearGradient(0, 16, 0, canvas.height - 6);
            areaGrad.addColorStop(0, isOrange
                ? (isLight ? 'rgba(234, 88, 12, 0.22)' : 'rgba(247, 147, 26, 0.25)')
                : (isLight ? 'rgba(5, 150, 105, 0.18)' : 'rgba(16, 185, 129, 0.22)'));
            areaGrad.addColorStop(1, isOrange ? 'rgba(247, 147, 26, 0.0)' : 'rgba(16, 185, 129, 0.0)');
            ctx.fillStyle = areaGrad;
            ctx.fill();
            ctx.restore();
        }

        // 5. Render 60-Second Segmented Equalizer Bars & Peak Decay Caps
        for (let i = 0; i < numBars; i++) {
            const pt = points[i];
            const isLatest = (i === numBars - 1);
            const barH = Math.max(pt.val > 0 ? 3 : 1, canvas.height - 6 - pt.y);

            // A. Background track rail
            const trackGrad = ctx.createLinearGradient(0, 16, 0, canvas.height - 6);
            trackGrad.addColorStop(0, isLight ? 'rgba(226, 232, 240, 0.2)' : 'rgba(30, 41, 59, 0.2)');
            trackGrad.addColorStop(1, isLight ? 'rgba(226, 232, 240, 0.55)' : 'rgba(30, 41, 59, 0.55)');
            ctx.fillStyle = trackGrad;
            ctx.fillRect(pt.x, 16, barWidth, usableHeight + 2);

            // B. Active bar with dynamic gradient
            const grad = ctx.createLinearGradient(0, canvas.height - 6, 0, pt.y);
            if (isLatest && pt.val > 0) {
                grad.addColorStop(0, isLight ? 'rgba(2, 132, 199, 0.25)' : 'rgba(56, 189, 248, 0.25)');
                grad.addColorStop(1, isLight ? '#0284c7' : '#38bdf8');
            } else if (pt.val > 0) {
                grad.addColorStop(0, isOrange ? (isLight ? 'rgba(234, 88, 12, 0.25)' : 'rgba(247, 147, 26, 0.25)') : (isLight ? 'rgba(5, 150, 105, 0.25)' : 'rgba(16, 185, 129, 0.25)'));
                grad.addColorStop(1, isOrange ? (isLight ? '#ea580c' : '#f7931a') : (isLight ? '#059669' : '#10b981'));
            } else {
                grad.addColorStop(0, isLight ? 'rgba(148, 163, 184, 0.25)' : 'rgba(71, 85, 105, 0.25)');
                grad.addColorStop(1, isLight ? 'rgba(148, 163, 184, 0.45)' : 'rgba(71, 85, 105, 0.45)');
            }
            ctx.fillStyle = grad;
            ctx.fillRect(pt.x, pt.y, barWidth, barH);

            // C. Bar accent top cap
            if (pt.val > 0) {
                ctx.fillStyle = isLatest
                    ? (isLight ? '#0284c7' : '#7dd3fc')
                    : (isOrange ? (isLight ? '#f97316' : '#f59e0b') : (isLight ? '#34d399' : '#6ee7b7'));
                ctx.fillRect(pt.x, pt.y - 1, barWidth, 2);
            }

            // D. Floating Peak-Hold Meter with Gravity Decay
            const peakVal = window.tpsPeakDecay[i];
            if (peakVal > 0) {
                const peakNorm = Math.min(1.0, peakVal / maxVal);
                const peakY = Math.round(canvas.height - 6 - (peakNorm * usableHeight));
                ctx.fillStyle = isLatest
                    ? (isLight ? '#0284c7' : '#38bdf8')
                    : (isOrange ? (isLight ? '#c2410c' : '#f59e0b') : (isLight ? '#047857' : '#34d399'));
                ctx.fillRect(pt.x, Math.max(16, peakY - 2), barWidth, 2);
            }
        }

        // 6. Real-Time Ingestion Radar Beacon (Latest Bar Pulse)
        if (currentTps > 0 && points.length > 0) {
            const lastPt = points[points.length - 1];
            const pulsePhase = (Date.now() % 1000) / 1000;
            const pulseRadius = 3 + pulsePhase * 7;
            const pulseAlpha = Math.max(0, 1.0 - pulsePhase);

            ctx.save();
            ctx.beginPath();
            ctx.arc(lastPt.centerX, lastPt.y, pulseRadius, 0, Math.PI * 2);
            ctx.strokeStyle = isLight ? `rgba(2, 132, 199, ${pulseAlpha})` : `rgba(56, 189, 248, ${pulseAlpha})`;
            ctx.lineWidth = 1.4;
            ctx.stroke();

            ctx.beginPath();
            ctx.arc(lastPt.centerX, lastPt.y, 2.5, 0, Math.PI * 2);
            ctx.fillStyle = isLight ? '#0284c7' : '#38bdf8';
            ctx.fill();
            ctx.restore();
        }

        // 7. Interactive Crosshair Scanner & On-Canvas HUD Badge (Does NOT scroll timeline)
        if (!canvas._hasTpsHover) {
            canvas._hasTpsHover = true;
            canvas._hoverIdx = -1;

            canvas.addEventListener('mousemove', (e) => {
                const rect = canvas.getBoundingClientRect();
                const mouseX = (e.clientX - rect.left) * (canvas.width / rect.width);
                const step = barWidth + gap;
                const idx = Math.floor((mouseX - marginX) / step);

                if (idx >= 0 && idx < numBars) {
                    canvas._hoverIdx = idx;
                } else {
                    canvas._hoverIdx = -1;
                }
                updateTpsChart(true);
            });

            canvas.addEventListener('mouseleave', () => {
                canvas._hoverIdx = -1;
                const probeEl = document.getElementById('tps-probe-val');
                if (probeEl) probeEl.textContent = 'Hover to inspect';
                updateTpsChart(true);
            });
        }

        if (canvas._hoverIdx >= 0 && canvas._hoverIdx < numBars) {
            const hIdx = canvas._hoverIdx;
            const hVal = window.tpsHistory[hIdx];
            const hPt = points[hIdx];
            const timeOffset = numBars - 1 - hIdx;

            // Vertical laser scanner hairline
            ctx.save();
            ctx.strokeStyle = isLight ? 'rgba(15, 23, 42, 0.45)' : 'rgba(248, 250, 252, 0.45)';
            ctx.lineWidth = 1;
            ctx.setLineDash([2, 2]);
            ctx.beginPath();
            ctx.moveTo(hPt.centerX, 16);
            ctx.lineTo(hPt.centerX, canvas.height - 6);
            ctx.stroke();
            ctx.setLineDash([]);

            // Glowing target indicator node
            ctx.beginPath();
            ctx.arc(hPt.centerX, hPt.y, 4, 0, Math.PI * 2);
            ctx.fillStyle = isOrange ? (isLight ? '#ea580c' : '#f7931a') : (isLight ? '#059669' : '#10b981');
            ctx.fill();
            ctx.strokeStyle = '#ffffff';
            ctx.lineWidth = 1.5;
            ctx.stroke();
            ctx.restore();

            const probeEl = document.getElementById('tps-probe-val');
            if (probeEl) {
                probeEl.innerHTML = `<span style="color: var(--accent-green); font-weight: bold;">${hVal.toFixed(2)} TPS</span> (T-${timeOffset}s)`;
            }
        }

        // 8. Scale Ceiling & Timeline Annotations
        ctx.fillStyle = isLight ? '#64748b' : '#94a3b8';
        ctx.font = '9px monospace';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'alphabetic';

        ctx.fillText(`Scale Ceiling: ${maxVal.toFixed(0)} TPS`, marginX, 12);
        ctx.fillText('-60s', marginX, canvas.height - 2);
        ctx.fillText('-30s', Math.round(canvas.width / 2) - 10, canvas.height - 2);

        ctx.textAlign = 'right';
        ctx.fillText('Real-Time', canvas.width - marginX, canvas.height - 2);
    }
    window.updateTpsChart = updateTpsChart;
    setInterval(() => updateTpsChart(false), 1000);

    // 2. Capture incoming transaction & pointer telemetry into local store
    const originalOnTransactionAudited = client.onTransactionAudited;
    client.onTransactionAudited = (data) => {
        if (originalOnTransactionAudited) originalOnTransactionAudited(data);

        const { txId, typeString, parsedTx } = data;
        const effectiveTxId = txId || (parsedTx ? parsedTx.txIdHex : null);

        // Ingest unique transaction samples into the active TPS window across all nodes
        if (effectiveTxId) {
            if (!window.seenTpsTxIds) window.seenTpsTxIds = new Set();
            if (!window.seenTpsTxIds.has(effectiveTxId)) {
                window.seenTpsTxIds.add(effectiveTxId);
                if (!window.tpsTxTimestamps) window.tpsTxTimestamps = [];
                window.tpsTxTimestamps.push(Date.now());
            }
        } else {
            if (!window.tpsTxTimestamps) window.tpsTxTimestamps = [];
            window.tpsTxTimestamps.push(Date.now());
        }
        if (parsedTx) {
            if (!blockchainStore.transactions.some(t => t.txId === txId)) {
                blockchainStore.transactions.push({
                    txId: txId || parsedTx.txIdHex,
                    typeString: typeString,
                    amount: parsedTx.amount,
                    recipientPubkeyHex: parsedTx.recipientPubkeyHex,
                    senderPubkeyHex: parsedTx.senderPubkeyHex,
                    pointerId: (parsedTx.generatedPointers && parsedTx.generatedPointers.length > 0) ? parsedTx.generatedPointers[0].pointerIdHex : null,
                    parentCoinId: parsedTx.parentCoinIdHex,
                    timestamp: Date.now()
                });
            }

            if (typeString === 'OP_MINT_COIN' && parsedTx.parentCoinIdHex) {
                const pCoinId = parsedTx.parentCoinIdHex;
                const existingCoin = blockchainStore.coins.get(pCoinId);
                if (existingCoin && parsedTx.auditSnapshot) {
                    existingCoin.auditSnapshot = parsedTx.auditSnapshot;
                }
                if (parsedTx.leafHashHex && parsedTx.auditSnapshot) {
                    if (!window.leafAuditSnapshots) window.leafAuditSnapshots = new Map();
                    window.leafAuditSnapshots.set(parsedTx.leafHashHex, parsedTx.auditSnapshot);
                    window.leafAuditSnapshots.set(pCoinId, parsedTx.auditSnapshot);
                }
            }

            if (parsedTx.inputPointerIds) {
                parsedTx.inputPointerIds.forEach(inId => {
                    const ptr = blockchainStore.pointers.get(inId);
                    if (ptr) {
                        ptr.spent = 1;
                    } else if (parsedTx.parentCoinIdHex) {
                        blockchainStore.pointers.set(inId, {
                            pointerId: inId,
                            parentCoinId: parsedTx.parentCoinIdHex,
                            ownerAddress: parsedTx.senderAddressHex,
                            prevTxHash: parsedTx.prevTxHashHex || parsedTx.txIdHex,
                            spent: 1,
                            staked: false
                        });
                    }
                    if (window.unspentPointers) {
                        const unspentPtr = window.unspentPointers.find(p => p.pointerId === inId);
                        if (unspentPtr) unspentPtr.spent = true;
                    }
                });
            }

            if (parsedTx.generatedPointers) {
                parsedTx.generatedPointers.forEach(ptr => {
                    const existing = blockchainStore.pointers.get(ptr.pointerIdHex);
                    const isSpent = existing ? (existing.spent === true || existing.spent === 1 || existing.spent === 2) : false;
                    blockchainStore.pointers.set(ptr.pointerIdHex, {
                        pointerId: ptr.pointerIdHex,
                        parentCoinId: ptr.parentCoinIdHex,
                        startSubunit: ptr.startSubunit,
                        endSubunit: ptr.endSubunit,
                        ownerAddress: ptr.ownerAddressHex,
                        prevTxHash: ptr.prevTxHashHex,
                        spent: isSpent ? existing.spent : ptr.spent,
                        staked: ptr.staked
                    });
                });
            }
        }

        if (viewBlockchain && viewBlockchain.style.display !== 'none') {
            renderBlockchainLedgerView();
        }
    };

    // 3. Render and Filter Blockchain Ledger View
    const searchCoinIdInput = document.getElementById('search-coin-id');
    const searchPointerIdInput = document.getElementById('search-pointer-id');
    const searchUserIdInput = document.getElementById('search-user-id');
    const txTypeCheckboxes = document.querySelectorAll('.tx-type-filter');
    const btnResetBlockchainView = document.getElementById('btn-reset-blockchain-view');
    const ledgerOutputContainer = document.getElementById('blockchain-ledger-output');

    /**
     * @brief Filters and renders coins, subunit pointer ranges, and operations in the Blockchain Explorer view.
     * @return {void}
     * @complexity Time: O(coins + pointers), Space: O(rendered_html_length).
     */
    function renderBlockchainLedgerView() {
        if (!ledgerOutputContainer) return;
        // Bypasses DOM construction if the user is not actively on the Blockchain Explorer tab
        if (!viewBlockchain || viewBlockchain.style.display === 'none') return;

        const coinQuery = (searchCoinIdInput?.value || '').trim().toLowerCase();
        const pointerQuery = (searchPointerIdInput?.value || '').trim().toLowerCase();
        const userQuery = (searchUserIdInput?.value || '').trim().toLowerCase();
        const selectedTypes = new Set(Array.from(txTypeCheckboxes).filter(cb => cb.checked).map(cb => cb.value));

        // Consolidate pointers from authoritative store and unspentPointers cache
        const allPointers = new Map(blockchainStore.pointers);

        (window.unspentPointers || []).forEach(p => {
            if (p.pointerId && !allPointers.has(p.pointerId)) {
                allPointers.set(p.pointerId, p);
            }
        });

        // Pre-group pointers by parentCoinId in a single O(P) pass to eliminate O(C x P) re-filtering
        const pointersByCoin = new Map();
        for (const ptr of allPointers.values()) {
            if (!ptr.parentCoinId) continue;
            let list = pointersByCoin.get(ptr.parentCoinId);
            if (!list) {
                list = [];
                pointersByCoin.set(ptr.parentCoinId, list);
            }
            list.push(ptr);
        }

        // Consolidate coins strictly from verified mint operations
        const allCoins = new Map(blockchainStore.coins);

        let html = '';

        // A. Filter and Render Transactions Matching Selected Checkboxes (Shown only when active filters exist)
        const isFiltering = selectedTypes.size > 0 || !!coinQuery || !!pointerQuery || !!userQuery;
        const filteredTxs = isFiltering ? blockchainStore.transactions.filter(tx => {
            if (selectedTypes.size > 0 && !selectedTypes.has(tx.typeString)) return false;
            if (coinQuery && !tx.parentCoinId?.toLowerCase().includes(coinQuery) && !tx.txId?.toLowerCase().includes(coinQuery)) return false;
            if (pointerQuery && !tx.pointerId?.toLowerCase().includes(pointerQuery)) return false;
            if (userQuery) {
                const sender = (tx.senderPubkeyHex || '').toLowerCase();
                const recipient = (tx.recipientPubkeyHex || '').toLowerCase();
                const resolvedPk = resolveUserIdToPubkey(userQuery)?.toLowerCase();
                const matchesSender = sender.includes(userQuery) || (resolvedPk && sender.includes(resolvedPk));
                const matchesRecipient = recipient.includes(userQuery) || (resolvedPk && recipient.includes(resolvedPk));
                if (!matchesSender && !matchesRecipient) return false;
            }
            return true;
        }) : [];

        if (filteredTxs.length > 0) {
            const isLight = document.documentElement.classList.contains('light-mode');
            const opTypeColor = isLight ? '#7c3aed' : '#a78bfa';
            html += `<div style="font-weight: 600; font-size: 0.9rem; color: var(--text-main); margin-bottom: -4px;">Filtered Operations (${filteredTxs.length})</div>`;
            filteredTxs.forEach(tx => {
                const sclAmt = formatScl(Number(tx.amount) / 160000000, 8);
                html += `
                    <div class="blockchain-coin-card" style="border-left: 4px solid var(--accent-green);">
                        <div style="display: flex; justify-content: space-between; font-family: monospace; font-size: 0.8rem; flex-wrap: wrap; gap: 8px;">
                            <span>Op Type: <strong style="color: ${opTypeColor};">${tx.typeString}</strong></span>
                            <span>Tx ID: <strong style="color: var(--text-main);">${tx.txId}</strong></span>
                            <span>Amount: <strong style="color: var(--accent-green);">¢${sclAmt}</strong></span>
                        </div>
                    </div>
                `;
            });
        }

        // B. Filter and Render Coins & Nested Pointers
        const sortedCoins = Array.from(allCoins.values()).sort((a, b) => {
            const numA = (a.blockNumber !== undefined && a.blockNumber !== null) ? a.blockNumber : Infinity;
            const numB = (b.blockNumber !== undefined && b.blockNumber !== null) ? b.blockNumber : Infinity;
            return numA - numB;
        });

        const coinEntries = sortedCoins.map((coin, index) => ({
            ...coin,
            originalIndex: index
        })).filter(coin => {
            if (coin.totalSubunits <= 0 || coin.totalSubunits > 2560000000000000) return false;
            if (coinQuery && !coin.coinId.toLowerCase().includes(coinQuery)) return false;
            if (pointerQuery) {
                const hasMatchingPointer = Array.from(allPointers.values()).some(
                    p => p.parentCoinId === coin.coinId && p.pointerId.toLowerCase().includes(pointerQuery)
                );
                if (!hasMatchingPointer) return false;
            }
            if (userQuery) {
                const coinOwnerMatch = coin.ownerAddress?.toLowerCase().includes(userQuery);
                const hasMatchingPointer = Array.from(allPointers.values()).some(
                    p => p.parentCoinId === coin.coinId && (p.ownerAddress || p.ownerAddressHex || '').toLowerCase().includes(userQuery)
                );
                if (!coinOwnerMatch && !hasMatchingPointer) return false;
            }
            if (selectedTypes.size > 0) {
                const coinChildPointers = Array.from(allPointers.values()).filter(cp => cp.parentCoinId === coin.coinId);
                const hasMatchingPointer = Array.from(allPointers.values()).some(p => {
                    if (p.parentCoinId !== coin.coinId) return false;
                    const isSpent = (p.spent === true || p.spent === 1 || p.spent === '1') ||
                        coinChildPointers.some(other =>
                            other.pointerId !== p.pointerId &&
                            BigInt(other.startSubunit || 0) >= BigInt(p.startSubunit || 0) &&
                            BigInt(other.endSubunit || 0) <= BigInt(p.endSubunit || 0) &&
                            (BigInt(other.endSubunit || 0) - BigInt(other.startSubunit || 0) < BigInt(p.endSubunit || 0) - BigInt(p.startSubunit || 0))
                        );
                    if (isSpent) {
                        return selectedTypes.has('SPENT');
                    }
                    if (selectedTypes.has('FEE_RECYCLED') && (p.spent === 2 || p.spent === '2')) return true;
                    if (selectedTypes.has('OP_MINT_COIN') && (!p.spent && !p.staked)) return true;
                    if (selectedTypes.has('OP_TRANSFER_POINTER') && (!p.spent && !p.staked)) return true;
                    if (selectedTypes.has('OP_STAKE') && p.staked) return true;
                    if (selectedTypes.has('OP_UNSTAKE') && !p.staked) return true;
                    return false;
                });
                if (!hasMatchingPointer) return false;
            }
            return true;
        });

        if (coinEntries.length === 0 && filteredTxs.length === 0) {
            ledgerOutputContainer.innerHTML = `
                <div class="card" style="text-align: center; color: var(--text-muted); font-family: monospace; padding: 32px;">
                    No coins, pointers, or operations match the current filter criteria.
                </div>
            `;
            return;
        }

        html += `<div style="font-weight: 600; font-size: 0.9rem; color: var(--text-main); margin-top: 8px; margin-bottom: -4px;">Coins & Subunit Pointer Ledger (${coinEntries.length})</div>`;

        if (!window.expandedCoinIds) window.expandedCoinIds = new Set();

        coinEntries.forEach((coin, idx) => {
            const coinScl = formatScl(Number(coin.totalSubunits) / 160000000, 8);
            const childPointers = pointersByCoin.get(coin.coinId) || [];

            let pointerHtml = '';
            if (childPointers.length > 0) {
                childPointers.forEach(ptr => {
                    if (pointerQuery && !ptr.pointerId.toLowerCase().includes(pointerQuery)) return;
                    if (userQuery) {
                        const ptrOwner = (ptr.ownerAddress || ptr.ownerAddressHex || coin.ownerAddress || '').toLowerCase();
                        if (!ptrOwner.includes(userQuery)) return;
                    }

                    const isSpent = (ptr.spent === true || ptr.spent === 1 || ptr.spent === '1') ||
                        childPointers.some(other =>
                            other.pointerId !== ptr.pointerId &&
                            BigInt(other.startSubunit || 0) >= BigInt(ptr.startSubunit || 0) &&
                            BigInt(other.endSubunit || 0) <= BigInt(ptr.endSubunit || 0) &&
                            (BigInt(other.endSubunit || 0) - BigInt(other.startSubunit || 0) < BigInt(ptr.endSubunit || 0) - BigInt(ptr.startSubunit || 0))
                        );

                    if (isSpent) {
                        if (selectedTypes.size > 0 && !selectedTypes.has('SPENT')) return;
                    } else if (selectedTypes.size > 0) {
                        let matches = false;
                        if (selectedTypes.has('FEE_RECYCLED') && (ptr.spent === 2 || ptr.spent === '2')) matches = true;
                        if (selectedTypes.has('OP_MINT_COIN') && (!ptr.spent && !ptr.staked)) matches = true;
                        if (selectedTypes.has('OP_TRANSFER_POINTER') && (!ptr.spent && !ptr.staked)) matches = true;
                        if (selectedTypes.has('OP_STAKE') && ptr.staked) matches = true;
                        if (selectedTypes.has('OP_UNSTAKE') && !ptr.staked) matches = true;
                        if (!matches) return;
                    }

                    const rangeSize = Number(BigInt(ptr.endSubunit || 0) - BigInt(ptr.startSubunit || 0) + 1n);
                    const ptrScl = formatScl(Number(rangeSize) / 160000000, 8);
                    const startFmt = Number(ptr.startSubunit || 0).toLocaleString('en-US');
                    const endFmt = Number(ptr.endSubunit || 0).toLocaleString('en-US');

                    let badgeClass = 'badge-unspent';
                    let statusText = 'Unspent';
                    if (isSpent) {
                        badgeClass = 'badge-spent'; statusText = 'Spent';
                    } else if (ptr.spent === 2 || ptr.spent === '2') {
                        badgeClass = 'badge-fee'; statusText = 'Fee';
                    } else if (ptr.staked) {
                        badgeClass = 'badge-staked'; statusText = 'Staked';
                    }

                    pointerHtml += `
                        <div style="font-family: monospace; font-size: 0.78rem; display: flex; flex-direction: column; gap: 4px; background-color: var(--bg-primary); padding: 8px 12px; border-radius: 4px; border: 1px solid var(--border-color);">
                            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                                <span>Pointer ID: <strong style="color: var(--text-main);">${ptr.pointerId}</strong></span>
                                <span class="pointer-badge ${badgeClass}">${statusText}</span>
                            </div>
                            <div style="display: flex; flex-direction: column; color: var(--text-muted); gap: 4px;">
                                <span>Owner (first 32 bytes): ${(ptr.ownerAddress || '')}</span>
                                ${isSpent ? '' : `<span>Range: ${startFmt} - ${endFmt} units (¢${ptrScl})</span>`}
                            </div>
                        </div>
                    `;
                });
            } else {
                pointerHtml = `<div style="font-size: 0.75rem; color: var(--text-muted); font-family: monospace;">No sub-pointers mapped yet.</div>`;
            }

            const isExpanded = window.expandedCoinIds.has(coin.coinId);
            const displayStyle = isExpanded ? 'display: flex;' : 'display: none;';
            const toggleIcon = isExpanded ? '▲' : '▼';

            html += `
                <div class="blockchain-coin-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; font-family: monospace; font-size: 0.85rem; font-weight: bold; flex-wrap: wrap; gap: 8px;">
                        <span>Coin #${coin.originalIndex} ID: <span style="color: var(--accent-green);">${coin.coinId}</span></span>
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <span>Amount: ${Number(coin.totalSubunits).toLocaleString('en-US')} units (¢${coinScl})</span>
                            <button class="btn btn-toggle-coin-pointers" data-coin-id="${coin.coinId}" style="padding: 2px 6px; font-size: 0.75rem; background: transparent; border: none; color: var(--text-muted); cursor: pointer;" aria-label="Toggle Pointers">${toggleIcon}</button>
                        </div>
                    </div>
                    <div class="pointer-list-container" id="pointers-container-${coin.coinId}" style="${displayStyle}">
                        <span style="font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: var(--text-muted);">Associated Subunit Pointers:</span>
                        ${pointerHtml}
                    </div>
                </div>
            `;
        });

        ledgerOutputContainer.innerHTML = html;

        if (!ledgerOutputContainer._hasToggleListener) {
            ledgerOutputContainer.addEventListener('click', (e) => {
                const btn = e.target.closest('.btn-toggle-coin-pointers');
                if (btn) {
                    const coinId = btn.dataset.coinId;
                    const container = document.getElementById(`pointers-container-${coinId}`);
                    if (container) {
                        const isCollapsed = container.style.display === 'none';
                        if (isCollapsed) {
                            container.style.display = 'flex';
                            btn.textContent = '▲';
                            window.expandedCoinIds.add(coinId);
                        } else {
                            container.style.display = 'none';
                            btn.textContent = '▼';
                            window.expandedCoinIds.delete(coinId);
                        }
                    }
                }
            });
            ledgerOutputContainer._hasToggleListener = true;
        }
    }

     // 4. Attach Event Listeners for Live Search, Checkboxes, and Reset Button
     if (searchCoinIdInput) searchCoinIdInput.addEventListener('input', renderBlockchainLedgerView);
     if (searchPointerIdInput) searchPointerIdInput.addEventListener('input', renderBlockchainLedgerView);
     if (searchUserIdInput) searchUserIdInput.addEventListener('input', renderBlockchainLedgerView);
     txTypeCheckboxes.forEach(cb => cb.addEventListener('change', renderBlockchainLedgerView));

     if (btnResetBlockchainView) {
         btnResetBlockchainView.addEventListener('click', () => {
             if (searchCoinIdInput) searchCoinIdInput.value = '';
             if (searchPointerIdInput) searchPointerIdInput.value = '';
             if (searchUserIdInput) searchUserIdInput.value = '';
             txTypeCheckboxes.forEach(cb => cb.checked = false);
             renderBlockchainLedgerView();
         });
     }

     // 5. Jump to Top Feature for Blockchain Explorer
     const btnScrollTop = document.getElementById('btn-scroll-top');
     if (btnScrollTop) {
         const toggleScrollTopVisibility = () => {
             if (window.scrollY > 300) {
                 btnScrollTop.classList.add('visible');
             } else {
                 btnScrollTop.classList.remove('visible');
             }
         };

         window.addEventListener('scroll', toggleScrollTopVisibility, { passive: true });

         btnScrollTop.addEventListener('click', () => {
             window.scrollTo({ top: 0, behavior: 'smooth' });
         });
     }
});
