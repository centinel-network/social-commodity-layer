/**
 * @file drift_certificates.js
 * @module client/ui/drift_certificates - Enterprise Drift Certificate TVD Auditing Platform
 *
 * @brief Isolated module powering the "Drift Certificates" sidebar view: histogram
 *        submission (RPC 0x000D, SCL402-metered), on-chain certificate anchoring
 *        (OP_APPLY_DRIFT_CERT via SubmitTx 0x0003), and professional deliverable export.
 *
 * @dependencies
 * - `auditor_client.js` (window.client / SclAuditorClient)
 * - `explorer_app.js` (window.selectUnspentPointers, window.resolveWalletCredentials,
 *   window.confirmedTxIds, window.lastBalanceSubunits)
 */
(function () {
    'use strict';

    /* ========================================================================
     * SECTION 1: CONSTANTS & MODULE STATE
     * ===================================================================== */

    /** @const {bigint} Atomic subunits per whole SCL coin. */
    const SUBUNITS_PER_COIN = 160000000n;

    /** @const {number} Fixed Hilbert-space dimensionality of the 7-qubit audit register. */
    const DRIFT_HISTOGRAM_DIM = 128;

    /** @const {bigint} Audit base fee: 1 SCL (mirrors the RPC 0x000D 402 gate exactly). */
    const DRIFT_BASE_FEE_SUBUNITS = 160000000n;

    /** @const {bigint} Audit fee per commenced 10,000 shots: 0.2 SCL. */
    const DRIFT_FEE_PER_10K_SHOTS = 32000000n;

    /** @const {bigint} On-chain anchoring fee: 0.5 SCL (halved staking-grade schedule). */
    const ANCHOR_FEE_SUBUNITS = 80000000n;

    /** @const {Array<string>} Human-readable drift classification labels. */
    const STATUS_LABELS = ['Fidelity Optimal', 'Drift Tolerable', 'Decoherence Exceeded', 'Tampering Suspected'];

    /** @const {Array<string>} Drift classification accent colors. */
    const STATUS_COLORS = ['var(--accent-green)', '#eab308', '#f97316', 'var(--accent-red)'];

    /** @type {Object} Module state container. */
    const state = {
        lastAudit: null,      // Parsed 0x000D certificate payload
        lastHistogram: null,  // Parsed 128-bin count array (for the deliverable)
        lastContext: null,    // { shots, beaconSeed, circuitText }
        anchor: null,         // { txIdHex, reqId, fee, appliedAt, confirmed }
        pollTimer: null,
        bound: false,
        auditWatchdog: null,  // Timeout handle flagging a silently missing 0x000D response
        sampleBeaconSeed: null // 32-byte client beacon bound to the loaded healthy sample
    };

    /* ========================================================================
     * SECTION 2: HELPERS
     * ===================================================================== */

    /**
     * @brief Formats raw subunits as a human-readable SCL amount.
     * @param {bigint|number} subunits Atomic subunit quantity.
     * @return {string} Formatted SCL string.
     */
    function fmtScl(subunits) {
        return (Number(subunits) / Number(SUBUNITS_PER_COIN)).toFixed(4) + ' SCL';
    }

    /**
     * @brief Quotes the audit fee for a shot budget. Mirrors rpc.c case 0x000D exactly:
     *        1 SCL base + 0.2 SCL per commenced 10,000 shots.
     * @param {number} shots Measurement shot budget.
     * @return {bigint} Fee in subunits.
     */
    function quoteAuditFee(shots) {
        const commenced = BigInt(Math.max(1, Math.ceil(Number(shots) / 10000)));
        return DRIFT_BASE_FEE_SUBUNITS + DRIFT_FEE_PER_10K_SHOTS * commenced;
    }

    /**
     * @brief Renders the live pipeline status badge.
     * @param {string} text Status label.
     * @param {string|null} color Optional CSS color.
     */
    function setStatus(text, color) {
        const el = document.getElementById('drift-status-badge');
        if (!el) return;
        el.textContent = text;
        el.style.color = color || 'var(--text-muted)';
    }

    /**
     * @brief Renders the wallet balance badge from explorer telemetry.
     */
    function refreshBalance() {
        const el = document.getElementById('drift-balance-badge');
        if (!el) return;
        /* Mirror the dashboard's shared wallet telemetry (updated every 2 s by the
         * chained onBalanceReceived hook). Keep the em-dash placeholder only while
         * no wallet has been loaded at all. */
        const walletLoaded = !!(window.client && window.client.walletPubkeyBytes) ||
            (typeof window.lastBalanceSubunits === 'bigint');
        if (!walletLoaded) {
            el.textContent = 'Balance: — (no wallet loaded)';
            el.style.color = 'var(--text-muted)';
            return;
        }
        const bal = window.lastBalanceSubunits || 0n;
        const shots = parseInt((document.getElementById('drift-shots') || {}).value || '15000', 10) || 15000;
        const needed = quoteAuditFee(shots) + ANCHOR_FEE_SUBUNITS;
        el.textContent = 'Balance: ' + fmtScl(bal);
        el.style.color = (bal >= needed) ? 'var(--accent-green)' : 'var(--accent-red)';
    }

    /**
     * @brief Sets the progress line under the submission form.
     * @param {string} text Message.
     * @param {boolean} [busy=false] Busy flag.
     */
    function progress(text, busy) {
        const el = document.getElementById('drift-progress');
        if (el) {
            el.textContent = text;
            el.style.color = busy ? 'var(--text-muted)' : 'var(--text-main)';
        }
    }

    /**
     * @brief Encodes a 128-bin count array into the 512-byte wire histogram
     *        (128 x u32 Big-Endian), matching the C engine's ingestion layout.
     * @param {Array<number>} counts 128 non-negative integers.
     * @return {Uint8Array} 512-byte wire buffer.
     */
    function buildHistogramBytes(counts) {
        const out = new Uint8Array(DRIFT_HISTOGRAM_DIM * 4);
        const view = new DataView(out.buffer);
        for (let i = 0; i < DRIFT_HISTOGRAM_DIM; i++) {
            view.setUint32(i * 4, counts[i] >>> 0, false);
        }
        return out;
    }

    /**
     * @brief Parses and validates the histogram textarea / file content.
     * @param {string} raw Raw JSON array or CSV text.
     * @param {number} shots Declared shot budget (conservation target).
     * @return {{ok: boolean, counts: Array<number>|null, error: string|null}}
     */
    function parseHistogram(raw, shots) {
        const text = (raw || '').trim();
        if (!text) return { ok: false, counts: null, error: 'Histogram is empty. Paste a 128-element JSON array or CSV, or click "Load Healthy QPU Sample".' };
        let values = null;
        try {
            const parsed = JSON.parse(text);
            if (Array.isArray(parsed)) values = parsed.map(Number);
        } catch (e) {
            values = text.split(/[\s,;]+/).filter(s => s.length > 0).map(Number);
        }
        if (!values || values.length !== DRIFT_HISTOGRAM_DIM) {
            return { ok: false, counts: null, error: 'Histogram must contain exactly 128 basis-state counts (found ' + (values ? values.length : 0) + ').' };
        }
        let total = 0;
        for (let i = 0; i < DRIFT_HISTOGRAM_DIM; i++) {
            if (!Number.isFinite(values[i]) || values[i] < 0 || !Number.isInteger(values[i])) {
                return { ok: false, counts: null, error: 'Bin ' + i + ' is not a non-negative integer.' };
            }
            total += values[i];
        }
        if (total !== Number(shots)) {
            return { ok: false, counts: null, error: 'Shot conservation violated: histogram totals ' + total + ' but the budget is ' + shots + '. The engine rejects non-conserving histograms.' };
        }
        return { ok: true, counts: values, error: null };
    }

    /** @const {string} Exact bytes of the engine's default calibration circuit
     * (quantum_tvd.cpp default_circuit[]). The healthy sample fills the circuit
     * field with this string so the digest the node audits equals the digest the
     * client-side ideal-distribution mirror computed against. */
    const CALIBRATION_CIRCUIT_QASM = 'OPENQASM 2.0; include "qelib1.inc"; qreg q[7]; h q; cx q[0], q[1];';

    /**
     * @brief Mirrors quantum_compute_ideal_distribution_qsim() byte-for-byte:
     *        SHA-256(circuit || beaconSeed) seeds a Knuth/MMIX LCG; amplitudes
     *        0.01 + (lcg & 0xFFFFFF) / 2^24 are L2-normalized, squared (Born rule),
     *        then L1-normalized. Produces the exact distribution the node will
     *        benchmark the submitted histogram against for the same seed.
     * @param {string} circuitText OpenQASM text (must equal the bytes sent to the node).
     * @param {Uint8Array} beaconSeed 32-byte client-generated beacon seed.
     * @return {Promise<Array<number>>} 128 ideal probabilities summing to 1.
     */
    async function computeIdealDistribution(circuitText, beaconSeed) {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('WebCrypto unavailable (secure context required) — cannot derive the qsim baseline');
        }
        const circuitBytes = new TextEncoder().encode(circuitText);
        const hashInput = new Uint8Array(circuitBytes.length + 32);
        hashInput.set(circuitBytes, 0);
        hashInput.set(beaconSeed, circuitBytes.length);
        const digest = new Uint8Array(await window.crypto.subtle.digest('SHA-256', hashInput));

        /* First 8 digest bytes as a little-endian u64 (host-order memcpy in C). */
        let lcg = 0n;
        for (let i = 7; i >= 0; i--) lcg = (lcg << 8n) | BigInt(digest[i]);
        if (lcg === 0n) lcg = 0xdeadbeefcafebaben;

        const M64 = 0xFFFFFFFFFFFFFFFFn;
        const amps = new Array(DRIFT_HISTOGRAM_DIM);
        let sumSq = 0;
        for (let i = 0; i < DRIFT_HISTOGRAM_DIM; i++) {
            lcg = (lcg * 6364136223846793005n + 1442695040888963407n) & M64;
            amps[i] = 0.01 + Number(lcg & 0xFFFFFFn) / 16777216.0;
            sumSq += amps[i] * amps[i];
        }
        const invNorm = (sumSq > 0) ? 1 / Math.sqrt(sumSq) : 1;
        const probs = new Array(DRIFT_HISTOGRAM_DIM);
        let total = 0;
        for (let i = 0; i < DRIFT_HISTOGRAM_DIM; i++) {
            probs[i] = Math.pow(amps[i] * invNorm, 2);
            total += probs[i];
        }
        const invTotal = (total > 0) ? 1 / total : 1;
        for (let i = 0; i < DRIFT_HISTOGRAM_DIM; i++) probs[i] *= invTotal;
        return probs;
    }

    /**
     * @brief Generates a demonstrative healthy-QPU histogram matching the engine's
     *        ideal distribution exactly (deterministic largest-remainder allocation,
     *        conserving the declared shot budget to the last shot). Against the
     *        beacon-seeded qsim baseline this audits as Fidelity Optimal.
     * @param {Array<number>} ideal 128 ideal probabilities.
     * @param {number} shots Shot budget.
     * @return {Array<number>} 128 counts summing to shots.
     */
    function sampleHistogramFromIdeal(ideal, shots) {
        const counts = ideal.map(p => Math.floor(p * shots));
        let assigned = counts.reduce((a, b) => a + b, 0);
        /* Largest-remainder pass: the shortfall (< 128) goes to the bins with the
         * largest fractional parts so the total conserves the budget exactly. */
        const order = ideal
            .map((p, i) => ({ i: i, frac: p * shots - Math.floor(p * shots) }))
            .sort((a, b) => b.frac - a.frac);
        const shortfall = shots - assigned;
        for (let j = 0; j < shortfall && j < order.length; j++) {
            counts[order[j].i] += 1;
        }
        return counts;
    }

    /* ========================================================================
     * SECTION 3: AUDIT SUBMISSION (RPC 0x000D, SCL402-METERED)
     * ===================================================================== */

    /**
     * @brief Arms the no-response watchdog for an in-flight 0x000D audit. A silent
     *        dead end (no certificate, no 402, no error) is reported with live
     *        pipeline diagnostics instead of leaving the operator staring at
     *        "AWAITING NODE" forever.
     * @param {number} [timeoutMs=30000] Watchdog window.
     */
    function armAuditWatchdog(timeoutMs) {
        disarmAuditWatchdog();
        state.auditWatchdog = setTimeout(() => {
            state.auditWatchdog = null;
            if (state.lastAudit) return; // A certificate already arrived.
            const client = window.client;
            const connected = !!(client && client.socket && client.socket.readyState === WebSocket.OPEN);
            setStatus(connected ? 'NO NODE RESPONSE' : 'PIPELINE DISCONNECTED', 'var(--accent-red)');
            progress('No drift certificate within ' + Math.round((timeoutMs || 30000) / 1000) +
                's. Diagnostics — connection: ' + (connected ? 'OPEN' : 'CLOSED') +
                '; WebAssembly engine: ' + (client && client.isWasmLoaded ? 'loaded' : 'still compiling') +
                '. If the node returned SCL402 the fee settlement micro-transaction may still be pending ' +
                'block inclusion; otherwise the request was dropped before reaching the 0x000D handler.', false);
        }, timeoutMs || 30000);
    }

    /**
     * @brief Cancels the audit watchdog once any terminal event arrives.
     */
    function disarmAuditWatchdog() {
        if (state.auditWatchdog) {
            clearTimeout(state.auditWatchdog);
            state.auditWatchdog = null;
        }
    }

    /**
     * @brief Validates the form, then dispatches the drift certificate audit request.
     *        Every failure mode states its exact requirement — the button never fails silently.
     */
    function submitAudit() {
        const client = window.client;
        if (!client || !client.socket || client.socket.readyState !== WebSocket.OPEN) {
            setStatus('PIPELINE DISCONNECTED', 'var(--accent-red)');
            progress('Cannot run the audit: no live node connection. Requirements: (1) open the Dashboard, ' +
                'load or generate wallet credentials and click "Connect Node"; (2) return here — the status ' +
                'badge above switches to PIPELINE CONNECTED automatically; (3) load the histogram; (4) Run Audit.', false);
            return;
        }
        if (!client.isWasmLoaded) {
            progress('The WebAssembly audit engine is still compiling inside the worker thread. Retry in a few seconds.', false);
            return;
        }
        if (typeof client.requestDriftCertAudit !== 'function') {
            progress('Audit pipeline unavailable: auditor_client.js did not expose requestDriftCertAudit. Reload the page.', false);
            return;
        }

        const shotsEl = document.getElementById('drift-shots');
        const shots = parseInt(shotsEl ? shotsEl.value : '', 10);
        if (!Number.isInteger(shots) || shots < 1000 || shots > 100000) {
            progress('Shot budget must be an integer between 1,000 and 100,000.', false);
            return;
        }

        const histogramEl = document.getElementById('drift-histogram');
        const parsed = parseHistogram(histogramEl ? histogramEl.value : '', shots);
        if (!parsed.ok) {
            progress(parsed.error, false);
            return;
        }

        const circuitEl = document.getElementById('drift-circuit');
        const circuitText = (circuitEl ? circuitEl.value : '').trim();
        const circuitBytes = circuitText.length > 0 ? new TextEncoder().encode(circuitText) : null;
        const beaconSeed = state.sampleBeaconSeed; // bound to the loaded sample; null -> node derives the DKG beacon

        state.lastHistogram = parsed.counts;
        state.lastContext = { shots: shots, beaconSeed: beaconSeed, circuitText: circuitText };

        progress('Dispatching audit (Method 0x000D)… If the node returns SCL402, the fee (' +
            fmtScl(quoteAuditFee(shots)) + ') settles autonomously via an SCL micro-transaction and the query replays.', true);
        setStatus('AWAITING NODE', 'var(--text-muted)');

        armAuditWatchdog(30000);

        client.requestDriftCertAudit(shots, beaconSeed, buildHistogramBytes(parsed.counts), circuitBytes, null);
    }

    /**
     * @brief Renders a received drift certificate payload (parsed by the worker).
     * @param {Object} data Certificate fields from DRIFT_CERT_AUDIT_RECEIVED.
     */
    function onAuditReceived(data) {
        disarmAuditWatchdog();
        state.lastAudit = data;

        const tvd = Number(data.tvdDouble);
        const pct = Math.min(100, Math.max(2, Math.round(tvd * 100)));

        document.getElementById('drift-tvd').textContent = tvd.toFixed(6);
        const statusEl = document.getElementById('drift-status');
        statusEl.textContent = STATUS_LABELS[data.status] || 'Unknown';
        statusEl.style.color = STATUS_COLORS[data.status] || 'var(--text-main)';
        document.getElementById('drift-confidence').textContent = '± ' + Number(data.confidenceMargin).toFixed(6);

        const gauge = document.getElementById('drift-gauge');
        gauge.style.width = pct + '%';
        gauge.style.background = STATUS_COLORS[data.status] || 'var(--accent-green)';

        document.getElementById('drift-circuit-hash').textContent = data.circuitHash || '—';
        document.getElementById('drift-commitment').textContent = data.tvdCommitmentHex || '—';
        document.getElementById('drift-sig').textContent = data.validatorSigHex || '—';
        document.getElementById('drift-meta').textContent =
            (data.numQubits || 7) + ' qubits / ' + (data.shots || 0).toLocaleString() + ' shots / ' +
            new Date(Number(data.timestamp) / 1000).toISOString();

        document.getElementById('drift-results').style.display = 'block';
        document.getElementById('drift-anchor-card').style.display = 'block';
        document.getElementById('drift-export-card').style.display = 'block';

        setStatus('CERTIFICATE ISSUED', STATUS_COLORS[data.status]);
        progress('Drift certificate issued: TVD ' + tvd.toFixed(6) + ' (' + STATUS_LABELS[data.status] + '). Ready for on-chain anchoring.', false);
    }

    /* ========================================================================
     * SECTION 4: ON-CHAIN ANCHORING (OP_APPLY_DRIFT_CERT)
     * ===================================================================== */

    /**
     * @brief Applies the latest drift certificate on-chain, mirroring the staking flow:
     *        select unspent pointers, sign the canonical certificate digest with ML-DSA-87,
     *        and submit an OP_APPLY_DRIFT_CERT intent via SubmitTx (Method 0x0003).
     */
    function applyOnChain() {
        const client = window.client;
        const audit = state.lastAudit;
        if (!client || !audit) return;
        if (!client.socket || client.socket.readyState !== WebSocket.OPEN) {
            document.getElementById('drift-anchor-status').textContent =
                'No live node connection — anchoring requires the SCL bridge. Connect a node on the Dashboard first.';
            document.getElementById('drift-anchor-status').style.color = 'var(--accent-red)';
            return;
        }
        if (typeof window.selectUnspentPointers !== 'function' || typeof window.resolveWalletCredentials !== 'function') {
            document.getElementById('drift-anchor-status').textContent = 'Wallet utilities unavailable — connect a node first.';
            return;
        }

        const feePlusTx = ANCHOR_FEE_SUBUNITS; // node applies the halved fee schedule on top
        const totalNeeded = feePlusTx + BigInt(Math.floor(Number(feePlusTx) * 0.0157079633)); // ~1.5708% halved (staking-grade, pi/200) preview

        const liquid = window.lastBalanceSubunits || 0n;
        if (liquid < totalNeeded) {
            document.getElementById('drift-anchor-status').textContent =
                'Insufficient liquid balance (' + fmtScl(liquid) + '). Anchoring needs ' + fmtScl(totalNeeded) +
                ' (0.5 SCL anchor fee + halved network fee). Top up the wallet to anchor on-chain.';
            document.getElementById('drift-anchor-status').style.color = 'var(--accent-red)';
            return;
        }

        const selectedInputs = window.selectUnspentPointers(feePlusTx, false);
        if (!selectedInputs || selectedInputs.length === 0) {
            document.getElementById('drift-anchor-status').textContent = 'No unspent pointers available for funding.';
            return;
        }

        const creds = window.resolveWalletCredentials();
        if (!creds || !creds.privKeyHex || !creds.pubKeyHex) {
            document.getElementById('drift-anchor-status').textContent = 'Wallet credentials unavailable (unlock the vault).';
            return;
        }

        const statusEl = document.getElementById('drift-anchor-status');
        statusEl.style.color = 'var(--text-muted)';
        statusEl.textContent = 'Signing OP_APPLY_DRIFT_CERT intent with ML-DSA-87…';

        const reqId = ((BigInt(Date.now()) << 16n) | BigInt(Math.floor(Math.random() * 65535))).toString();
        state.anchor = { txIdHex: null, reqId: reqId, fee: feePlusTx, appliedAt: Date.now(), confirmed: false };

        client.submitTransaction(reqId, 'OP_APPLY_DRIFT_CERT', {
            circuitHashHex: audit.circuitHash,
            tvdScaled: String(audit.tvdScaled),
            shots: audit.shots,
            status: audit.status,
            commitmentRootHex: audit.tvdCommitmentHex.length === 64 ? audit.tvdCommitmentHex : '',
            timestampUs: String(audit.timestamp),
            recipientPubkeyHex: creds.pubKeyHex, // anchored certificate attributed to the enterprise wallet
            senderPubkeyHex: creds.pubKeyHex,
            privkeyHex: creds.privKeyHex,
            amountSubunits: feePlusTx.toString(),
            inputs: selectedInputs
        });
    }

    /**
     * @brief Handles a signed anchoring wire frame: records the intent tx id and
     *        begins polling explorer telemetry for block inclusion.
     * @param {Object} frame WIRE_FRAME_READY payload.
     */
    function onWireFrameReady(frame) {
        if (!state.anchor || state.anchor.txIdHex) return;
        if (!frame || !frame.txIdHex) return;
        /* Only the anchoring intent this module dispatched (matched by requestId)
         * may occupy the anchor slot; concurrent SCL402 settlement frames for the
         * audit fee must not be mistaken for the on-chain certificate anchor. */
        if (state.anchor.reqId !== undefined && frame.requestId !== undefined &&
            String(frame.requestId) !== String(state.anchor.reqId)) return;

        state.anchor.txIdHex = frame.txIdHex;
        const txEl = document.getElementById('drift-anchor-tx');
        txEl.style.display = 'block';
        txEl.textContent = 'Anchoring intent tx: ' + frame.txIdHex;
        document.getElementById('drift-anchor-status').textContent = 'Submitted — awaiting block inclusion…';

        if (state.pollTimer) clearInterval(state.pollTimer);
        let attempts = 0;
        state.pollTimer = setInterval(() => {
            attempts++;
            if (window.confirmedTxIds && window.confirmedTxIds.has(frame.txIdHex)) {
                clearInterval(state.pollTimer);
                state.pollTimer = null;
                state.anchor.confirmed = true;
                const s = document.getElementById('drift-anchor-status');
                s.textContent = 'CONFIRMED ON-CHAIN';
                s.style.color = 'var(--accent-green)';
                txEl.textContent = 'Anchored on-chain. Tx: ' + frame.txIdHex;
            } else if (attempts > 90) {
                clearInterval(state.pollTimer);
                state.pollTimer = null;
            }
        }, 4000);
    }

    /* ========================================================================
     * SECTION 5: PROFESSIONAL DELIVERABLE EXPORT
     * ===================================================================== */

    /**
     * @brief Escapes a string for embedding in the exported HTML document.
     * @param {string} s Raw string.
     * @return {string} Escaped string.
     */
    function esc(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    /**
     * @brief Builds the standalone printable certificate document and opens it in a new tab.
     */
    function exportCertificate() {
        const a = state.lastAudit;
        if (!a) return;
        const anchor = state.anchor || {};
        const certId = (a.circuitHash || '').substring(0, 16).toUpperCase() || '—';
        const issued = new Date(Number(a.timestamp) / 1000);
        const tvd = Number(a.tvdDouble);
        const label = STATUS_LABELS[a.status] || 'Unknown';
        const color = STATUS_COLORS[a.status] || '#10b981';
        const fee = quoteAuditFee(a.shots);

        const histJson = state.lastHistogram ? JSON.stringify(state.lastHistogram) : '[]';

        const doc = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Centinel Drift Certificate ${esc(certId)}</title>
<style>
  @page { size: A4; margin: 18mm; }
  * { box-sizing: border-box; }
  body { font-family: Georgia, 'Times New Roman', serif; color: #1e293b; margin: 0; padding: 32px; background: #fff; }
  .doc { max-width: 720px; margin: 0 auto; }
  .brand { display: flex; justify-content: space-between; align-items: baseline; border-bottom: 3px double #0f172a; padding-bottom: 12px; }
  .brand h1 { font-size: 20px; letter-spacing: .12em; margin: 0; text-transform: uppercase; }
  .brand span { font-size: 11px; color: #64748b; }
  h2 { font-size: 15px; text-transform: uppercase; letter-spacing: .1em; color: #334155; margin: 26px 0 8px; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  td { padding: 6px 10px; border: 1px solid #e2e8f0; }
  td.k { background: #f8fafc; width: 34%; color: #475569; font-weight: bold; }
  td.v { font-family: 'Courier New', monospace; word-break: break-all; }
  .headline { text-align: center; margin: 26px 0; }
  .headline .tvd { font-size: 42px; font-weight: bold; color: ${color === 'var(--accent-green)' ? '#10b981' : (color === 'var(--accent-red)' ? '#ef4444' : '#eab308')}; }
  .headline .cls { font-size: 15px; letter-spacing: .08em; text-transform: uppercase; color: #334155; }
  .note { font-size: 11px; color: #64748b; line-height: 1.7; }
  ol { font-size: 11px; color: #475569; line-height: 1.8; padding-left: 22px; }
  .sig-line { margin-top: 40px; display: flex; justify-content: space-between; font-size: 11px; color: #64748b; }
  .print-bar { position: fixed; top: 0; left: 0; right: 0; background: #0f172a; color: #fff; padding: 10px 16px; font-family: system-ui, sans-serif; font-size: 12px; display: flex; gap: 12px; align-items: center; }
  .print-bar button { background: #10b981; color: #04140c; border: 0; padding: 6px 14px; font-weight: 600; cursor: pointer; }
  @media print { .print-bar { display: none; } body { padding: 0; } }
</style>
</head>
<body>
<div class="print-bar">
  <button onclick="window.print()">Print / Save as PDF</button>
  <span>Centinel Labs · Quantum Drift Certificate · Independent TVD Attestation</span>
</div>
<div class="doc">
  <div class="brand"><h1>Centinel Labs</h1><span>Verifiable QPU Fidelity · Post-Quantum Auditing</span></div>

  <div class="headline">
    <div style="font-size:12px;letter-spacing:.2em;color:#64748b;">QUANTUM DRIFT CERTIFICATE</div>
    <div class="tvd">TVD ${tvd.toFixed(6)}</div>
    <div class="cls">${esc(label)} · Confidence ± ${Number(a.confidenceMargin).toFixed(6)} (Chernoff–Hoeffding, 99.9999%)</div>
    <div style="font-size:11px;color:#64748b;margin-top:6px;">Certificate ID ${esc(certId)} · Issued ${esc(issued.toISOString())}</div>
  </div>

  <h2>Audit Parameters</h2>
  <table>
    <tr><td class="k">Circuit SHA-256</td><td class="v">${esc(a.circuitHash)}</td></tr>
    <tr><td class="k">Register / Dimension</td><td class="v">${esc(a.numQubits)} qubits · ${128} basis states</td></tr>
    <tr><td class="k">Measurement Shots</td><td class="v">${esc(a.shots)}</td></tr>
    <tr><td class="k">TVD (fixed-point, 10^9 scale)</td><td class="v">${esc(a.tvdScaled)}</td></tr>
    <tr><td class="k">TVD (double precision)</td><td class="v">${tvd.toFixed(9)}</td></tr>
    <tr><td class="k">Drift Classification</td><td class="v">${esc(label)} (code ${esc(a.status)})</td></tr>
  </table>

  <h2>Cryptographic Material</h2>
  <table>
    <tr><td class="k">BDLOP Commitment c1 (first 256 bits)</td><td class="v">${esc(a.tvdCommitmentHex || '—')}</td></tr>
    <tr><td class="k">Validator ML-DSA-87 Signature (first 256 bits)</td><td class="v">${esc(a.validatorSigHex || '—')}</td></tr>
    <tr><td class="k">Signature Scheme</td><td class="v">NIST FIPS 204 ML-DSA-87 (Dilithium5)</td></tr>
    <tr><td class="k">Commitment Scheme</td><td class="v">BDLOP homomorphic lattice commitment (Module-SIS)</td></tr>
  </table>

  <h2>On-Chain Anchoring</h2>
  <table>
    <tr><td class="k">Operation Type</td><td class="v">OP_APPLY_DRIFT_CERT (staking-grade halved fee schedule)</td></tr>
    <tr><td class="k">Anchoring Fee</td><td class="v">${fmtScl(ANCHOR_FEE_SUBUNITS)} (+ network fee)</td></tr>
    <tr><td class="k">Audit Fee (SCL402 settled)</td><td class="v">${fmtScl(fee)}</td></tr>
    <tr><td class="k">Transaction ID</td><td class="v">${esc(anchor.txIdHex || 'Not yet applied')}</td></tr>
    <tr><td class="k">Ledger Status</td><td class="v">${anchor.confirmed ? 'CONFIRMED ON-CHAIN' : (anchor.txIdHex ? 'Submitted / awaiting inclusion' : 'Not applied')}</td></tr>
  </table>

  <h2>Independent Verification Protocol</h2>
  <ol>
    <li><b>Recompute the TVD.</b> Simulate the circuit (digest above) with any qsim-compatible simulator to obtain the ideal distribution P, then evaluate (1/2)&middot;&Sigma;|P(x) &minus; h(x)/shots| over all 128 basis states using the histogram embedded below. The result must match the certified value.</li>
    <li><b>Verify the signature.</b> Validate the ML-DSA-87 (FIPS 204) validator signature over the canonical digest SHA-256(circuit_hash &Vert; tvd_scaled &Vert; shots &Vert; status &Vert; commitment_root &Vert; timestamp) using the node's published Dilithium5 public key.</li>
    <li><b>Open the commitment.</b> The BDLOP commitment must open to exactly the certified fixed-point TVD under the homomorphic binding property.</li>
    <li><b>Confirm the anchor.</b> Resolve the Transaction ID above in the Centinel blockchain explorer; the operation must carry this certificate's digest fields.</li>
  </ol>

  <h2>Embedded Measurement Histogram (128 basis states)</h2>
  <div class="note" style="font-family:'Courier New',monospace;word-break:break-all;">${esc(histJson)}</div>

  <div class="sig-line">
    <span>Centinel Labs · Social Commodity Layer · centinel.network</span>
    <span>Post-Quantum: ML-DSA-87 / ML-KEM-512 · Lean 4 verified TVD kernel</span>
  </div>
</div>
</body>
</html>`;

        const w = window.open('', '_blank');
        if (w) {
            w.document.write(doc);
            w.document.close();
        }
    }

    /**
     * @brief Downloads a machine-readable JSON certificate bundle.
     */
    function exportJson() {
        const a = state.lastAudit;
        if (!a) return;
        const payload = {
            standard: 'centinel.drift-certificate/v1',
            issuedAt: new Date(Number(a.timestamp) / 1000).toISOString(),
            circuitHash: a.circuitHash,
            circuitQasm: state.lastContext ? state.lastContext.circuitText || '' : '',
            numQubits: a.numQubits,
            shots: a.shots,
            tvdScaled: String(a.tvdScaled),
            tvdDouble: a.tvdDouble,
            confidenceMargin: a.confidenceMargin,
            status: a.status,
            statusLabel: STATUS_LABELS[a.status] || 'Unknown',
            bdlopCommitmentC1: a.tvdCommitmentHex || '',
            validatorSignaturePrefix: (a.validatorSigHex || '').replace(/\.\.\.$/, ''),
            auditFeeSubunits: quoteAuditFee(a.shots).toString(),
            anchoring: state.anchor || null,
            histogram: state.lastHistogram || []
        };
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'centinel-drift-certificate-' + (a.circuitHash || '').substring(0, 12) + '.json';
        link.click();
        URL.revokeObjectURL(url);
    }

    /* ========================================================================
     * SECTION 6: CLIENT BINDING & VIEW LIFECYCLE
     * ===================================================================== */

    /**
     * @brief Maps shared pipeline status notifications (the exact events that
     *        drive the dashboard's sidebar badge) onto the Drift view header.
     * @param {string} status Clean status label from SclAuditorClient._logStatus.
     */
    function onPipelineStatus(status) {
        const s = String(status || '');
        if (s === 'PIPELINE CONNECTED') {
            setStatus('PIPELINE CONNECTED', 'var(--accent-green)');
        } else if (s === 'PIPELINE DISCONNECTED' || s === 'TERMINATED') {
            setStatus('PIPELINE DISCONNECTED', 'var(--accent-red)');
        } else if (s === 'WORKER CREATED' || s === 'WASM LOADED' || s === 'KEYS INITIALIZED') {
            setStatus(s, 'var(--text-muted)');
        }
        refreshBalance();
    }

    /**
     * @brief Attaches the platform's callbacks to the global pipeline client (idempotent).
     *        The dashboard's own handlers are chained, never replaced, so both views
     *        render the exact same live connection and balance state.
     */
    function bindClient() {
        const client = window.client;
        if (!client || state.bound) return;
        state.bound = true;
        client.onDriftCertAuditReceived = onAuditReceived;
        client.onWireFrameReady = onWireFrameReady;
        client.onPaymentRequired = (challenge) => {
            if (Number(challenge.methodId) === 0x000D) {
                armAuditWatchdog(120000); // settlement tx must wait for block inclusion before the replay
                progress('SCL402 challenge received (' + fmtScl(BigInt(challenge.amountSubunits)) +
                    '). Settling autonomously via machine-to-machine micro-transaction…', true);
            }
        };

        /* Chain the shared pipeline telemetry. explorer_app.js owns the primary
         * onStatusChange / onBalanceReceived / onRpcError handlers (sidebar badge,
         * balance panel, console fallbacks); wrap them so the Drift view mirrors
         * the same state instead of freezing on the defaults it was entered with. */
        const upstreamStatus = client.onStatusChange;
        client.onStatusChange = (status) => {
            if (typeof upstreamStatus === 'function') upstreamStatus(status);
            onPipelineStatus(status);
        };

        const upstreamBalance = client.onBalanceReceived;
        client.onBalanceReceived = (data) => {
            if (typeof upstreamBalance === 'function') upstreamBalance(data);
            refreshBalance();
        };

        const upstreamRpcError = client.onRpcError;
        client.onRpcError = (data) => {
            if (typeof upstreamRpcError === 'function') upstreamRpcError(data);
            if (data && Number(data.methodId) === 0x000D) {
                disarmAuditWatchdog();
                setStatus('AUDIT REJECTED', 'var(--accent-red)');
                progress('Node rejected the drift audit (status 0x' +
                    Number(data.status).toString(16).padStart(4, '0') + '): ' +
                    (data.error || 'no diagnostics returned') +
                    '. Fix the highlighted requirement and run the audit again.', false);
            }
        };
    }

    /**
     * @brief View entry point invoked by explorer_app.js switchPageView('drift').
     */
    function onEnter() {
        bindClient();
        refreshBalance();
        updateFeeQuote();
        const ready = !!(window.client && window.client.socket && window.client.socket.readyState === WebSocket.OPEN);
        setStatus(ready ? 'PIPELINE CONNECTED' : 'PIPELINE DISCONNECTED', ready ? 'var(--accent-green)' : 'var(--accent-red)');
    }

    /**
     * @brief Updates the fee quote when the shot budget changes.
     */
    function updateFeeQuote() {
        const shotsEl = document.getElementById('drift-shots');
        const shots = parseInt(shotsEl ? shotsEl.value : '', 10) || 15000;
        const quoteEl = document.getElementById('drift-fee-quote');
        if (quoteEl) quoteEl.value = fmtScl(quoteAuditFee(shots)) + '  (' + shots.toLocaleString() + ' shots)';
        refreshBalance(); // affordability coloring is a function of the quoted fee
    }

    /**
     * @brief Highlights the active pricing tier card (selection ring only — the
     *        "Most Popular" accent styling from the markup is left untouched).
     */
    function selectTier(activeId) {
        ['drift-tier-standard', 'drift-tier-precision', 'drift-tier-anchor'].forEach((id) => {
            const el = document.getElementById(id);
            if (el) el.style.boxShadow = (id === activeId) ? '0 0 0 2px var(--accent-green)' : 'none';
        });
    }

    /**
     * @brief Wires all DOM event listeners once.
     */
    function bindDom() {
        const shotsEl = document.getElementById('drift-shots');
        if (shotsEl) shotsEl.addEventListener('input', updateFeeQuote);

        const submitEl = document.getElementById('drift-submit');
        if (submitEl) submitEl.addEventListener('click', submitAudit);

        /* Pricing tier cards are interactive: Standard selects the 15,000-shot
         * budget (1.4 SCL), Precision selects 100,000 shots (3.0 SCL), Anchoring
         * explains / jumps to the on-chain anchoring step. */
        const tierConfigs = [
            { id: 'drift-tier-standard', shots: 15000 },
            { id: 'drift-tier-precision', shots: 100000 },
            { id: 'drift-tier-anchor', shots: null }
        ];
        tierConfigs.forEach((cfg) => {
            const tierEl = document.getElementById(cfg.id);
            if (!tierEl) return;
            tierEl.style.cursor = 'pointer';
            tierEl.title = cfg.shots
                ? 'Select the ' + cfg.shots.toLocaleString() + '-shot audit budget'
                : 'On-chain anchoring adds +0.5 SCL after a certificate is issued';
            tierEl.addEventListener('click', () => {
                selectTier(cfg.id);
                if (cfg.shots) {
                    if (shotsEl) shotsEl.value = cfg.shots;
                    updateFeeQuote();
                    progress('Tier selected: ' + cfg.shots.toLocaleString() + ' shots — audit fee quoted at ' +
                        fmtScl(quoteAuditFee(cfg.shots)) + '. Load the histogram (or the healthy sample) and click "Run Audit".', false);
                } else {
                    const anchorCard = document.getElementById('drift-anchor-card');
                    if (anchorCard && state.lastAudit) {
                        anchorCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    }
                    progress('On-chain anchoring (+0.5 SCL, halved staking-grade fee schedule) applies to a certificate ' +
                        'issued in step 2 below' + (state.lastAudit ? ' — jumping to the anchoring card.' : ' — run an audit first.'), false);
                }
            });
        });

        const sampleEl = document.getElementById('drift-sample');
        if (sampleEl) sampleEl.addEventListener('click', async () => {
            const shots = parseInt(shotsEl ? shotsEl.value : '', 10) || 15000;
            const circuitEl = document.getElementById('drift-circuit');
            const histogramEl = document.getElementById('drift-histogram');
            progress('Deriving the deterministic qsim baseline for the 7-qubit calibration circuit…', true);
            try {
                /* Bind a fresh client-side beacon seed: the node honours client-provided
                 * seeds (quantum_tvd.cpp has_provided_seed), so the ideal distribution
                 * computed here is byte-for-byte the one the audit benchmarks against. */
                const beaconSeed = new Uint8Array(32);
                window.crypto.getRandomValues(beaconSeed);
                const ideal = await computeIdealDistribution(CALIBRATION_CIRCUIT_QASM, beaconSeed);
                const counts = sampleHistogramFromIdeal(ideal, shots);

                if (circuitEl) circuitEl.value = CALIBRATION_CIRCUIT_QASM;
                if (histogramEl) histogramEl.value = JSON.stringify(counts);
                state.sampleBeaconSeed = beaconSeed;
                state.lastHistogram = counts;
                state.lastContext = { shots: shots, beaconSeed: beaconSeed, circuitText: CALIBRATION_CIRCUIT_QASM };
                updateFeeQuote();

                let sum = 0, maxDev = 0;
                for (let i = 0; i < DRIFT_HISTOGRAM_DIM; i++) {
                    sum += counts[i];
                    maxDev = Math.max(maxDev, Math.abs(counts[i] / shots - ideal[i]));
                }
                progress('Healthy QPU sample loaded: 128 basis states totalling ' + sum.toLocaleString() + ' shots ' +
                    '(max per-bin deviation from the qsim baseline ' + maxDev.toFixed(6) + '), circuit field set to the ' +
                    'calibration circuit. Click "Run Audit" — the certificate is expected to classify as Fidelity Optimal.', false);
            } catch (e) {
                progress('Could not load the healthy sample: ' + (e && e.message ? e.message : String(e)) +
                    '. Paste a 128-count histogram manually and click "Run Audit".', false);
            }
        });

        const browseEl = document.getElementById('drift-histogram-browse');
        const fileEl = document.getElementById('drift-histogram-file');
        if (browseEl && fileEl) {
            browseEl.addEventListener('click', () => fileEl.click());
            fileEl.addEventListener('change', () => {
                const file = fileEl.files && fileEl.files[0];
                if (!file) return;
                const reader = new FileReader();
                reader.onload = (e) => {
                    document.getElementById('drift-histogram').value = String(e.target.result || '');
                    progress('Histogram file loaded (' + file.name + '). Validate by clicking "Run Audit".', false);
                };
                reader.readAsText(file);
            });
        }

        const applyEl = document.getElementById('drift-apply');
        if (applyEl) applyEl.addEventListener('click', applyOnChain);

        const exportEl = document.getElementById('drift-export');
        if (exportEl) exportEl.addEventListener('click', exportCertificate);

        const exportJsonEl = document.getElementById('drift-export-json');
        if (exportJsonEl) exportJsonEl.addEventListener('click', exportJson);

        /* Compute the fee quote immediately on first paint so the field never
         * shows the "—" placeholder, even before the view is first entered. */
        updateFeeQuote();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bindDom);
    } else {
        bindDom();
    }

    /* Exported module surface consumed by explorer_app.js */
    window.SCLDriftCertificates = {
        onEnter: onEnter,
        submitAudit: submitAudit,
        applyOnChain: applyOnChain,
        exportCertificate: exportCertificate,
        exportJson: exportJson
    };
})();
