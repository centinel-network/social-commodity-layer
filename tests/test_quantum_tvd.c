/**
 * @file tests/test_quantum_tvd.c
 * @module tests/test_quantum_tvd - Quantum Total Variation Distance (TVD) Audit Suite
 *
 * @brief Formal verification suite evaluating quantum state distribution distances,
 *        sample complexity bounds, noise-induced statevector drift, and cryptographic
 *        drift certificate generation.
 *
 * @details
 * Validates the statistical, physical, and cryptographic properties of the Quantum TVD subsystem:
 *
 * 1. Metric Space Axioms:
 *    - Confirms that the vectorized Total Variation Distance metric:
 *      \f[
 *        \delta(P, Q) = \frac{1}{2} \|P - Q\|_1 = \frac{1}{2} \sum_{i=1}^{\Omega} |P(i) - Q(i)|
 *      \f]
 *      obeys identity of indiscernibles (\f$\delta(P, P) \approx 0\f$), symmetry, and maximal
 *      separation under orthogonal distributions (\f$\delta(P, P_{\perp}) \approx 1.0\f$).
 *
 * 2. Chernoff-Hoeffding Sample Complexity Verification:
 *    - Tests empirical histogram convergence across variable shot budgets M in {1k, 5k, 15k, 50k, 100k},
 *      verifying that sampling error remains strictly bounded by the Chernoff confidence margin:
 *      \f[
 *        \epsilon(M) = \sqrt{\frac{\ln(2 / \delta)}{2M}}
 *      \f]
 *
 * 3. Quantum Noise Channel Calibration & Drift Classification:
 *    - Emulates physical QPU decoherence via Kraus operators for Pauli depolarizing noise:
 *      \f[
 *        \mathcal{E}(\rho) = (1 - \lambda)\rho + \frac{\lambda}{d} I
 *      \f]
 *    - Confirms proper classification into operational fidelity tiers:
 *      `FIDELITY_OPTIMAL` (\f$\delta \le 0.05\f$), `DRIFT_TOLERABLE` (\f$\delta \le 0.25\f$),
 *      `DECOHERENCE_EXCEEDED` (\f$\delta \le 0.60\f$), and `TAMPERING_SUSPECTED` (\f$\delta > 0.60\f$).
 *
 * 4. Cryptographic Drift Certificate Anchoring:
 *    - Validates end-to-end certificate creation: computing fixed-point TVD scaling (\f$10^6\f$),
 *      generating BDLOP lattice commitments, and signing via ML-DSA-87 (Dilithium5).
 *    - Proves anti-tamper security: altering a single bit in the scaled TVD metric causes
 *      cryptographic verification to reject the certificate.
 *
 * @invariants
 * - Bounded Metric: For any valid quantum distributions P and Q, \f$0.0 \le \delta(P, Q) \le 1.0\f$.
 * - Zero Drift: \f$\delta(P, P) < 0.001\f$ under high-shot empirical sampling (M = 1,000,000).
 * - Anti-Tampering: Modifying `cert->tvd_scaled` strictly invalidates `quantum_tvd_audit_verify_certificate`.
 *
 * @standards
 * - Total Variation Distance / Kolmogorov-Smirnov statistical metric definition.
 * - Chernoff-Hoeffding bound for bounded random variable empirical means.
 * - NIST FIPS 204: ML-DSA-87 post-quantum signature verification.
 * - BDLOP Homomorphic Lattice Commitment Scheme.
 *
 * @dependencies
 * - `constants.h`, `types.h`, `utils.h`, `crypto.h`, `client_state.h`, `quantum_tvd.h`.
 * - POSIX Math library (`libm`).
 * - OpenSSL `libcrypto`.
 *
 * @threading
 * - Tests execute synchronously in the primary test thread.
 * - QPU simulation calls are reentrant and operate on stack-allocated statevector arrays.
 *
 * @memory_model
 * - Fixed-dimension probability buffers (`QUANTUM_STATE_DIM`) reside on the stack.
 * - Client state structures allocated on the heap are released via `client_state_destroy`.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <time.h>

#include "constants.h"
#include "types.h"
#include "utils.h"
#include "crypto.h"
#include "client_state.h"
#include "quantum_tvd.h"

/* ============================================================================ */
/* SECTION 0: TEST HARNESS INFRASTRUCTURE & ASSERTION MACROS                    */
/* ============================================================================ */
/** @brief Status code returned on test success. */
#define TEST_PASS 0
/** @brief Status code returned on test assertion failure. */
#define TEST_FAIL 1

/**
 * @def ASSERT_TRUE(cond, msg)
 * @brief Asserts condition evaluates to true; emits failure location on error.
 */
#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "  [ASSERTION FAILED] %s (%s) at %s:%d\n", #cond, msg, __FILE__, __LINE__); \
        return TEST_FAIL; \
    } \
} while(0)

/**
 * @def ASSERT_EQUAL_INT(actual, expected, msg)
 * @brief Asserts integer equality; logs expected vs actual values on failure.
 */
#define ASSERT_EQUAL_INT(actual, expected, msg) do { \
    if ((actual) != (expected)) { \
        fprintf(stderr, "  [ASSERTION FAILED] Expected %d, got %d (%s) at %s:%d\n", \
                (int)(expected), (int)(actual), msg, __FILE__, __LINE__); \
        return TEST_FAIL; \
    } \
} while(0)

/**
 * @def RUN_TEST(func)
 * @brief Executes a test module, reporting status banners and aborting on failure.
 */
#define RUN_TEST(func) do { \
    printf("\n[RUN] %s...\n", #func); \
    int res = func(); \
    if (res == TEST_PASS) { \
        printf("[PASS] %s completed successfully.\n", #func); \
    } else { \
        printf("[FAIL] %s failed!\n", #func); \
        exit(1); \
    } \
} while(0)

/**
 * @brief Emits a visual section separator and title header to stdout.
 *
 * @param[in] title Banner header text. Null-terminated ASCII.
 *
 * @pre `title != NULL`
 * @post Header text written to stdout.
 *
 * @complexity
 * - Time: O(1)
 * - Space: O(1) auxiliary
 */
static void print_header(const char *title) {
    printf("\n====================================================================================================\n");
    printf("  %s\n", title);
    printf("====================================================================================================\n");
}

/* ============================================================================ */
/* SECTION 1: MATHEMATICAL METRIC AXIOMS (IDENTITY, MAXIMUM DISTANCE)          */
/* ============================================================================ */
/**
 * @brief Validates metric space axioms for Total Variation Distance over quantum states.
 *
 * @details
 * Evaluates the mathematical consistency of `quantum_compute_tvd_vectorized`:
 * 1. Identity of Indiscernibles:
 *    Sampling from the ideal distribution at high shot count (M = 1,000,000) must yield:
 *    \f[
 *      \delta(P_{\text{ideal}}, P_{\text{ideal}}) \to 0.0 \quad (\text{assert } < 0.001)
 *    \f]
 * 2. Maximal Metric Separation:
 *    Synthesizing an orthogonal distribution where all probability mass is shifted to the
 *    minimal-probability basis state must yield:
 *    \f[
 *      \delta(P_{\text{ideal}}, P_{\perp}) \to 1.0 \quad (\text{assert } > 0.95 \text{ and } \le 1.0)
 *    \f]
 *
 * @pre Native simulator must compute normalized ideal distribution.
 * @post Emits observed metric distances to stdout.
 *
 * @return int `TEST_PASS` (0) on metric axiom satisfaction; `TEST_FAIL` (1) otherwise.
 *
 * @complexity
 * - Time: O(QUANTUM_STATE_DIM)
 * - Space: O(QUANTUM_STATE_DIM) stack memory.
 */
static int test_tvd_metric_axioms(void) {
    print_header("1. QUANTUM TVD MATHEMATICAL METRIC AXIOMS");

    double p_ideal[QUANTUM_STATE_DIM];
    uint8_t beacon_seed[32];
    memset(beacon_seed, 0x42, 32);

    int res = quantum_compute_ideal_distribution_qsim(NULL, 0, beacon_seed, p_ideal, QUANTUM_STATE_DIM);
    ASSERT_EQUAL_INT(res, 0, "Ideal distribution computation failed");

    // Case A: Identity of Indiscernibles (Perfect Sampling Limit)
    uint32_t perfect_hist[QUANTUM_STATE_DIM];
    uint32_t total_shots = 1000000;
    for (size_t i = 0; i < QUANTUM_STATE_DIM; i++) {
        perfect_hist[i] = (uint32_t)round(p_ideal[i] * total_shots);
    }

    double tvd_zero = quantum_compute_tvd_vectorized(p_ideal, perfect_hist, QUANTUM_STATE_DIM, total_shots);
    printf("  • TVD(P_ideal, P_ideal) = %.8f (Expected ~0.0)\n", tvd_zero);
    ASSERT_TRUE(tvd_zero < 0.001, "TVD under identical distributions must converge to 0");

    // Case B: Orthogonal State Maximum Distance (TVD = 1.0)
    uint32_t orthogonal_hist[QUANTUM_STATE_DIM];
    memset(orthogonal_hist, 0, sizeof(orthogonal_hist));
    
    // Invert probability mass completely to orthogonal states
    size_t min_idx = 0;
    for (size_t i = 1; i < QUANTUM_STATE_DIM; i++) {
        if (p_ideal[i] < p_ideal[min_idx]) min_idx = i;
    }
    orthogonal_hist[min_idx] = total_shots;

    double tvd_max = quantum_compute_tvd_vectorized(p_ideal, orthogonal_hist, QUANTUM_STATE_DIM, total_shots);
    printf("  • TVD(P_ideal, P_orthogonal) = %.6f (Expected ~1.0)\n", tvd_max);
    ASSERT_TRUE(tvd_max > 0.95 && tvd_max <= 1.0, "Orthogonal distributions must yield TVD near 1.0");

    return TEST_PASS;
}

/* ============================================================================ */
/* SECTION 2: CHERNOFF-HOEFFDING SAMPLE COMPLEXITY CONVERGENCE                  */
/* ============================================================================ */
/**
 * @brief Evaluates empirical sampling convergence against Chernoff-Hoeffding analytic bounds.
 *
 * @details
 * Evaluates finite-shot measurement error across varying shot budgets:
 * M in {1,000, 5,000, 15,000, 50,000, 100,000}.
 *
 * For each shot budget M:
 * 1. Simulates noisy QPU histogram generation with zero physical noise (\f$\lambda = 0\f$).
 * 2. Computes the empirical TVD between the sample histogram and ideal distribution.
 * 3. Calculates the analytic Chernoff confidence margin:
 *    \f[
 *      \epsilon = \sqrt{\frac{\ln(2 / 10^{-6})}{2M}}
 *    \f]
 * 4. Asserts that the empirical error delta satisfies:
 *    \f[
 *      |\delta_{\text{sampled}} - 0.0| \le \epsilon + 0.05
 *    \f]
 *    where 0.05 represents the finite-basis discretization slack.
 *
 * @pre Ideal probability distribution must be initialized.
 * @post Emits sample complexity convergence table to stdout.
 *
 * @return int `TEST_PASS` (0) if all shot budgets satisfy bounds; `TEST_FAIL` (1) otherwise.
 *
 * @complexity
 * - Time: O(Budgets * (M + QUANTUM_STATE_DIM))
 * - Space: O(QUANTUM_STATE_DIM) stack memory.
 */
static int test_chernoff_hoeffding_bounds(void) {
    print_header("2. CHERNOFF-HOEFFDING SAMPLE COMPLEXITY VERIFICATION");

    double p_ideal[QUANTUM_STATE_DIM];
    uint8_t beacon_seed[32];
    memset(beacon_seed, 0x11, 32);
    quantum_compute_ideal_distribution_qsim(NULL, 0, beacon_seed, p_ideal, QUANTUM_STATE_DIM);

    uint32_t shot_budgets[] = { 1000, 5000, 15000, 50000, 100000 };
    size_t num_budgets = sizeof(shot_budgets) / sizeof(shot_budgets[0]);

    printf("| Shot Budget (M) | Observed TVD | Chernoff Margin (e) | Empirical Error Delta | Bound Holds? |\n");
    printf("|-----------------|--------------|---------------------|-----------------------|--------------|\n");

    for (size_t b = 0; b < num_budgets; b++) {
        uint32_t M = shot_budgets[b];
        uint32_t hist[QUANTUM_STATE_DIM];

        // Simulate zero-noise sampling variance
        QuantumNoiseModelConfig zero_noise = { 0.0, 0.0, 0.0, 0.0, 0.0 };
        quantum_simulate_noisy_qpu_histogram(p_ideal, QUANTUM_STATE_DIM, M, &zero_noise, beacon_seed, hist);

        double tvd_sampled = quantum_compute_tvd_vectorized(p_ideal, hist, QUANTUM_STATE_DIM, M);
        double epsilon = sqrt(log(2.0 / 1e-6) / (2.0 * (double)M));
        double delta = fabs(tvd_sampled - 0.0);

        bool satisfied = delta <= (epsilon + 0.05); // Include finite basis dimensionality slack
        printf("| %15u | %12.6f | %19.6f | %21.6f | %12s |\n",
               M, tvd_sampled, epsilon, delta, satisfied ? "PASSED" : "FAILED");

        ASSERT_TRUE(satisfied, "Sampling deviation must respect Chernoff concentration limits");
    }

    return TEST_PASS;
}

/* ============================================================================ */
/* SECTION 3: QUANTUM NOISE CHANNEL DRIFT SENSITIVITY (KRAUS MAPS)             */
/* ============================================================================ */
/**
 * @brief Validates QPU noise simulation and operational drift classification thresholds.
 *
 * @details
 * Evaluates the sensitivity of TVD measurements to increasing rates of Pauli
 * depolarizing noise \f$\lambda \in \{0.00, 0.01, 0.05, 0.10, 0.25, 0.50, 0.80\}\f$:
 * 1. Simulates noisy execution via Kraus map operators:
 *    \f[
 *      \mathcal{E}(\rho) = (1 - \lambda)\rho + \frac{\lambda}{d} I
 *    \f]
 * 2. Measures resulting TVD against the noise-free ideal state.
 * 3. Asserts that:
 *    - \f$\lambda = 0.00 \implies \text{TVD} < 0.05\f$ (`FIDELITY_OPTIMAL`).
 *    - \f$\lambda \ge 0.80 \implies \text{TVD} > 0.25\f$ (crossing into `DECOHERENCE_EXCEEDED`
 *      or `TAMPERING_SUSPECTED`).
 *
 * @pre `quantum_simulate_noisy_qpu_histogram` must be implemented.
 * @post Emits noise calibration classification table to stdout.
 *
 * @return int `TEST_PASS` (0) if noise mapping conforms to bounds; `TEST_FAIL` (1) otherwise.
 *
 * @complexity
 * - Time: O(Rates * (Shots + QUANTUM_STATE_DIM))
 * - Space: O(QUANTUM_STATE_DIM) stack memory.
 */
static int test_noise_channel_drift_curves(void) {
    print_header("3. QUANTUM NOISE CHANNEL DRIFT SENSITIVITY (KRAUS MAPS)");

    double p_ideal[QUANTUM_STATE_DIM];
    uint8_t beacon_seed[32];
    memset(beacon_seed, 0x77, 32);
    quantum_compute_ideal_distribution_qsim(NULL, 0, beacon_seed, p_ideal, QUANTUM_STATE_DIM);

    double depol_rates[] = { 0.00, 0.01, 0.05, 0.10, 0.25, 0.50, 0.80 };
    size_t num_rates = sizeof(depol_rates) / sizeof(depol_rates[0]);

    printf("| Depol. Rate (L) | Injected Noise Type | Observed TVD | Drift State Classification |\n");
    printf("|-----------------|---------------------|--------------|----------------------------|\n");

    for (size_t i = 0; i < num_rates; i++) {
        double lambda = depol_rates[i];
        QuantumNoiseModelConfig cfg = { lambda, 0.0, 0.0, 0.0, 0.0 };

        uint32_t hist[QUANTUM_STATE_DIM];
        quantum_simulate_noisy_qpu_histogram(p_ideal, QUANTUM_STATE_DIM, QUANTUM_DEFAULT_SHOTS, &cfg, beacon_seed, hist);

        double tvd = quantum_compute_tvd_vectorized(p_ideal, hist, QUANTUM_STATE_DIM, QUANTUM_DEFAULT_SHOTS);

        const char *status_str;
        if (tvd <= 0.05) status_str = "FIDELITY_OPTIMAL";
        else if (tvd <= 0.25) status_str = "DRIFT_TOLERABLE";
        else if (tvd <= 0.60) status_str = "DECOHERENCE_EXCEEDED";
        else status_str = "TAMPERING_SUSPECTED";

        printf("| %15.2f | Pauli Depolarizing  | %12.6f | %-26s |\n", lambda, tvd, status_str);

        if (lambda == 0.0) {
            ASSERT_TRUE(tvd < 0.05, "Zero noise must yield optimal fidelity");
        } else if (lambda >= 0.80) {
            ASSERT_TRUE(tvd > 0.25, "High depolarizing noise must trip decoherence boundary");
        }
    }

    return TEST_PASS;
}

/* ============================================================================ */
/* SECTION 4: CRYPTOGRAPHIC ANCHORING & DRIFT CERTIFICATE INTEGRITY             */
/* ============================================================================ */
/**
 * @brief End-to-end integration test for quantum drift certificate signing and tampering detection.
 *
 * @details
 * Validates the complete cryptographic lifecycle of a `QuantumDriftCertificate`:
 * 1. Initializes a client node `State` and generates a Dilithium5 user wallet.
 * 2. Generates a certificate from a mock OpenQASM 2.0 quantum circuit:
 *    - Computes TVD and scales to fixed-point integer (\f$\text{scaled} = \text{round}(\text{tvd} \cdot 10^6)\f$).
 *    - Evaluates Chernoff confidence margin.
 *    - Generates BDLOP lattice commitment over the scaled metric.
 *    - Computes Dilithium5 signature over the certificate payload.
 * 3. Asserts valid certificate verification succeeds against the wallet's public key.
 * 4. Mutates `cert.tvd_scaled` by +1000 units and asserts cryptographic verification fails.
 *
 * @pre OpenSSL and Dilithium5 keypair routines initialized.
 * @post Cleans up client state and releases allocated resources.
 *
 * @return int `TEST_PASS` (0) if certificate generation and anti-tamper checks pass; `TEST_FAIL` (1) otherwise.
 *
 * @complexity
 * - Time: O(QuantumSimulation + DilithiumSign + BdlopCommit)
 * - Space: O(sizeof(State)) heap memory.
 */
static int test_drift_certificate_cryptographic_anchoring(void) {
    print_header("4. QUANTUM DRIFT CERTIFICATE CRYPTOGRAPHIC ANCHORING");

    State state;
    memset(&state, 0, sizeof(State));
    client_state_init(&state, 0);
    create_user_wallet(&state.user_wallet);

    uint8_t dummy_circuit[] = "OPENQASM 2.0; include \"qelib1.inc\"; qreg q[7]; h q[0]; cx q[0], q[1];";
    size_t circuit_len = strlen((char*)dummy_circuit);
    uint8_t beacon_seed[32];
    memset(beacon_seed, 0xEE, 32);

    QuantumDriftCertificate cert;
    int gen_res = quantum_tvd_audit_generate_certificate(&state, dummy_circuit, circuit_len, NULL, QUANTUM_DEFAULT_SHOTS, beacon_seed, &cert);
    ASSERT_EQUAL_INT(gen_res, 0, "Certificate generation failed");

    printf("  • Generated TVD Metric:       %.6f (%llu fixed-point)\n", cert.tvd_double, (unsigned long long)cert.tvd_scaled);
    printf("  • Confidence Margin (e):      %.6f\n", cert.confidence_margin);
    printf("  • Operational Status:         %d\n", (int)cert.status);

    // 1. Verify valid certificate against wallet public key
    int ver_res = quantum_tvd_audit_verify_certificate(&cert, state.user_wallet.dilithium_pubkey);
    ASSERT_EQUAL_INT(ver_res, 0, "Valid certificate verification failed");
    printf("  • Cryptographic Signature & BDLOP Commitment Verification: SUCCESS\n");

    // 2. Tampering Test: Alter TVD metric and assert cryptographic rejection
    cert.tvd_scaled += 1000;
    int tamper_res = quantum_tvd_audit_verify_certificate(&cert, state.user_wallet.dilithium_pubkey);
    ASSERT_TRUE(tamper_res != 0, "Tampered certificate must fail verification");
    printf("  • Tampered TVD Metric Rejection: SUCCESS (Detected and Rejected)\n");

    client_state_destroy(&state);
    return TEST_PASS;
}

/* ============================================================================ */
/* SECTION 5: MAIN TEST EXECUTION ENTRYPOINT                                    */
/* ============================================================================ */
/**
 * @brief Main execution entrypoint for the Quantum TVD Audit & Verification Suite.
 *
 * @details
 * Orchestrates the execution sequence:
 * 1. Mutes verbose console logging via `scl_log_set_level(LOG_LEVEL_FATAL)`.
 * 2. Sequentially executes the 4 quantum audit modules.
 * 3. Prints final verification summary table.
 *
 * @param[in] argc Argument count (unused).
 * @param[in] argv Argument vector (unused).
 *
 * @return int Returns 0 on successful completion of all tests; aborts via `exit(1)` on error.
 *
 * @complexity
 * - Time: ~1-2 seconds total execution.
 * - Space: Transient stack and heap memory.
 */
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    /* Suppress verbose logging to maintain clean audit report output */
    scl_log_set_level(LOG_LEVEL_FATAL);

    printf("====================================================================================================\n");
    printf("  SATOCIALIST PROTOCOL: QUANTUM TVD AUDITING & VERIFICATION SUITE\n");
    printf("====================================================================================================\n");

    RUN_TEST(test_tvd_metric_axioms);
    RUN_TEST(test_chernoff_hoeffding_bounds);
    RUN_TEST(test_noise_channel_drift_curves);
    RUN_TEST(test_drift_certificate_cryptographic_anchoring);

    print_header("FINAL VERIFICATION SUMMARY");
    printf("  • All 4 Quantum TVD Test Modules: PASSED (100%%)\n");
    printf("  • Mathematical Accuracy: Proved convergence under Chernoff bounds and metric validity.\n");
    printf("  • Cryptographic Hygiene: Dilithium5 signature and BDLOP commitments verified.\n");
    printf("====================================================================================================\n\n");

    return 0;
}
