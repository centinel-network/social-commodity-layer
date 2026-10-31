/-
  ==============================================================================
  Satocialist Protocol: Abstract Lean Model of Total Variation Distance (TVD)
  ==============================================================================

  File: tvd_invariants.lean
  Module: Satocialist.Quantum.TVD
  Compiler: Lean 4 (v4.3.0 or compatible standard distribution)
  Execution: lean tvd_invariants.lean
  Verification Output: [0 Errors / 0 Warnings]

  Architectural Scope:
  This module machine-checks metric-style properties and arithmetic bounds for an
  abstract fixed-point Nat/Int model of the Total Variation Distance kernel. It
  does not verify the C++ implementation in common/crypto/quantum_tvd.cpp, quantum
  state preparation, sampling, or floating-point behavior.

  Formally Verified Invariants (for the abstract model):
  1. Non-Negativity (Theorem 1): computeTvdScaled p q >= 0 for all Nat lists p q.
  2. Identity of Indiscernibles (Theorem 2): computeTvdScaled p p = 0.
  3. Metric Symmetry (Theorem 3): computeTvdScaled p q = computeTvdScaled q p.
  4. Upper Bound (Theorem 4): For DiscreteProbDist values whose probs sum to
     FixedScale, computeTvdScaled p.probs q.probs <= FixedScale. The proof does not
     depend on the dimension being exactly HilbertDim.
  5. Arithmetic Safety (Theorem 5): For dim <= 65536, dim * (2 * FixedScale) < 2^64,
     hence also < 2^128. This bounds the stated intermediate magnitude; it is not a
     proof of the full C++ accumulation loop.
  ==============================================================================
-/

namespace Satocialist.Quantum.TVD

set_option maxRecDepth 2000000
set_option maxHeartbeats 20000000

-- =============================================================================
-- SECTION 1: DISCRETE PROBABILITY DISTRIBUTIONS OVER FINITE DIMENSIONS
-- =============================================================================

/-- Fixed dimension representing a 7-qubit quantum state space (2^7 = 128 states) -/
def HilbertDim : Nat := 128

/-- Precision scale for fixed-point integer arithmetic representation (1.0 = 10^9) -/
def FixedScale : Nat := 1000000000

/-- Integer approximation of absolute value -/
def intAbs (x : Int) : Int :=
  if x < 0 then -x else x

/-- Discrete finite probability distribution vector in fixed-point integer scale -/
structure DiscreteProbDist (dim : Nat) where
  probs : List Nat
  length_eq : probs.length = dim
  sum_eq : probs.foldl (· + ·) 0 = FixedScale

/-- Pure integer computation of scaled L1/2 distance for zipped Nat lists. `zip`
truncates to the shorter input, so callers requiring full support equality must pass
equal-length lists. -/
def computeTvdScaled (p q : List Nat) : Nat :=
  let absDiffs := (p.zip q).map (fun (a, b) => (intAbs (a - b)).toNat)
  (absDiffs.foldl (· + ·) 0) / 2

-- =============================================================================
-- 2. Formal Mathematical Theorems
-- =============================================================================

/--
Lemma: Absolute difference symmetry over integers.
-/
theorem intAbs_sub_comm (a b : Int) : intAbs (a - b) = intAbs (b - a) := by
  unfold intAbs
  split <;> split <;> omega

/--
Lemma: Absolute difference non-negativity.
-/
theorem intAbs_nonneg (a b : Int) : intAbs (a - b) >= 0 := by
  unfold intAbs
  split <;> omega

/--
Theorem 1: Non-Negativity of Computed TVD.
For any two distributions, the calculated TVD is strictly greater than or equal to 0.
-/
theorem tvd_nonneg (p q : List Nat) : computeTvdScaled p q >= 0 := by
  unfold computeTvdScaled
  exact Nat.zero_le _

/--
Theorem 2: Identity of Indiscernibles.
If two probability distribution vectors are identical, their TVD is strictly zero.
-/
theorem tvd_identity (p : List Nat) : computeTvdScaled p p = 0 := by
  have h_zeros : (p.zip p).map (fun (a, b) => (intAbs (a - b)).toNat) = List.replicate p.length 0 := by
    induction p with
    | nil => rfl
    | cons x xs ih =>
      have h_xx : (intAbs (x - x)).toNat = 0 := by
        unfold intAbs
        split <;> omega
      dsimp [List.zip, List.zipWith, List.map, List.replicate] at *
      rw [h_xx, ih]
  have h_fold : ∀ acc, (List.replicate p.length 0).foldl (· + ·) acc = acc := by
    induction p.length with
    | zero => intro acc; rfl
    | succ n ih =>
      intro acc
      dsimp [List.replicate, List.foldl]
      exact ih acc
  change (((p.zip p).map (fun (a, b) => (intAbs (a - b)).toNat)).foldl (· + ·) 0) / 2 = 0
  rw [h_zeros]
  have h_fold_0 := h_fold 0
  omega

/--
Theorem 3: Symmetry of TVD Metric.
TVD(P, Q) is mathematically identical to TVD(Q, P).
-/
theorem tvd_symmetry (p q : List Nat) : computeTvdScaled p q = computeTvdScaled q p := by
  have h_zip : ((p.zip q).map (fun (a, b) => (intAbs (a - b)).toNat)) =
               ((q.zip p).map (fun (a, b) => (intAbs (a - b)).toNat)) := by
    induction p generalizing q with
    | nil =>
      cases q <;> rfl
    | cons x xs ih =>
      cases q with
      | nil => rfl
      | cons y ys =>
        have h_sym : (intAbs ((x : Int) - (y : Int))).toNat = (intAbs ((y : Int) - (x : Int))).toNat := by
          rw [intAbs_sub_comm]
        have h_ih := ih ys
        dsimp [List.zip, List.zipWith, List.map] at *
        rw [h_sym, h_ih]
  change (((p.zip q).map (fun (a, b) => (intAbs (a - b)).toNat)).foldl (· + ·) 0) / 2 =
         (((q.zip p).map (fun (a, b) => (intAbs (a - b)).toNat)).foldl (· + ·) 0) / 2
  rw [h_zip]

/--
Theorem 4: TVD Upper Boundary for Normalized Distributions.
For `DiscreteProbDist` values whose probability vectors have equal length and each sum
to `FixedScale`, `computeTvdScaled` is at most `FixedScale`. The proof does not use the
`dim = HilbertDim` hypothesis.
-/
theorem tvd_upper_bound_scaled (p q : DiscreteProbDist dim)
    (_h_dim : dim = HilbertDim) :
    computeTvdScaled p.probs q.probs <= FixedScale := by
  have fold_add : ∀ (l : List Nat) (acc : Nat), l.foldl (· + ·) acc = acc + l.foldl (· + ·) 0 := by
    intro l
    induction l with
    | nil => intro acc; rfl
    | cons x xs ih =>
      intro acc
      dsimp [List.foldl]
      rw [ih (acc + x), ih (0 + x)]
      omega
  have h_sum_diff : ∀ (l1 l2 : List Nat),
    l1.length = l2.length →
    ((l1.zip l2).map (fun (a, b) => (intAbs (a - b)).toNat)).foldl (· + ·) 0 <=
    l1.foldl (· + ·) 0 + l2.foldl (· + ·) 0 := by
    intro l1 l2
    revert l2
    induction l1 with
    | nil =>
      intro l2 h_len
      cases l2 with
      | nil =>
        dsimp [List.zip, List.zipWith, List.map, List.foldl]
        omega
      | cons y ys => contradiction
    | cons x xs ih =>
      intro l2 h_len
      cases l2 with
      | nil => contradiction
      | cons y ys =>
        have h_bound_elem : (intAbs (x - y)).toNat <= x + y := by
          unfold intAbs
          split <;> omega
        dsimp [List.length] at h_len
        have h_ih := ih ys (by omega)
        dsimp [List.zip, List.zipWith, List.map, List.foldl] at *
        rw [fold_add _ (0 + (intAbs (x - y)).toNat)]
        rw [fold_add xs (0 + x)]
        rw [fold_add ys (0 + y)]
        omega
  have h_res := h_sum_diff p.probs q.probs (by rw [p.length_eq, q.length_eq])
  rw [p.sum_eq, q.sum_eq] at h_res
  change (((p.probs.zip q.probs).map (fun (a, b) => (intAbs (a - b)).toNat)).foldl (· + ·) 0) / 2 <= FixedScale
  omega

/--
Theorem 5: Intermediate Magnitude Bound for Bounded Dimension.
For any dimension `dim <= 65536`, the magnitude `dim * (2 * FixedScale)` is strictly
less than 2^64, and therefore also less than 2^128. This bounds the stated
intermediate accumulation magnitude; it does not by itself prove a particular C++
loop implementation.
-/
theorem tvd_accumulation_fits_u64 (dim : Nat) (h_dim : dim <= 65536) :
    dim * (2 * FixedScale) < 18446744073709551616 := by
  have h1 : dim * (2 * FixedScale) <= 65536 * (2 * 1000000000) := by
    apply Nat.mul_le_mul h_dim (Nat.le_refl _)
  have h2 : 65536 * (2 * 1000000000) = 131072000000000 := by rfl
  have h3 : 131072000000000 < 18446744073709551616 := by native_decide
  exact Nat.lt_of_le_of_lt (by omega) h3

end Satocialist.Quantum.TVD
