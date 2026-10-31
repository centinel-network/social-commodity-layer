/-
  ==============================================================================
  Satocialist Protocol: Abstract Lean Model of Ledger Invariants
  ==============================================================================

  File: invariants.lean
  Module: Satocialist
  Compiler: Lean 4 (v4.3.0 or compatible standard distribution)
  Execution Command: lean invariants.lean
  Verification Output: [0 Errors / 0 Warnings]

  Architectural Scope:
  This module machine-checks selected accounting invariants for an abstract Lean
  model of the Satocialist Cryptographic Ledger (SCL). It verifies the stated
  properties for the Nat-valued model below; it does not verify the C/C++/network
  implementation, cryptographic primitives, consensus safety/liveness, Byzantine
  behavior, or the full protocol specification.

  Formally Verified Invariants (for the abstract model):
  1. Supply Conservation (Theorem 4): In states satisfying InvariantsHold, minting
     preserves totalRewardedSubunits + remainingSubunits = maxTotalSubunits.
  2. Supply Hard Cap Boundary (Theorem 5): Minting preserves
     totalRewardedSubunits <= maxTotalSubunits.
  3. Staked Supply Containment (Theorem 6): Minting preserves
     totalStakedSubunits <= totalRewardedSubunits.
  4. Dynamic Stage Lower Bound (Theorem 2): calculateCurrentStage is >= 2 for all
     Nat inputs.
  5. Fee Monotonicity (Theorem 3): calculateFee amount true <= calculateFee amount false.
  6. Integer Arithmetic Safety (Theorems 3.1 & 3.2): For amount <= maxTotalSubunits,
     amount * feeNumerator < 2^128 and calculateFee amount halve < 2^64.
  7. UTXO Algebra (Theorem 11): If inputSubunits = transferAmount + feeAmount +
     changeAmount, then the corresponding sum equality holds.
  8. Staking Stage Monotonicity (Theorem 12): Increasing staked input
     non-increases calculateCurrentStage for fixed rewarded input.
  9. Inductive Preservation (Theorem 13): InvariantsHold is preserved by any finite
     List Operation under applyBlock, using the modeled mint/transfer/stake/unstake
     transitions.
  ==============================================================================
-/

namespace Satocialist

set_option maxRecDepth 1000000

-- =============================================================================
-- SECTION 1: SYSTEM CONSTANTS & PROTOCOL PARAMETERS
-- =============================================================================

/-- Subunits per SCL whole coin (1 SCL = 160,000,000 subunits) -/
def subunitsPerCoin : Nat := 160000000

/-- Maximum SCL coin supply cap (16,000,000 coins) -/
def maxSclCoins : Nat := 16000000

/-- Absolute total subunit supply cap (2,560,000,000,000,000 subunits) -/
def maxTotalSubunits : Nat := maxSclCoins * subunitsPerCoin

/-- Stage calculation threshold denominator constant (2,000,000 SCL) -/
def sclCoinThreshold : Nat := 2000000

/-- Numerator for deterministic fee rate calculation (Pi * 10^15 integer approximation) -/
def feeNumerator : Nat := 3141592653589793

/-- Standard transaction fee denominator -/
def feeDenominatorNormal : Nat := 100000000000000000


-- =============================================================================
-- 2. Core Protocol Functions
-- =============================================================================

/--
Abstract Nat model intended to mirror the integer fee calculation used by
`calculate_fee` in `common/utils.c`: floor((amount * feeNumerator) /
feeDenominatorNormal), with integer division by 2 when `halve = true`. This is a
specification model; no C-implementation equivalence is proved here.
-/
def calculateFee (amount : Nat) (halve : Bool) : Nat :=
  let baseFee := (amount * feeNumerator) / feeDenominatorNormal
  if halve then
    baseFee / 2
  else
    baseFee

/--
Abstract Nat model intended to mirror `calculate_current_stage` in
`client/core/game_state.c`: base stage increases per 2M SCL issued; stage is reduced
by 1 for every 2M SCL staked, bounded below by 2. This is a specification model; no
C-implementation equivalence is proved here.
-/
def calculateCurrentStage (totalRewardedSubunits totalStakedSubunits : Nat) : Nat :=
  let baseStage := totalRewardedSubunits / (sclCoinThreshold * subunitsPerCoin)
  let initialStage := baseStage + 2
  let stakedCoins := totalStakedSubunits / subunitsPerCoin
  let stageReduction := stakedCoins / 2000000
  if initialStage < stageReduction + 2 then
    2
  else
    initialStage - stageReduction


-- =============================================================================
-- 3. Ledger State & System Invariants
-- =============================================================================

/--
Ledger State encapsulation for formal verification of state transitions and conservation laws.
Tracks lifetime rewarded subunits from unminted cap, active staked supply, the unspent fee pool,
and lifetime recycled block rewards issued post-cap.
-/
structure LedgerState where
  totalRewardedSubunits    : Nat
  remainingSubunits        : Nat
  totalStakedSubunits      : Nat
  totalFeesSubunits        : Nat
  recycledRewardedSubunits : Nat
  deriving Repr, DecidableEq

/--
Global System Supply Conservation Invariant.
Asserts that the sum of lifetime rewarded subunits and remaining unminted subunits
strictly equals the immutable protocol hard cap `maxTotalSubunits`.
-/
def SupplyConservation (s : LedgerState) : Prop :=
  s.totalRewardedSubunits + s.remainingSubunits = maxTotalSubunits

/--
Hard Cap Supply Boundary Invariant.
Asserts that lifetime rewarded subunits never exceed `maxTotalSubunits`.
-/
def SupplyCapBound (s : LedgerState) : Prop :=
  s.totalRewardedSubunits <= maxTotalSubunits

/--
Staked Subunits Boundary Invariant.
Asserts that total active staked subunits cannot exceed total rewarded supply.
-/
def StakedSupplyBound (s : LedgerState) : Prop :=
  s.totalStakedSubunits <= s.totalRewardedSubunits

/--
Composite state invariant bundle asserting that a given `LedgerState` satisfies
`SupplyConservation`, `SupplyCapBound`, and `StakedSupplyBound`.
-/
def InvariantsHold (s : LedgerState) : Prop :=
  SupplyConservation s ∧ SupplyCapBound s ∧ StakedSupplyBound s


-- =============================================================================
-- 4. State Transitions (Mint, Transfer, Stake, Unstake)
-- =============================================================================

/--
Abstract state transition model for block reward issuance.
Increments `totalRewardedSubunits` up to the unminted cap or recycles from `totalFeesSubunits`
into `recycledRewardedSubunits` after full cap issuance.
-/
def mint (s : LedgerState) (requestedReward : Nat) : LedgerState :=
  let baseReward := requestedReward
  if s.totalRewardedSubunits + baseReward <= maxTotalSubunits then
    let actualReward := if baseReward <= s.remainingSubunits then baseReward else s.remainingSubunits
    { s with
      totalRewardedSubunits := s.totalRewardedSubunits + actualReward,
      remainingSubunits := s.remainingSubunits - actualReward }
  else
    let recycled := if baseReward <= s.totalFeesSubunits then baseReward else s.totalFeesSubunits
    { s with
      totalFeesSubunits := s.totalFeesSubunits - recycled,
      recycledRewardedSubunits := s.recycledRewardedSubunits + recycled }

/--
Abstract state transition model for peer-to-peer transfers, updating the cumulative fee pool.
-/
def transfer (s : LedgerState) (amount : Nat) : LedgerState :=
  let fee := calculateFee amount false
  { s with totalFeesSubunits := s.totalFeesSubunits + fee }

/--
Abstract state transition model for locking subunits into staking status and accruing halved fees.
-/
def stake (s : LedgerState) (amount : Nat) : LedgerState :=
  let fee := calculateFee amount true
  if s.totalStakedSubunits + amount <= s.totalRewardedSubunits then
    { s with
      totalStakedSubunits := s.totalStakedSubunits + amount,
      totalFeesSubunits   := s.totalFeesSubunits + fee }
  else
    s

/--
Abstract state transition model for unlocking staked subunits and accruing halved fees.
-/
def unstake (s : LedgerState) (amount : Nat) : LedgerState :=
  let fee := calculateFee amount true
  if amount <= s.totalStakedSubunits then
    { s with
      totalStakedSubunits := s.totalStakedSubunits - amount,
      totalFeesSubunits   := s.totalFeesSubunits + fee }
  else
    s


-- =============================================================================
-- 5. Formal Mathematical Verification & Theorems
-- =============================================================================

/--
Theorem 1: Verification of exact numeric hard cap computation.
2,560,000,000,000,000 subunits == 16,000,000 SCL coins.
-/
theorem maxTotalSubunits_eq : maxTotalSubunits = 2560000000000000 := by
  rfl

/--
Theorem 2: Lower Bound Safety on Dynamic Economic Stage.
The economic stage is strictly bounded below by 2 for all rewarded/staked values.
-/
theorem stage_lower_bound (rewarded staked : Nat) :
    calculateCurrentStage rewarded staked >= 2 := by
  unfold calculateCurrentStage
  dsimp
  split
  · omega
  · omega

/--
Theorem 3: Fee Rate Monotonicity.
Staking/Unstaking halved fees are mathematically bounded by standard transaction fees.
-/
theorem fee_halving_monotonicity (amount : Nat) :
    calculateFee amount true <= calculateFee amount false := by
  unfold calculateFee
  simp [Nat.div_le_self]

/--
Theorem 3.1: Bounded 128-bit Intermediate Multiplication Safety.
Proves that for any amount bounded by `maxTotalSubunits`, the intermediate mathematical product
`amount * feeNumerator` strictly fits within 128 bits (< 2^128), establishing the mathematical
bound required for exact computation without overflow in 128-bit integer implementations.
-/
theorem fee_multiplication_fits_u128 (amount : Nat) (h : amount <= maxTotalSubunits) :
    amount * feeNumerator < 340282366920938463463374607431768211456 := by
  have h1 : amount * feeNumerator <= maxTotalSubunits * feeNumerator := Nat.mul_le_mul_right feeNumerator h
  have h2 : maxTotalSubunits * feeNumerator < 340282366920938463463374607431768211456 := by native_decide
  exact Nat.lt_of_le_of_lt h1 h2

/--
Theorem 3.2: Bounded 64-bit Fee Output Safety.
Proves that for any amount bounded by `maxTotalSubunits`, the resulting fee strictly fits within `UInt64`.
-/
theorem fee_result_fits_u64 (amount : Nat) (h : amount <= maxTotalSubunits) (halve : Bool) :
    calculateFee amount halve < 18446744073709551616 := by
  unfold calculateFee
  dsimp
  have h1 : amount * feeNumerator <= maxTotalSubunits * feeNumerator := Nat.mul_le_mul_right feeNumerator h
  have h2 : (amount * feeNumerator) / feeDenominatorNormal <= (maxTotalSubunits * feeNumerator) / feeDenominatorNormal :=
    Nat.div_le_div_right h1
  have h3 : (maxTotalSubunits * feeNumerator) / feeDenominatorNormal < 18446744073709551616 := by native_decide
  have h_base : (amount * feeNumerator) / feeDenominatorNormal < 18446744073709551616 := Nat.lt_of_le_of_lt h2 h3
  have h_half : ((amount * feeNumerator) / feeDenominatorNormal) / 2 <= (amount * feeNumerator) / feeDenominatorNormal :=
    Nat.div_le_self _ 2
  have h_base_half : ((amount * feeNumerator) / feeDenominatorNormal) / 2 < 18446744073709551616 := Nat.lt_of_le_of_lt h_half h_base
  split
  · exact h_base_half
  · exact h_base

/--
Theorem 4: Minting Preserves Supply Conservation.
Adding minted coin rewards maintains `totalRewardedSubunits + remainingSubunits = maxTotalSubunits`.
-/
theorem mint_preserves_conservation (s : LedgerState) (r : Nat)
    (h_inv : InvariantsHold s) :
    SupplyConservation (mint s r) := by
  rcases s with ⟨rewarded, remaining, staked, fees, recycled⟩
  have h_cons : rewarded + remaining = maxTotalSubunits := h_inv.1
  by_cases h_outer : rewarded + r ≤ maxTotalSubunits
  · by_cases h_inner : r ≤ remaining
    · simp [mint, SupplyConservation, h_outer, h_inner]
      omega
    · simp [mint, SupplyConservation, h_outer, h_inner]
      omega
  · simp [mint, SupplyConservation, h_outer]
    exact h_cons

/--
Theorem 5: Minting Preserves Hard Cap Boundary.
-/
theorem mint_preserves_supply_cap (s : LedgerState) (r : Nat)
    (h_inv : InvariantsHold s) :
    SupplyCapBound (mint s r) := by
  rcases s with ⟨rewarded, remaining, staked, fees, recycled⟩
  have h_cons : rewarded + remaining = maxTotalSubunits := h_inv.1
  have h_cap : rewarded <= maxTotalSubunits := h_inv.2.1
  by_cases h_outer : rewarded + r ≤ maxTotalSubunits
  · by_cases h_inner : r ≤ remaining
    · simp [mint, SupplyCapBound, h_outer, h_inner]
    · simp [mint, SupplyCapBound, h_outer, h_inner]
      omega
  · simp [mint, SupplyCapBound, h_outer]
    exact h_cap

/--
Theorem 6: Minting Preserves Staked Supply Boundary.
-/
theorem mint_preserves_staked_bound (s : LedgerState) (r : Nat)
    (h_inv : InvariantsHold s) :
    StakedSupplyBound (mint s r) := by
  rcases s with ⟨rewarded, remaining, staked, fees, recycled⟩
  have h_staked : staked <= rewarded := h_inv.2.2
  by_cases h_outer : rewarded + r ≤ maxTotalSubunits
  · by_cases h_inner : r ≤ remaining
    · simp [mint, StakedSupplyBound, h_outer, h_inner, Nat.le_trans h_staked (Nat.le_add_right rewarded r)]
    · simp [mint, StakedSupplyBound, h_outer, h_inner, Nat.le_trans h_staked (Nat.le_add_right rewarded remaining)]
  · simp [mint, StakedSupplyBound, h_outer, h_staked]

/--
Theorem 7: Complete Mint State Invariant Preservation.
-/
theorem mint_preserves_invariants (s : LedgerState) (r : Nat)
    (h_inv : InvariantsHold s) :
    InvariantsHold (mint s r) := by
  exact ⟨mint_preserves_conservation s r h_inv,
         mint_preserves_supply_cap s r h_inv,
         mint_preserves_staked_bound s r h_inv⟩

/--
Theorem 7.1: Exact Fee Recycling Conservation.
Proves that under post-cap reward recycling, the sum of remaining unspent fees and
total recycled block rewards is strictly conserved (`unspentFees + recycledMinted = constant`).
-/
theorem mint_preserves_fee_recycling_conservation (s : LedgerState) (r : Nat) :
    (mint s r).totalFeesSubunits + (mint s r).recycledRewardedSubunits =
    s.totalFeesSubunits + s.recycledRewardedSubunits := by
  rcases s with ⟨rewarded, remaining, staked, fees, recycled⟩
  by_cases h_outer : rewarded + r ≤ maxTotalSubunits
  · simp [mint, h_outer]
  · by_cases h_recycled : r ≤ fees
    · simp [mint, h_outer, h_recycled]
      omega
    · simp [mint, h_outer, h_recycled]
      omega

/--
Theorem 7.2: Post-Cap Fee Recycling Bounds Preservation.
Proves that when minting draws from the recycled fee pool (post-cap phase),
the unspent fee pool `totalFeesSubunits` is monotonically non-increasing.
-/
theorem mint_preserves_fee_pool_bound (s : LedgerState) (r : Nat) :
    (mint s r).totalFeesSubunits <= s.totalFeesSubunits := by
  rcases s with ⟨rewarded, remaining, staked, fees, recycled⟩
  by_cases h_outer : rewarded + r ≤ maxTotalSubunits
  · simp [mint, h_outer]
  · by_cases h_recycled : r ≤ fees
    · simp [mint, h_outer, h_recycled]
    · simp [mint, h_outer, h_recycled]

/--
Theorem 8: Transfers Preserve Invariants.
-/
theorem transfer_preserves_invariants (s : LedgerState) (amount : Nat)
    (h_inv : InvariantsHold s) :
    InvariantsHold (transfer s amount) := by
  have h_cons : s.totalRewardedSubunits + s.remainingSubunits = maxTotalSubunits := h_inv.1
  have h_cap : s.totalRewardedSubunits <= maxTotalSubunits := h_inv.2.1
  have h_staked : s.totalStakedSubunits <= s.totalRewardedSubunits := h_inv.2.2
  unfold transfer InvariantsHold SupplyConservation SupplyCapBound StakedSupplyBound
  dsimp
  exact ⟨by omega, by omega, by omega⟩

/--
Theorem 9: Staking Preserves Invariants.
-/
theorem stake_preserves_invariants (s : LedgerState) (amount : Nat)
    (h_inv : InvariantsHold s) :
    InvariantsHold (stake s amount) := by
  rcases s with ⟨rewarded, remaining, staked, fees, recycled⟩
  have h_cons : rewarded + remaining = maxTotalSubunits := h_inv.1
  have h_cap : rewarded <= maxTotalSubunits := h_inv.2.1
  have h_staked : staked <= rewarded := h_inv.2.2
  by_cases h_stake_ok : staked + amount ≤ rewarded
  · simp [stake, InvariantsHold, SupplyConservation, SupplyCapBound, StakedSupplyBound,
          h_stake_ok, h_cons, h_cap]
  · simpa [stake, InvariantsHold, SupplyConservation, SupplyCapBound, StakedSupplyBound,
           h_stake_ok] using h_inv

/--
Theorem 10: Unstaking Preserves Invariants.
-/
theorem unstake_preserves_invariants (s : LedgerState) (amount : Nat)
    (h_inv : InvariantsHold s) :
    InvariantsHold (unstake s amount) := by
  rcases s with ⟨rewarded, remaining, staked, fees, recycled⟩
  have h_cons : rewarded + remaining = maxTotalSubunits := h_inv.1
  have h_cap : rewarded <= maxTotalSubunits := h_inv.2.1
  have h_staked : staked <= rewarded := h_inv.2.2
  by_cases h_amt : amount ≤ staked
  · have h_unstaked_le : staked - amount ≤ staked := Nat.sub_le staked amount
    have h_unstaked_bound : staked - amount ≤ rewarded := Nat.le_trans h_unstaked_le h_staked
    simp [unstake, InvariantsHold, SupplyConservation, SupplyCapBound, StakedSupplyBound,
          h_amt, h_cons, h_cap, h_unstaked_bound]
  · simpa [unstake, InvariantsHold, SupplyConservation, SupplyCapBound, StakedSupplyBound,
           h_amt] using h_inv

/--
UTXO Pointer Split Model.
Represents a transaction splitting or transferring UTXO subunits.
-/
structure UtxoTransaction where
  inputSubunits  : Nat
  transferAmount : Nat
  feeAmount      : Nat
  changeAmount   : Nat

/--
A UTXO Transaction is valid iff input equals output + fee + change.
-/
def ValidUtxoTx (tx : UtxoTransaction) : Prop :=
  tx.inputSubunits = tx.transferAmount + tx.feeAmount + tx.changeAmount

/--
Theorem 11: Conservation of Subunit Assets in UTXO Splits and Transfers.
Sum of transfer output, change output, and fee equals total input subunits.
-/
theorem utxo_conservation (tx : UtxoTransaction) (h_valid : ValidUtxoTx tx) :
    tx.transferAmount + tx.changeAmount + tx.feeAmount = tx.inputSubunits := by
  unfold ValidUtxoTx at h_valid
  omega

/--
Theorem 12: Staking Monotonically Reduces or Maintains Economic Stage.
Increasing staked coins never increases the consensus stage requirement.
-/
theorem stage_monotonic_with_staking (rewarded staked1 staked2 : Nat)
    (h_staked : staked1 <= staked2) :
    calculateCurrentStage rewarded staked2 <= calculateCurrentStage rewarded staked1 := by
  have h_red1 : staked1 / subunitsPerCoin ≤ staked2 / subunitsPerCoin := Nat.div_le_div_right h_staked
  have h_red2 : (staked1 / subunitsPerCoin) / 2000000 ≤ (staked2 / subunitsPerCoin) / 2000000 := Nat.div_le_div_right h_red1
  have stage_decr : ∀ (base y1 y2 : Nat), y1 ≤ y2 →
      (if base + 2 < y2 + 2 then 2 else base + 2 - y2) ≤
      (if base + 2 < y1 + 2 then 2 else base + 2 - y1) := by
    intro base y1 y2 h
    by_cases h2 : base + 2 < y2 + 2
    · rw [ite_eq_left h2]
      by_cases h1 : base + 2 < y1 + 2
      · rw [ite_eq_left h1]
        omega
      · rw [ite_eq_right h1]
        have h_base_ge_y1 : y1 ≤ base := by omega
        omega
    · rw [ite_eq_right h2]
      by_cases h1 : base + 2 < y1 + 2
      · rw [ite_eq_left h1]
        have h_base_lt_y1 : base < y1 := by omega
        omega
      · rw [ite_eq_right h1]
        exact Nat.sub_le_sub_left h (base + 2)
  simpa [calculateCurrentStage] using
    (stage_decr (rewarded / (sclCoinThreshold * subunitsPerCoin))
                ((staked1 / subunitsPerCoin) / 2000000)
                ((staked2 / subunitsPerCoin) / 2000000)
                h_red2)


-- =============================================================================
-- 6. Inductive Verification over Arbitrary Block Sequences
-- =============================================================================

/-- Operational transactions that alter or query ledger state -/
inductive Operation
  | Mint (requestedReward : Nat)
  | Transfer (amount : Nat)
  | Stake (amount : Nat)
  | Unstake (amount : Nat)

/-- Apply an operation to the ledger state -/
def applyOp (s : LedgerState) : Operation -> LedgerState
  | Operation.Mint r     => mint s r
  | Operation.Transfer a => transfer s a
  | Operation.Stake a    => stake s a
  | Operation.Unstake a  => unstake s a

/-- Apply a sequence (block or chain) of operations sequentially -/
def applyBlock (s : LedgerState) : List Operation -> LedgerState
  | [] => s
  | op :: ops => applyBlock (applyOp s op) ops

/--
Theorem 13: Inductive Invariant Preservation over Operation Sequences.
Proves that applying any finite sequence of modeled operations (`List Operation`) to an
initially valid `LedgerState` yields a state satisfying `InvariantsHold`.
-/
theorem block_preserves_invariants (ops : List Operation) (s : LedgerState)
    (h_inv : InvariantsHold s) :
    InvariantsHold (applyBlock s ops) := by
  induction ops generalizing s with
  | nil =>
    exact h_inv
  | cons op rest ih =>
    unfold applyBlock
    have h_op_inv : InvariantsHold (applyOp s op) := by
      cases op with
      | Mint r => exact mint_preserves_invariants s r h_inv
      | Transfer a => exact transfer_preserves_invariants s a h_inv
      | Stake a => exact stake_preserves_invariants s a h_inv
      | Unstake a => exact unstake_preserves_invariants s a h_inv
    exact ih (applyOp s op) h_op_inv

end Satocialist
