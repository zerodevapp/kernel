# Kernel v4 — FV Round 2 Plan

> **Strategy**: target *proof-obligation coverage*, not literal line coverage. "Full FV coverage" for this codebase means: every public/privileged entry point, every security-critical storage invariant, every view/write equivalence, every unbounded permission composition path, and every assembly-heavy signature path is either **proven** or **explicitly documented as out of scope**.

**Branch**: `audit/fv-round-2` (off `audit/fv-round-1` @ `3856e68`)
**Companion docs**:
- [`audit/FV_PLAN.md`](./FV_PLAN.md) — Round 1 multi-phase plan (Phases A-E)
- [`audit/fv-gap-audit.md`](./fv-gap-audit.md) — orchestrator's original gap audit + backend dispatch rationale
- [`audit/fv-round-1-findings.md`](./fv-round-1-findings.md) — Round 1 per-property findings
- [`audit/FV_COVERAGE.md`](./FV_COVERAGE.md) — Live coverage board (to be created in Phase 4)

---

## Phase 1 — Close known gaps from Round 1

| # | Property | Round 1 status | Round 2 status |
|---|----------|----------------|----------------|
| 15 | `_erc1271IsValidSignatureViaNestedEIP712` TypedDataSign branch | Kontrol partial (14 SUCCESS, 0 CEX, timeout); Halmos PROVEN on PersonalSign | ✅ **CLOSED** — Kontrol Round 2: 524 nodes, 90 SUCCESS, 0 CEX, hit 500-iter limit. Manual CFG proof closes the gap at `audit/manual-proofs/property-15-erc1271-nested-eip712.md` (commit `a16ff4b`). |
| Phase C invariant | `nonRootCannotBypassFastPathWithExecuteUserOp` | Unprovable under current CVL summaries (NONDET callback havoc) | ✅ **CLOSED** — Writer-local decomposition into 4 rules in `certora/specs/PhaseCWriterLocal.spec` (commit `56d03a2`). All 4 rules + 4 sanity checks PASS. Job: https://prover.certora.com/output/3606101/37e8675776484e4998f16f528d2dd29a |
| Phase D #4 liveness | `allSuccessImpliesAggregateSuccess` | Dropped (Certora `rule_sanity` bitvec gotcha) | Deferred to a future Certora release. Security direction proven; this is liveness. Low priority. |

---

## Phase 2 — Function-by-function proof obligation matrix

Enumerate every public/external function plus security-relevant internal helper, assign ≥1 FV obligation per row. Backend choice per the matrix:

- **Halmos** — pure, bounded, state-local
- **Certora** — cross-call, unbounded arrays, multi-step traces
- **Kontrol** — assembly-heavy, calldata-manipulation, precise EVM semantics
- **Manual / sc-critical-thinker** — single-return-site CFG arguments, structural-by-inspection claims

### Draft surface inventory

| Contract | Public/external | Internal security-relevant | Round 1 coverage |
|---|---|---|---|
| `Kernel` | execute, executeFromExecutor, executeUserOp, validateUserOp, installModule×2, uninstallModule, setRoot, grantAccess, isValidSignature, upgradeToAndCall, fallback | _processUserOp, _checkValidation | Partial (Phase A #3, #5, #14; Phase C #1; Phase D #4, #6, #11) |
| `ValidationManager` | — | _initializeValidation, _installValidator, _installPolicy, _installSigner, _uninstallValidation, _uninstallValidator, _uninstallPolicy, _uninstallSigner, _grantAccess, _setRoot×2, _verifySignaturePermission, _validateUserOpPermission, _validateUserOpValidator, _validateUserOpFallback, _verifyInstallSignature | Partial (Phase A #5, #14; Phase B #7; Phase D #4, #6, #11) |
| `ModuleManager` | setNonce, setValidNonceFrom, grantAccess wrappers | _checkNonce, _checkAndIncrementNonce, _grantAccess | Partial (Phase A #13; Phase B #7) |
| `ExecutionManager` | — | _executeCall, _executeDelegateCall, _executeBatchCall, _execute | Phase A #3 batch tests on `fix/audit-internal-batch-1` only (pre-Round-1) |
| `KernelFactory` | deploy, deployECDSA, getAddress, getECDSAAddress | _initialize | Phase A #12 |
| `Staker` | approveFactory, approveFactoryWithSignature, stake, unstake | — | Phase A #10 |
| `KernelUUPS` | upgradeToAndCall, proxiableUUID | _authorizeUpgrade | Phase A #3 |
| `Kernel7702`, `KernelImmutableECDSA` | _verifyFallbackSignature (effective entry via isValidSignature) | — | Phase A #9 |
| `lib/ERC1271`, `lib/Lib4337` | _erc1271IsValidSignature*, intersectValidationData | various | Phase A #2; Phase E #15 |

### Obligation types

For each function, identify which apply:

- **AC** (access control): caller restrictions hold
- **TR** (transition): every state change preserves the relevant invariant
- **EQ** (equivalence): two paths (view/write, internal/external, alternate ABIs) agree on the audit-relevant outcome
- **NR** (non-replay): operations are not replayable
- **NB** (non-bypass): no path returns success without the expected predicate holding
- **DT** (determinism): pure functions are deterministic; CREATE2 deployments are deterministic
- **OF** (overflow): arithmetic cannot overflow under reachable preconditions

### Dispatch ordering (highest leverage first)

1. **Round 1 remainder**: `_checkValidation`, `_processUserOp` (non-fast-path), `_uninstallValidator/Policy/Signer`, `_verifyInstallSignatureRaw`, `_validateUserOpValidator`, `_validateUserOpFallback`
2. **ExecutionManager**: `_executeCall`, `_executeDelegateCall`, `_executeBatchCall` — each function under each execution mode
3. **Cross-contract**: KernelFactory `getAddress(addr_predicted == addr_deployed)`, Staker stake/unstake monotonicity
4. **UUPS / fallback signers**: extend Phase A #3/#9 to cover error paths and reentrancy guards

---

## Phase 3 — System-level compositional proofs

Compositional rules that span multiple internal functions or across multiple transactions.

### Candidates

| Rule | Description | Backend | Complexity |
|---|---|---|---|
| `validateUserOp_then_executeUserOp` | End-to-end: for any sequence `validateUserOp; executeUserOp`, the inner delegatecall is gated by the validation's authorisation **regardless of mode** (validator / permission / root / fallback × enable-mode × replayable-mode). | Certora | L |
| `install_uninstall_setRoot_lifecycle` | Any install → uninstall → re-install sequence on the same vId leaves the validation in a sound state (no stale grants, correct nonce, hook respected). | Certora | M |
| `enable_mode_install_signature` | An enable-mode UserOp installs the package iff `_verifyInstallSignatureRaw` accepts the root signature. | Certora | M |
| `replayable_userop_hash_chain_agnostic` | A replayable UserOp's digest is `chainid`-independent and the nonce is the replay barrier. | Halmos | S |
| `factory_to_kernel_consistency` | A kernel deployed via `KernelFactory.deploy(pkgs, nonce)` has the same initial state as one constructed and initialised by hand with the same args. | Certora | M |

### Strategy

Each compositional rule typically needs:

- A harness that exposes multiple internal functions as external entry points
- NONDET summaries for **leaf** module calls (validators, policies, signers, hooks) — not for kernel internals
- A multi-step rule that calls the functions in sequence and asserts the compositional invariant

Round 1's Phase C harness pattern (`certora/harnesses/KernelHarness.sol`) is the starting template.

---

## Phase 4 — Make FV regression-grade

### Coverage board

`audit/FV_COVERAGE.md` — a live table that maps each (Contract × Function × Obligation) tuple to:

- **Backend**: Halmos / Certora / Kontrol / Manual / OOS (out of scope)
- **Status**: Proven / Partial / Failed / NotStarted
- **Job URL or test file path**
- **Regression witness commit** (if a bug was found en route)

Updated on every Round 2 dispatch and PR merge. Becomes the "FV trust dashboard" reviewers can pin in PRs.

### Regression witnesses

One Halmos/Certora test per bug found in this round (or any future round) that would have CEX'd pre-fix. Already started in Round 1:

- `InitializeValidationHalmos.checkInitializeValidationBumpsByOneEmptyData` ↔ commit `9f9471c`
- `PermissionStatelessHalmos.checkSigIdxDoesNotAdvanceForAnyNonPolicySignerType` ↔ commit `bfbef77`
- `Kernel.spec validateUserOpEnforcesInnerSelectorAccess_naive` ↔ commits `0921b25` + `ce185f6`

Round 2 continues this pattern for any new findings.

### PR gating

- **Per-PR (must pass)**: Halmos on the proven rule set. Cold ~30 s, warm ~10 s. Cheap enough to gate every PR.
- **Nightly (must not regress)**: Certora on the full spec suite (`Kernel.conf`, `Permission.conf`, `SetRootLifo.conf`, `PermissionEquivalence.conf` and any Round 2 additions). Heavy — ~30 min total.
- **Per-release**: Kontrol on the assembly-heavy claims. Expensive but rare.
- **Coverage-board gate**: any PR adding a new public/external function must add a row to `FV_COVERAGE.md` and either an FV obligation or an explicit OOS justification.

---

## Effort & sequencing

| Phase | Effort estimate | Trigger |
|-------|-----------------|---------|
| 1 (close gaps) | 1-3 days | Start immediately. #15 first, then Phase C invariant split, then Phase D #4 deferred. |
| 2 (matrix) | 2-3 weeks | Start the inventory in parallel with Phase 1. Dispatch as bandwidth allows. |
| 3 (compositional) | 1-2 weeks | After Phase 2 covers the underlying functions. |
| 4 (regression-grade) | 3-5 days | Coverage board can be drafted alongside Phase 1; CI gating once Phase 2 stabilises. |

Total realistic window for Round 2: **4-6 weeks of focused FV work**, assuming a single FV-focused engineer (or one team lead orchestrating subagents).

---

## Out-of-scope items (declared upfront)

These are intentionally NOT in Round 2 scope. Adding them later is fine; the OOS declaration is to keep Round 2 finite:

- **Gas semantics** — handled by gas profiler + BTT tests
- **Cross-chain replay** — handled by integration / fuzz tests; covered for Staker (Phase A #10)
- **External validator/policy/signer module correctness** — Kernel's trust boundary; modules are sandboxed by `_onlyEntryPointOrSelf`, their internal correctness is the module author's responsibility
- **Tama (Lean EDSL)** — rewrite cost not justified for post-release v4
- **Clear (Yul-on-Lean)** — `via_ir = false` precludes meaningful coverage; would require flipping the foundry profile
- **ERC-1271 nested EIP-712 contentsName encoding edge cases** — partially covered; full closure requires Kontrol with larger budget OR manual proof

---

## How to resume

1. Read this file + `FV_PLAN.md` + `FV_COVERAGE.md` for state.
2. Check `git status` for any in-flight artifacts.
3. Re-dispatch using the orchestrator (`sc-formal-verifier`) on the highest-priority open obligation.
4. Update `FV_COVERAGE.md` on every dispatch completion.
