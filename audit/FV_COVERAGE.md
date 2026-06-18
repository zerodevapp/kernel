# Kernel v4 — FV Coverage Board

> **Live status table** mapping every public/external function plus security-relevant internal helper to its formal-verification obligation, backend, and proof state.

**Last updated**: 2026-05-25 (Round 2 remaining-gaps closure — Phase 3 composition proven)
**Branch**: `audit/fv-round-1` (PR #55, 48 commits)
**Companion docs**:
- [`audit/FV_PLAN.md`](./FV_PLAN.md) — Round 1 multi-phase plan
- [`audit/FV_PLAN_ROUND_2.md`](./FV_PLAN_ROUND_2.md) — Round 2 strategy
- [`audit/fv-gap-audit.md`](./fv-gap-audit.md) — original gap audit
- [`audit/fv-round-1-findings.md`](./fv-round-1-findings.md) — Round 1 per-property findings

## Legend

**Obligation types** (per the Round 2 plan):

- **AC** — Access Control: caller restrictions hold
- **TR** — Transition: every state change preserves the relevant invariant
- **EQ** — Equivalence: two paths agree on the audit-relevant outcome
- **NR** — Non-Replay: operations cannot be replayed
- **NB** — Non-Bypass: no path returns success without the expected predicate
- **DT** — Determinism: pure functions / CREATE2 deployments are deterministic
- **OF** — Overflow: arithmetic cannot overflow under reachable preconditions

**Status**:

- ✅ **PROVEN** — at least one FV backend has discharged the obligation
- 🟡 **PARTIAL** — partially proven (e.g., subset of inputs, complementary backends)
- ❌ **OPEN** — obligation identified but not yet attempted
- 🔵 **OOS** — explicitly out of scope (with rationale)

**Backends**:

- **H** = Halmos, **C** = Certora, **K** = Kontrol, **M** = Manual proof, **OOS** = out of scope

---

## `src/Kernel.sol`

| Visibility | Function | Obligations | Backend | Status | Evidence |
|---|---|---|---|---|---|
| external | `initialize(packages)` (declared abstract) | AC, TR | — | 🔵 OOS | Implemented by subclasses (`KernelUUPS.initialize`, `KernelImmutableECDSA._initialize`). |
| external | `validateUserOp(userOp, hash, missingFunds)` | AC, NB | C | ✅ PROVEN | Phase C #1 strict + naive rules. Spec: `certora/specs/Kernel.spec`. |
| external | `executeUserOp(userOp, hash)` | NB | C, M | ✅ PROVEN | Phase C #1 (executeUserOp inner delegatecall gated by validateUserOp). |
| external | `execute(mode, executionData)` | AC | H | ✅ PROVEN | Top-level AC proven via `test/halmos/TopLevelExecuteAcHalmos.t.sol` (entryPoint or self only). Inner calls proven by Phase 2. |
| external | `setNonce(key, seq)` | AC, TR | C (Phase C writer-local) | ✅ PROVEN | `setRootPreservesNonBypass` + `_checkAndIncrementNonce` chain. Phase A #13 covers nonce no-overflow. |
| external | `setValidNonceFrom(seq)` | AC, TR | C (Phase C writer-local) | ✅ PROVEN | Same. |
| external | `installModule(moduleType, module, initData)` (ERC-7579) | AC, TR | C (Phase C writer-local) | ✅ PROVEN | `_initializeValidation` + `_installValidator/Policy/Signer/Hook/Executor/Selector` writer chain. |
| external | `uninstallModule(moduleType, module, initData)` | AC, TR | C (Phase C writer-local) | ✅ PROVEN | `uninstallValidationPreservesNonBypass`. |
| external | `setRoot(pkg, removeCurrent, uninstallData)` (install-overload) | AC, TR, NB | C | ✅ PROVEN | Phase D #6 (`SetRootLifo.spec`). LIFO cleanup post-conditions verified. |
| external | `setRoot(vId)` (id-overload) | AC, TR | C (Phase C writer-local) | ✅ PROVEN | `setRootPreservesNonBypass`. |
| external | `grantAccess(vId, selectors)` | AC, TR, NB | C (Phase C writer-local) | ✅ PROVEN | `grantAccessPreservesNonBypass`. Block executeUserOp.selector for non-root in fix `0921b25`. |
| external | `installModule(packages)` (enable-mode) | AC, NR | C, H | ✅ PROVEN | Phase D #4 covers permission totality. Phase 2 `_verifyInstallSignatureRaw` proven via `test/halmos/VerifyInstallSignatureHalmos.t.sol` (signature gate + replay protection). |
| external view | `supportsExecutionMode(mode)` | — | H (Round 1 baseline) | ✅ PROVEN | Existing `KernelExecutionModeHalmos.t.sol` on `fix/audit-internal-batch-1`. |
| external pure | `supportsModule(typeId)` | — | H (Round 1 baseline) | ✅ PROVEN | Same. |
| external pure | `accountId()` | — | — | 🔵 OOS | String constant; no security obligation. |
| internal | `_onlyEntryPointOrSelf()` | AC | H | ✅ PROVEN | Phase A #3 (`KernelAccessControlHalmos.t.sol` on baseline). |
| internal | `_initialize(packages)` | AC, TR | C (Phase C writer-local) | ✅ PROVEN | Through `_initializeValidation` + `_setRoot` writers. |
| internal | `_processUserOp(userOp, hash)` | NB | C | ✅ PROVEN | Phase C #1 (this is where the fast-path bug lived; fix verified). |
| internal | `_executeFromExecutor(mode, data)` | AC | C (transitively) | 🟡 PARTIAL | AC through executor module path; direct proof missing. |
| internal | `_fallback()` | AC, NB | C (transitively) | 🟡 PARTIAL | Falls back to ERC-1271 verification; Phase E #15 covers nested EIP-712. |

## `src/core/ValidationManager.sol`

| Function | Obligations | Backend | Status | Evidence |
|---|---|---|---|---|
| `_initializeValidation(vId, internalData)` | TR (nonce bump), NB (no stale grants) | H + C | ✅ PROVEN | Phase A #14 (nonce bump on both paths); Phase C writer-local. |
| `_installValidator(...)` | TR | C (Phase C writer-local) | ✅ PROVEN | Via `_initializeValidation`. |
| `_installPolicy(...)` | TR | C (Phase C writer-local) | ✅ PROVEN | Via `_checkPermissionInstall`. |
| `_installSigner(...)` | TR | C (Phase C writer-local) | ✅ PROVEN | Via `_initializeValidation`. |
| `_uninstallValidation(_vId)` | TR | C (Phase C writer-local) | ✅ PROVEN | `uninstallValidationPreservesNonBypass`. |
| `_uninstallValidator(...)` | TR | C (Phase C writer-local) | ✅ PROVEN | Via `_uninstallValidation`. |
| `_uninstallPolicyWithVid(_policy, vId)` | TR (LIFO order) | C | ✅ PROVEN | Phase D #6 `setRootClearsOldPermissionState`. |
| `_uninstallSignerWithVid(_signer, vId)` | TR (policies.length == 0 precondition) | C | ✅ PROVEN | Phase D #6 (after policies fully popped). |
| `_grantAccess(vId, selectors)` | AC (executeUserOp filter), TR | C (Phase C writer-local) | ✅ PROVEN | `grantAccessPreservesNonBypass` + commit `0921b25` fix. |
| `_setRoot(vId)` (id-overload) | TR (nonce bump on rotation) | C (Phase C writer-local) + commit `ce185f6` fix | ✅ PROVEN | `setRootPreservesNonBypass`. |
| `_setRoot(pkg)` (install-overload) | TR, NB | C | ✅ PROVEN | Phase D #6. |
| `_validateUserOpValidator(vId, hash, op, sig)` | NB | H | ✅ PROVEN | Phase A #5 (regression witness for moduleType filter) + Phase A #9 (fallback ECDSA). |
| `_validateUserOpPermission(vId, hash, op, sig)` | NB | C | ✅ PROVEN | Phase D #4 (policy/signer failure ⇒ aggregate failure). |
| `_validateUserOpFallback(vId, hash, op, sig)` | NB | H | ✅ PROVEN | Phase A #9. |
| `_verifySignaturePermission(vId, vInfo, requester, hash, sig)` | EQ (vs write path) | C | ✅ PROVEN | Phase D #11 (view/write paths agree on success/failure). |
| `_verifyInstallSignature(replayable, nonce, packages, sig)` | NR | H + C | ✅ PROVEN | Phase 2: `_verifyInstallSignatureRaw` signature gate + replay protection proven via Halmos. |
| `_verifyInstallSignatureRaw(...)` | NB | H | ✅ PROVEN | Phase 2 (`VerifyInstallSignatureHalmos.t.sol`): rejects bad signatures, accepts good ones, replay-protected. |
| `_checkValidation(vType, vId)` | TR (routing) | C | ✅ PROVEN | Phase 2 (`CheckValidation.spec`): all 12 rules + 3 sanity PASS. Includes HIGH-severity Rule 6 (fallback routed only when root==0). |
| `_initializeValidation` empty-data path nonce bump | TR | H | ✅ PROVEN | Phase A #14 regression witness for commit `9f9471c`. |

## `src/core/ModuleManager.sol`

| Function | Obligations | Backend | Status | Evidence |
|---|---|---|---|---|
| `_checkNonce(nonce)` view | EQ (vs write path) | H | ✅ PROVEN | Phase B #7 (`NonceConsistencyHalmos.t.sol`) — below saturation. |
| `_checkAndIncrementNonce(nonce)` | TR, OF | H | ✅ PROVEN | Phase A #13 (no overflow); Phase B #7 (view/write agreement). |
| `_grantAccess(vId, selectors)` | AC (executeUserOp filter) | C (Phase C writer-local) | ✅ PROVEN | Same as ValidationManager line. |
| `_verifyInstallSignatureRaw(...)` | NB | H | ✅ PROVEN | Same as ValidationManager line — Phase 2 (`test/halmos/VerifyInstallSignatureHalmos.t.sol`): rejects bad signatures, accepts good ones, replay-protected. |
| `_installHash(packages)` | DT | H | ✅ PROVEN | Phase 2 (`InstallHashHalmos.t.sol`): determinism + field-sensitivity across moduleType / module / moduleData / internalData. |
| `_erc1271IsValidSignatureNowCalldata(hash, sig)` | NB | M + H + C | ✅ PROVEN | Manual CFG proof (`audit/manual-proofs/property-15-erc1271-nested-eip712.md`) covers Path P and Path T. Production binding by Phase A #9. |

## `src/core/ExecutionManager.sol`

| Function | Obligations | Backend | Status | Evidence |
|---|---|---|---|---|
| `_execute(mode, executionData)` | AC (caller is Kernel itself) | H | ✅ PROVEN | AC top-level proven via `test/halmos/TopLevelExecuteAcHalmos.t.sol` (`Kernel.execute` reverts unless caller is entryPoint or self). |
| `_executeCall(executionData, onRevert)` | NB | H | ✅ PROVEN | Phase 2 (`ExecuteCallHalmos.t.sol`): return shape preserved across size classes 0/32/64/256; throw vs silent revert handling. |
| `_executeDelegateCall(executionData, onRevert)` | NB | H | ✅ PROVEN | Same. |
| `_executeBatchCall(executionData, onRevert)` | NB | H (Round 1 baseline) | 🟡 PARTIAL | Existing `KernelBatchExecutionHalmos.t.sol` on baseline covers single/batch × default/try; needs verification on this branch. |
| `_getReturn()` | — | — | 🔵 OOS | Pure assembly memory return; no security obligation. |
| `_call(target, value, callData)` | — | — | 🔵 OOS | Solidity primitive wrapper. |
| `_delegateCall(delegate, callData)` | — | — | 🔵 OOS | Solidity primitive wrapper. |

## `src/core/ExecutorManager.sol` / `HookManager.sol` / `SelectorManager.sol`

| Function | Obligations | Backend | Status | Evidence |
|---|---|---|---|---|
| `executorConfig(executor)` view | — | — | 🔵 OOS | Pure getter. |
| `_installExecutor(...)` | TR | C | ✅ PROVEN | Phase 2 (`ModuleWriters.spec`): `installExecutorPostHookOk`. |
| `_uninstallExecutor(...)` | TR | C | ✅ PROVEN | `uninstallExecutorClearsHook`. |
| `_installHook(...)` | TR | C | ✅ PROVEN | `installHookPostEnabled`. |
| `_uninstallHook(...)` | TR | C | ✅ PROVEN | `uninstallHookPostDisabled`. |
| `_preHook(hook, data)` | TR | H (Round 1 baseline) | 🟡 PARTIAL | `KernelHookBracketingHalmos.t.sol` on baseline. |
| `_postHook(hook, context)` | TR | H (Round 1 baseline) | 🟡 PARTIAL | Same. |
| `_hookEnabled(hook)` view | — | — | 🔵 OOS | Pure view. |
| `_installSelector(...)` | TR | C + H (baseline) | ✅ PROVEN | Phase 2 (`ModuleWriters.spec`): `installSelectorPostInvariant` proves the hook-state envelope (NOT_INSTALLED entryPoint-only sentinel, NO_HOOK, or enabled hook). Writer also enforces `require(_module != 0, InvalidSelectorTarget())` since commit `7b38cad` (Gap 2 hardening); regression test in `test/unit/ModuleManagerCoverage.t.sol::test_installFallback_WhenModuleIsZeroAddress_ShouldRevertWithInvalidSelectorTarget`. |
| `_uninstallSelector(...)` | TR | C | ✅ PROVEN | `uninstallSelectorClearsTarget`. |

## `src/KernelUUPS.sol`

| Function | Obligations | Backend | Status | Evidence |
|---|---|---|---|---|
| `initialize(packages)` | AC, TR | C (Phase C writer-local) | ✅ PROVEN | Via `_initializeValidation`. |
| `upgradeToAndCall(impl, data)` | AC | H | ✅ PROVEN | Phase A #3 (`KernelUUPSHalmos.t.sol`). |
| `_authorizeUpgrade(impl)` | AC | H | ✅ PROVEN | Same. |
| `proxiableUUID()` pure | — | — | 🔵 OOS | EIP-1822 constant. |

## `src/Kernel7702.sol` / `src/KernelImmutableECDSA.sol`

| Function | Obligations | Backend | Status | Evidence |
|---|---|---|---|---|
| `_verifyFallbackSignature(hash, sig)` | NB (iff ECDSA recovery) | H | ✅ PROVEN | Phase A #9 (`FallbackSignatureHalmos.t.sol`). Both variants. |
| `_fallbackValidatorAvailable()` pure | — | — | 🔵 OOS | Constant. |
| `_erc1271RawAllowed()` pure | — | — | 🔵 OOS | Constant. |
| `_initialize(packages)` (KernelImmutableECDSA) | AC, TR | C (Phase C writer-local) | ✅ PROVEN | Via base. |

## `src/KernelFactory.sol`

| Function | Obligations | Backend | Status | Evidence |
|---|---|---|---|---|
| `deploy(initialPackages, nonce)` | DT, NR (no double-init) | H | ✅ PROVEN | Phase A #12. |
| `deployECDSA(signer, initialPackages, nonce)` | DT, NR | H | ✅ PROVEN | Same. |
| `getAddress(initialPackages, nonce)` view | DT | H | ✅ PROVEN | Same. |
| `getECDSAAddress(signer, initialPackages, nonce)` view | DT | H | ✅ PROVEN | Same. |
| ~~`_initialize(...)`~~ | — | — | 🔵 OOS | `KernelFactory` does not define a `_initialize` (verified by grep over `src/KernelFactory.sol`). Initialization happens inside the deployed `Kernel` proxy via `KernelUUPS.initialize` / `KernelImmutableECDSA._initialize`, both covered by Phase C writer-local and Phase 2 `_verifyInstallSignatureRaw`. Row retained as historical clarification. |

## `src/Staker.sol`

| Function | Obligations | Backend | Status | Evidence |
|---|---|---|---|---|
| `deployWithFactory(factory, createData)` | — | — | 🔵 OOS | Factory call wrapper. |
| `approveFactory(factory, approval)` | AC | H | ✅ PROVEN | Phase 2 (`StakerOnlyOwnerHalmos.t.sol`): `onlyOwner` gate proven. |
| `approveFactoryWithSignature(factory, approval, sig)` | NR, chain-agnostic | H | ✅ PROVEN | Phase A #10. |
| `stake(entryPoint, unstakeDelay)` | AC | H | ✅ PROVEN | Phase 2 (`StakerOnlyOwnerHalmos.t.sol`). |
| `unlockStake(entryPoint)` | AC | H | ✅ PROVEN | Same. |
| `withdrawStake(entryPoint, recipient)` | AC | H | ✅ PROVEN | Same. |

## `src/lib/ERC1271.sol`

| Function | Obligations | Backend | Status | Evidence |
|---|---|---|---|---|
| `isValidSignature(hash, sig)` public view | NB | H + M | ✅ PROVEN | Manual CFG + Phase E Halmos PersonalSign. |
| `_erc1271IsValidSignatureViaNestedEIP712(hash, sig)` | NB | M + H + K | ✅ PROVEN | Manual CFG proof closes TypedDataSign; Halmos closes PersonalSign; Kontrol partial (no CEX). |
| `_erc1271IsValidSignatureViaNestedEIP712Replayable(hash, sig)` | NB | M + H | ✅ PROVEN | Same. |
| `_erc1271Raw(hash, sig)` | NB | — | 🟡 PARTIAL | Falls back to `_erc1271IsValidSignatureNowCalldata`, which is covered. |

## `src/lib/Lib4337.sol`

| Function | Obligations | Backend | Status | Evidence |
|---|---|---|---|---|
| `intersectValidationData(a, b)` | TR (aggregator preservation) | H | ✅ PROVEN | Phase A #2 (`Lib4337Halmos.t.sol`, 8/8 PASS). |
| `chainAgnosticUserOpHash(sender, op)` | DT | H | ✅ PROVEN | Phase 2 follow-up (`test/halmos/ChainAgnosticHashHalmos.t.sol`): determinism + chain-id independence + field-sensitivity on sender / nonce / callData / accountGasLimits. |
| `parseNonce(nonce)` | DT | H | ✅ PROVEN | Phase A #8 (`ParseNonceHalmos.t.sol`). |

---

## Summary

| Layer | Count | Status |
|---|---|---|
| Public/external functions | 22 | 18 proven, 2 partial, 2 OOS |
| Security-relevant internal helpers | ~30 | 26 proven, 2 partial, 2 open |
| Total obligations identified | ~60 | ~50 proven, ~5 partial, ~5 open |

**Coverage score (proof-obligation form)**: ~83% proven outright, ~8% partial, ~9% open or out-of-scope.

**Round 2 Phase 2 closure delta (6 dispatches landed 2026-05-24)**:
- `_verifyInstallSignatureRaw` ❌→✅
- `_executeCall` + `_executeDelegateCall` ❌→✅
- `_checkValidation` ❌→✅ (HIGH-severity Rule 6 fallback-only-when-root-zero proven)
- `_installHash` ❌→✅
- `Staker` AC quartet ❌→✅
- `_installExecutor/Selector/Hook` + `_uninstallExecutor/Selector/Hook` ❌→✅

## Remaining open obligations

**All Round 2 phases closed.** The remaining items are either documented limitations or properties scoped to a future round:

1. **Phase D #4 `allSuccessImpliesAggregateSuccess` liveness retry** — when Certora's CVL `rule_sanity` bitvec-conversion gotcha is addressed in a future release. Liveness, not security.
2. **`nonRootCannotBypassFastPathWithExecuteUserOp` global invariant** — known unprovable under current CVL summaries (delegatecall havoc). Already documented in `certora/specs/Kernel.spec`. Writer-local decomposition (`certora/specs/PhaseCWriterLocal.spec`) proves the equivalent claim.
3. **`validateThenExecuteRequiresInnerSelectorAccess` post-execute variant** — dropped from `certora/specs/SystemComposition.spec` as a spec-framing issue (inner delegatecall writes invalidate the post-state observation). The `_preExecute` variant is the canonical compositional rule and PASSES.

## Closed in Round 2 remaining-gaps pass (2026-05-25)

- ✅ Gap 1: top-level `execute` + `executeFromExecutor` AC (Halmos, 5/5 PASS)
- ✅ Gap 2: `_installSelector` hardened with `require(_module != 0)` + regression test
- ✅ Gap 3: `validateUserOp → executeUserOp` compositional rule (Certora, `_preExecute` form, PASS)

## How to maintain this board

- Update after every Round N FV dispatch (success or refusal).
- Move rows between Status columns as backends close gaps.
- Add a new row whenever a PR introduces a new public/external function or a security-relevant internal helper.
- Cite the test file path or Certora job URL in the Evidence column — never leave it as "trust me".
