---
date: 2026-05-20
project: kernel-v4
type: fv-gap-audit
status: dispatch-plan
tags: [formal-verification, gap-audit, halmos, certora, kontrol]
target_vault_path: ~/Documents/Obsidian/projects/kernel-v4/audits/fv-gap-audit.md
---

# Kernel v4 — Formal Verification Gap Audit

> Orchestrator dispatch plan. The user reviews this before any subagent writes proofs. No proofs have been written from this plan yet. This file was written to `audit/` inside the repo because the Obsidian vault is outside the sandbox; documentor should move/copy it to the `target_vault_path` above.

## Scope

Source surveyed: `/Users/taek/workspace/kernel_v4/src/` (~2,549 LOC across 16 contracts).
Existing FV artifacts: 14 Halmos test files in `test/halmos/`, ~85 `check_*` functions. No Certora, no Kontrol, no Tama, no Clear.

## Baseline — What's Already Proven (Halmos)

| File | Proofs | Surface covered |
|---|---|---|
| `KernelAccessControlHalmos.t.sol` | 3 | `_onlyEntryPointOrSelf` on installModule / execute / executeFromExecutor |
| `KernelBatchExecutionHalmos.t.sol` | 8 | Single/batch × default/try semantics, return-data order |
| `KernelExecutionModeHalmos.t.sol` | 9 | `supportsExecutionMode` matrix, `supportsModule` types 0/1-6/7/100 |
| `KernelExecutorHalmos.t.sol` | 7 | Executor return-data shapes 0/8/32/64/256/1024/4096 |
| `KernelFallbackHalmos.t.sol` | 5 | Uninstalled selector reverts, hook-zero gating, no-hook caller policy |
| `KernelGrantAccessHalmos.t.sol` | 8 | Caller restriction, data alignment, nonce increment, multi-selector |
| `KernelHookBracketingHalmos.t.sol` | 5 | Fallback/executor pre/post hook called, revert paths |
| `KernelInstallSignatureHalmos.t.sol` | 6 | Invalid sig reverts, wrong nonce reverts, nonce consumed, sequential nonces |
| `KernelModuleIdempotencyHalmos.t.sol` | 6 | Install→uninstall round-trip for validator/executor/selector/hook/permission; double-install reverts |
| `KernelModuleSafetyHalmos.t.sol` | 1 | Root validator cannot be uninstalled |
| `KernelNonceHalmos.t.sol` | 9 | `setNonce` / `setValidNonceFrom` monotonic, key independence, nonce layout |
| `KernelSelectorHalmos.t.sol` | 5 | Install/uninstall, callType sender appending, delegatecall doesn't append, hook revert |
| `KernelSetRootHalmos.t.sol` | 9 | Caller restriction (both overloads), uninstalled validator reverts, zero-vId reverts, type validation |
| `KernelSignatureHalmos.t.sol` | 4 | Root signature valid/invalid, invalid type reverts, validator-not-installed reverts |
| `KernelStorageSlotHalmos.t.sol` | 7 | All 6 ERC-7201 slots pairwise distinct + derivations |

**Source functions touched by existing proofs**: most public entry points on `Kernel` and the major install/uninstall routes through `ModuleManager` / `ValidationManager` / `SelectorManager`.

**Notable un-touched areas**: `Lib4337.intersectValidationData`, `executeUserOp` linkage to `validateUserOp`, `_verifyStatelessSignature`, permission composition (`_verifySignaturePermission` / `_validateUserOpPermission`), `parseNonce`, `KernelUUPS._authorizeUpgrade`, `Kernel7702` / `KernelImmutableECDSA` fallback signer paths, `setRoot` permission-uninstall LIFO, `Staker.approveFactoryWithSignature` replay safety, `KernelFactory.deploy` determinism.

## Cross-Cutting Findings on Existing Coverage

- **Strong**: storage slot distinctness, access control on EP-gated functions, sentinel-value safety on fallback/executor configs, install-signature nonce mechanics, batch execution semantics.
- **Weak**: anything multi-step (permission install → signer → sign → execute), anything involving the unbounded `policies[]` array, anything that requires two functions to agree on the same predicate (e.g. `_checkNonce` view vs `_checkAndIncrementNonce` write under the `nonceValidFrom` ratchet).
- **Untouched**: arithmetic overflow corners (nonce wrap), upgrade authorisation on the UUPS path, the actual security claim documented in `Kernel.executeUserOp`'s SECURITY comment (the safety of the inner delegatecall rests entirely on `validateUserOp` having already approved the outer UserOp).

## Dispatch Plan

Severity:
- **Critical** — direct path to account takeover or fund loss.
- **High** — privilege escalation, signature replay, or storage corruption with no reasonable mitigation.
- **Medium** — DoS, configuration corruption, or recovery-required state inconsistency.

Effort: S = single subagent call, < 1 day. M = 1-2 day shape, multiple lemmas. L = research-level, expect timeouts and refinement.

### Highest-severity gaps (dispatch order)

| # | Property | Sev | Backend | Why this backend, not the others | Effort |
|---|---|---|---|---|---|
| 1 | `executeUserOp`'s inner delegatecall to `address(this)` cannot execute any privileged kernel function unless `validateUserOp` already authorised the outer UserOp under a validation that owns the inner selector. | **Critical** | **certora** | Two-step trace property: `validateUserOp(op)` then `executeUserOp(op)` keyed by the same `userOpHash`. The link goes through transient storage (`_validationHook`) and the `_allowedSelector` gating against the inner selector. Halmos can in principle handle two calls but the second call's inner calldata (`userOp.callData[4:]`) is symbolic bytes delegatecalled into `address(this)`, which blows up path exploration. Certora's rule language was built for this: pre = `validateUserOp` succeeded, post = no privileged write occurred unless the validation that authorised the call had selector access. | L |
| 2 | `Lib4337.intersectValidationData` preserves aggregator authority: if `preAgg > 1` and `resAgg == 0`, the result's aggregator is `preAgg`. Mirrored: `preAgg == 0` and `resAgg > 1` → result is `resAgg`. Different non-zero aggregators → result is `1` (failure). All six precedence rules in the source comment hold for every input pair. | **Critical** | **halmos** | Pure function, no storage, six precedence rules over `uint256` packed fields. Bounded symbolic execution is a perfect fit and the source comment flags it `SECURITY CRITICAL`. Certora is overkill; Kontrol/Clear cannot see Solidity-level packed encoding cleanly. | S |
| 3 | UUPS upgrade gating: `upgradeToAndCall` reverts unless `msg.sender == ENTRYPOINT \|\| msg.sender == address(this)`. `_authorizeUpgrade` is internal-view, but the public entry path is what an attacker reaches. | **Critical** | **halmos** | Single-call property; pre = arbitrary caller; post = revert unless caller is in allowlist. Same shape as existing `KernelAccessControlHalmos` tests but on the UUPS contract specifically — pull it forward to match. | S |
| 4 | Permission validation totality: a permission-type UserOp succeeds iff **every** policy in `vInfo[vId].policies` returns success AND the signer returns ERC-1271 magic. No policy can be silently skipped. The intersection chain through `Lib4337.intersectValidationData` preserves this. | **Critical** | **certora** | The policy array is unbounded. Halmos must fix a length to symbolically execute; Certora's `forall i in policies` quantifier expresses this directly. Also the intersection chain through `Lib4337.intersectValidationData` is the exact composition shape Certora was built for. | L |
| 5 | `_verifyStatelessSignature` cannot enroll a non-policy, non-signer module into the permission's signature chain (the `bfbef77` fix). For permission type, only packages with `moduleType == 5` or `moduleType == 6` whose `internalData[0:4] == pId` are consumed. | **High** | **halmos** | Bounded property: for a small `packages.length` (≤ 4) and symbolic `moduleType`, prove that if any package with moduleType ∉ {5,6} and matching pId exists, it is skipped (`sigIdx` not incremented). This is the regression test the fix needs and Halmos handles bounded arrays fine. | S |
| 6 | `setRoot(packages, removeCurrent=true)` with `VALIDATION_TYPE_PERMISSION`: after the call, the old root's `policies.length == 0`, `signer == address(0)`, and `vInfo[oldRoot].hook == NOT_INSTALLED`. The LIFO loop runs in `i = policies.length; i > 0; i--` order. | **High** | **certora** | Multi-step state machine: starts with non-empty `policies` array, runs N+1 internal operations (N policy uninstalls + 1 signer uninstall), ends in the cleared state. Halmos can do this for `policies.length` fixed at 2 or 3 but Certora expresses it cleanly with an invariant + rule. | M |
| 7 | `_checkNonce` (view) and `_checkAndIncrementNonce` (write) agree on which `seq` is acceptable under the `nonceValidFrom` ratchet. Formally: `_checkNonce(n)` returns success iff `_checkAndIncrementNonce(n)` would not revert (run on the same pre-state). | **High** | **halmos** | Single-shot property over two functions sharing storage; the ratchet branch (`nonceValidFrom > nonce[key]`) is the only case to symbolically explore. Pure SMT, no quantifiers needed. | M |
| 8 | `parseNonce` round-trip: encoding `[vMode \| vType \| vId \| nonceKey \| seq]` then parsing recovers exactly `(vMode, vType, vId)` for both `VALIDATION_TYPE_VALIDATOR` (full 20-byte vId) and `VALIDATION_TYPE_PERMISSION` (4-byte pId, lower 16 bytes zero-padded). | **High** | **halmos** | Pure assembly bit-shuffling, symbolic over the 256-bit nonce. Tiny, fast Halmos target. A bug here mis-routes validation → trivial account compromise. | S |
| 9 | `Kernel7702._verifyFallbackSignature` and `KernelImmutableECDSA._verifyFallbackSignature` accept a signature iff `ECDSA.tryRecoverCalldata(hash, sig)` equals the expected signer (the EOA / immutable-args address). No other recovery result authorises the fallback path. | **High** | **halmos** | Single call, pure function over signature bytes. Halmos handles ECDSA via cheatcode modelling. Two variants but identical shape — bundle as one dispatch. | S |
| 10 | `Staker.approveFactoryWithSignature` is replay-safe: a valid signature increments `nonces[factory]`, so the same `(factory, approval, signature)` tuple cannot succeed twice. Uses chain-agnostic EIP-712 — proof must hold across `chainid`. | **High** | **halmos** | Two-call property (first succeeds, second with identical args reverts). Halmos handles sequential calls. The cross-chain claim reduces to "the digest doesn't include `chainid`" which is a constant check. | S |
| 11 | `_verifySignaturePermission` (view, ERC-1271 path) and `_validateUserOpPermission` (write, ERC-4337 path) return the same aggregate `validationData` for a given `(vId, policies, signer, hash, signatures)` tuple. The two paths must not diverge in authorisation. | **High** | **certora** | Two-function equivalence over an unbounded policy array. Quantification on `policies` is Certora territory. Halmos would need a bound on `policies.length` and even then the symbolic `op.signature` rewriting inside the UserOp path makes the SMT explode. | L |
| 12 | `KernelFactory.deploy` is deterministic and idempotent: for any `(initialPackages, nonce)` the deployed address equals `getAddress(initialPackages, nonce)`, and a second call returns the same address without re-initializing (no double-init). Same for `deployECDSA`. | **Medium** | **halmos** | Pure salt derivation + LibClone semantics. The no-double-init claim is a state property over two consecutive calls. Both fit in a single Halmos file. | S |
| 13 | `_checkAndIncrementNonce` cannot overflow `uint64` within a single transaction (the `++` is safe under Solidity's overflow check, given `_nonce` is provided externally). Equivalent: no input drives `nonce[key]` from below `type(uint64).max` to wrap. | **Medium** | **halmos** | Pure arithmetic bound; tiny SMT obligation. Practically unreachable but the spec-level claim deserves a proof for completeness. Pair with SMTChecker enabled in CI for defence-in-depth. | S |
| 14 | `_initializeValidation`: both the empty-`_internalData` path and the non-empty path leave `vInfo[vId].nonce` at exactly `previous + 1`. Existing tests cover happy path; this is the "no-double-bump and no-zero-bump" invariant explicitly. | **Medium** | **halmos** | Single-call, single-storage-slot property. Halmos. | S |
| 15 | ERC-1271 nested EIP-712 (`_erc1271IsValidSignatureViaNestedEIP712` and the Replayable variant) does not return success when the contents-hash reconstruction fails. The assembly path is intricate; only the explicit success branch should authorise. | **Medium** | **kontrol** | The function is heavy assembly with calldata manipulation. Halmos can run it but the SMT cost of symbolic-bytes calldata copies is high. Kontrol/KEVM reasons natively over the assembly. If Kontrol setup turns out too expensive for one property, demote to Halmos with a bounded signature length and mark the audit entry "partial". | L |

### Properties intentionally NOT proposed (and why)

- **`supportsExecutionMode` exhaustiveness for unsupported types** — already proven in `KernelExecutionModeHalmos.t.sol`.
- **Validator-path hook bracketing** — only fallback and executor hook bracketing are covered today. Adding the validator-path version would be valuable but it's Medium severity at best and the bracketing logic is shared across paths; defer until the higher-severity items land.
- **`isModuleInstalled` correctness for type 7+** — already proven via `check_DoesNotSupportModuleType7`.
- **Mode dispatch / gas semantics** — out of scope for FV; handled by BTT + gas tests.
- **Tama / Clear properties** — Kernel v4 is post-release with audits and a Foundry/Yul toolchain. The rewrite cost of Tama (Lean EDSL) and the Yul-extraction setup of Clear (which would also have to grapple with `via_ir = false`) is not justified for v4. Reserve Tama/Clear for a hypothetical v5 redesign or for the most critical greenfield primitive.

## Backend Tally

| Backend | Properties | Effort total |
|---|---|---|
| `sc-fv-halmos` | 2, 3, 5, 7, 8, 9, 10, 12, 13, 14 — **10 properties** | ~8-10 days |
| `sc-fv-certora` | 1, 4, 6, 11 — **4 properties** | ~3-4 weeks incl. setup |
| `sc-fv-kontrol` | 15 (preferred) — **1 property** | ~1 week incl. Kontrol setup |
| `sc-fv-clear` | 0 | — |
| `sc-fv-tama` | 0 | — |

## Recommended Dispatch Order

1. **Phase A — Halmos S-effort gaps in parallel**: #2, #3, #5, #8, #9, #10, #12, #13, #14. Most are file-disjoint so parallel-safe; collision risk only on `test/halmos/` itself which the per-property file naming convention already handles.
2. **Phase B — Halmos M-effort**: #7 (`_checkNonce` ↔ `_checkAndIncrementNonce` consistency).
3. **Phase C — Certora setup + first property**: #1. This is the single highest-value proof in the entire codebase; Certora setup pays for itself here.
4. **Phase D — Certora deepening**: #4, #6, #11 once #1 has unblocked the Certora harness.
5. **Phase E — Kontrol experiment**: #15. If Kontrol setup is too costly, demote to a Halmos partial.

## Confidence After Full Plan Lands

- Halmos-proven (Phase A + B): ~95 properties total (existing 85 + new 10).
- Certora-proven: 4 critical multi-step / unbounded-data claims.
- Kontrol-proven: 1 (or Halmos partial).
- **Acknowledged unproven**: full ERC-1271 nested EIP-712 if Kontrol fails; gas semantics; cross-contract real-EntryPoint replay (handled by integration / fuzz tests, not FV).

## Notes for the Subagents (when dispatched)

- Halmos compatibility: v0.3.3, `check_*` / `invariant_*` prefix. Match the existing file's naming convention (mix of `check_X` and `checkX` is present — keep the file consistent internally).
- Run `forge clean` before `halmos` since v0.3.3 occasionally produces artifacts without AST.
- `vm.expectRevert(bytes4)` is not supported in Halmos. Use `try { ... assert(false); } catch {}` or low-level `(bool success,) = ...; assertFalse(success);`.
- `foundry.toml` has `via_ir = false` for contract-size reasons. This rules out Clear (which reasons about Yul output) unless we accept a separate compile pipeline.
- Specs live in `~/Documents/Obsidian/projects/kernel-v4/specs/` (when documentor has populated them — at the moment the source-level NatSpec is the de facto spec).
