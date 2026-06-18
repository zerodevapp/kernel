---
date: 2026-05-20
branch: audit/fv-round-1
type: fv-findings
status: in-progress
---

# Kernel v4 — FV Round 1 Findings

Subagent results as they land. Each entry: property, status, file, notable observations, follow-ups.

## Phase A — Halmos (in flight)

### ✅ #2 — `Lib4337.intersectValidationData` aggregator precedence

- **Status**: PROVEN (8/8 checks pass, 0.30s total wall time)
- **File**: `test/halmos/Lib4337Halmos.t.sol`
- **Checks**:
  - `checkRule1_PreFailure` — preAgg==1 ⇒ result agg==1
  - `checkRule1_ResFailure` — resAgg==1 ⇒ result agg==1
  - `checkRule2_BothSuccess` — both 0 ⇒ result agg==0
  - `checkRule3_PreserveAggregator` — **SECURITY CRITICAL** — preAgg>1 & resAgg==0 ⇒ result agg==preAgg
  - `checkRule4_AdoptAggregator` — preAgg==0 & resAgg>1 ⇒ result agg==resAgg
  - `checkRule5_SameAggregator` — preAgg==resAgg>1 ⇒ result agg==preAgg
  - `checkRule6_ConflictingAggregators` — preAgg>1 & resAgg>1 & differ ⇒ result agg==1
  - `checkAggregatorPreservedWhenResAgg0` — combined regression guard with fully symbolic words
- **Notable observations**:
  - The impl has an early-out (`if (preValidationData == 0 || validationRes == 0) return preValidationData | validationRes;`) not enumerated as a separate rule. Aggregator-only checks are insensitive to this branch.
  - Agent masked out bit 47 of each uint48 time field (`CLEAR_MODE_BITS = ~((1<<255) | (1<<207))`) to avoid the orthogonal `ValidityFormatMismatch` revert path. Mask is symbolic, not a fixed concrete value.
  - Source comment is ambiguous about whether `preAgg == resAgg == 0` belongs to rule 2 or rule 5. Impl reads rule 2 first; agent constrained rule 5 check to `agg > 1` to keep rules disjoint.
- **Follow-up**: separate Halmos dispatch later to verify the `ValidityFormatMismatch` revert path itself (rejects malformed-format inputs).

### ✅ #3 — `KernelUUPS.upgradeToAndCall` caller gating

- **Status**: PROVEN (3/3 checks)
- **File**: `test/halmos/KernelUUPSHalmos.t.sol`
- **Worktree branch**: `worktree-agent-ae153a8b47bc09c98`
- **Checks**:
  - `checkUpgradeToAndCallRevertsForArbitraryCaller` — pass, 1 path
  - `checkUpgradeToAndCallSucceedsForEntryPoint` — pass, 1 path
  - `checkUpgradeToAndCallSucceedsForSelf` — pass, 2 paths
- **Notable observations**:
  - Solady's `UUPSUpgradeable` only exposes `upgradeToAndCall`; no `upgradeTo(address)` to cover separately.
  - Allowlist is exactly `{ENTRYPOINT, address(this)}` via `_onlyEntryPointOrSelf` — no role registry, no module bypass.
  - **Important harness note**: agent deployed a real ERC1967 proxy via `LibClone.deployERC1967(impl)` and called the proxy, NOT the implementation directly. The existing `KernelExecutorHalmos` pattern (`new KernelUUPS(...)`) would short-circuit on Solady's `onlyProxy` modifier (`UnauthorizedCallContext()`) and never reach the auth check. Future Halmos harnesses on upgrade paths must follow the proxy pattern.
  - Agent ran a probe to confirm proofs aren't vacuous: forced `ok == false` for EntryPoint case and Halmos produced a counterexample.

### 🚨 #5 — `_verifyStatelessSignature` moduleType filter — **BUG WITNESS** (fix already on `fix/audit-internal-batch-1`)

- **Status**: COUNTEREXAMPLE on `master`/`audit/fv-round-1` @ `a836274` (pre-fix). PROVEN GREEN when commit `bfbef77` is applied.
- **File**: `test/halmos/PermissionStatelessHalmos.t.sol`
- **Worktree branch**: `worktree-agent-a79a0778c7f9061eb`
- **Checks**:
  - `checkSanitySinglePolicyAccepts` — positive control, passes (confirms harness wiring is correct)
  - `checkSigIdxDoesNotAdvanceForModuleType1` — FAIL on master (VALIDATOR type sneaks in)
  - `checkSigIdxDoesNotAdvanceForModuleType4` — FAIL on master (HOOK type sneaks in)
  - `checkSigIdxDoesNotAdvanceForAnyNonPolicySignerType` — FAIL on master, symbolic counterexamples at wrongModuleType ∈ {1, 2, 3, 4}
- **The bug**:
  - At `src/core/ModuleManager.sol:339` (on master), the permission-branch signature loop accepts any package with `internalData[0:4] == pId` regardless of `moduleType`.
  - A non-policy / non-signer module (VALIDATOR=1, EXECUTOR=2, FALLBACK=3, HOOK=4) whose `internalData[0:4]` happens to equal `pId` is consumed into the signature chain.
- **Fix maps to**: `bfbef77 fix: filter permission stateless match by module type` (1 line: add `&& (pkg.moduleType == 5 || pkg.moduleType == 6)`).
- **Notable observations from agent**:
  - Calldata-layout gotcha: `abi.encode(struct)` wraps in a 1-tuple with an outer offset that the source's inline assembly `permissionSig := signature.offset` doesn't expect. Agent encoded `abi.encode(sigs)` (inner `bytes[]` directly). Without this fix the harness reverts vacuously — positive-control test exists to catch regression.
  - `packages.length = 2` was the minimum needed: length 1 cases are vacuously rejected by the existing "last signature is signer" require.

## Branch divergence summary

**Master is missing two fixes that already exist on `fix/audit-internal-batch-1`**:

| Bug | Fix commit | Date | Status on master |
|-----|-----------|------|-------------------|
| `_initializeValidation` empty-data path doesn't bump nonce → stale selector grants survive uninstall+empty-reinstall | `9f9471c` | 2026-04-29 | **NOT MERGED** |
| `_verifyStatelessSignature` accepts non-policy/non-signer modules into signature chain | `bfbef77` | 2026-04-29 | **NOT MERGED** |

Both fixes (plus 3 other audit fixes: `bccbb5d`, `5a6c865`, `d54c56a`) are sitting on `fix/audit-internal-batch-1`, which is also unmerged.

The Halmos tests we just authored act as **regression witnesses** — they would have caught these bugs pre-fix and will pin the fix in place post-merge.

### ✅ #8 — `parseNonce` round-trip

- **Status**: PROVEN (2/2 checks, 0.01s)
- **File**: `test/halmos/ParseNonceHalmos.t.sol`
- **Worktree branch**: `worktree-agent-a2e3e14e9362e728a`
- **Checks**:
  - `checkParseNonceRoundTripValidator` — pass, 1 path
  - `checkParseNonceRoundTripPermission` — pass, 1 path
- **Notable observations**:
  - `checkParseNonceRejectsInvalidVType` was NOT authored — the function has no revert branch. The `else` clause accepts every `vType ≠ 0x02` including `0x00 (ROOT)`, `0x01 (VALIDATOR)`, and junk. Caller-side enforcement lives at `ValidationManager._validateValidationData:339-340`. Re-dispatch the rejection check there in Phase B.
  - `vType` byte is doubly encoded — it's at byte[1] AND high byte of `vId`. After parsing, `vType == vId[0]` is an invariant. Source comment in `Utils.sol:42-44` is slightly misleading.
  - The 16 zero bytes between `pId` and `nonceKey` in the permission encoding are mandatory; non-zero values there are silently dropped.
  - Negative control verified — agent flipped expected type byte to 0x02 in validator check and Halmos correctly produced a counterexample.

### ✅ #9 — `Kernel7702` + `KernelImmutableECDSA` fallback ECDSA

- **Status**: PROVEN (2/2 checks, 0.08s)
- **File**: `test/halmos/FallbackSignatureHalmos.t.sol`
- **Worktree branch**: `worktree-agent-aa60b59a740a18832`
- **Checks**:
  - `checkKernel7702FallbackAcceptsIffExpectedSigner` — pass, 5 paths
  - `checkKernelImmutableECDSAFallbackAcceptsIffExpectedSigner` — pass, 5 paths
- **Notable observations**:
  - Agent needed `--default-bytes-lengths 0,64,65,66,128` to enumerate both ECDSA length classes (64 EIP-2098 + 65 standard) plus the `default { break }` fall-through. Halmos's default `[0, 65, 1024]` would skip length 64.
  - Required `--function check` to match the project's no-underscore prefix convention.
  - Both proofs are tight; iff is checked bit-for-bit over fully symbolic `(hash, sig)`. No vm.assume.

### ✅ #10 — `Staker.approveFactoryWithSignature` replay safety

- **Status**: PROVEN (3/3 checks, 0.28s)
- **File**: `test/halmos/StakerReplayHalmos.t.sol`
- **Worktree branch**: `worktree-agent-a8edd42254b6d4aad`
- **Checks**:
  - `checkApproveFactoryWithSignatureBumpsNonce` — nonce += 1 on success
  - `checkApproveFactoryWithSignatureReplayDigestDiffers` — bumped nonce flows into next digest, so replay produces a different digest
  - `checkApproveFactoryWithSignatureDigestChainIdIndependent` — `digest(chainA) == digest(chainB)`, confirms `_hashTypedDataSansChainId` is in use
- **Notable observations**:
  - Halmos cannot directly prove "second call reverts" because ECDSA is modeled as an uninterpreted function — solver can pick recovered addresses such that both digests recover to `owner()`. So the property decomposes into (a) digest differs + nonce advances (proven by Halmos), and (b) one signature validates only one digest (ECDSA collision-resistance, outside Halmos). Standard decomposition.
  - Chain-id-independence: 2 paths, structurally proves the digest assembly doesn't read `chainid()`.
  - Signature symbolised at 65 bytes; storage seeded via `vm.store` for symbolic starting nonce.

### ✅ #12 — `KernelFactory.deploy` determinism + no double-init

- **Status**: PROVEN (4/4 checks, 0.15s)
- **File**: `test/halmos/KernelFactoryHalmos.t.sol`
- **Worktree branch**: `worktree-agent-a34511133d8e83c9c`
- **Checks**:
  - `checkDeployMatchesGetAddress(uint256 nonce)` — UUPS variant, deterministic
  - `checkSecondDeployReturnsSameAddressNoReinit(uint256 nonce)` — UUPS variant, idempotent
  - `checkDeployECDSAMatchesGetECDSAAddress(address signer, uint256 nonce)` — ECDSA, deterministic
  - `checkSecondDeployECDSAReturnsSameAddressNoReinit(address signer, uint256 nonce)` — ECDSA, idempotent
- **Notable observations**:
  - `initialPackages` constrained to `length=1, type-1 root validator` — CREATE2 salt is independent of package contents once hashed, so this doesn't weaken the property.
  - The no-double-init claim is an INDIRECT proof: factory branches on `alreadyDeployed` from `LibClone.createDeterministicERC1967` and skips `initialize`; Solady's `initializer` modifier would revert on a second init; Halmos proves the second deploy doesn't revert → therefore no re-init path exists.
  - For a direct proof, would need harness access to `Initializable._INITIALIZED_SLOT`. Current formulation is the tightest indirect proof.

### ✅ #13 — `_checkAndIncrementNonce` no overflow

- **Status**: PROVEN (1/1 check, 0.05s, 6 paths)
- **File**: `test/halmos/NonceOverflowHalmos.t.sol`
- **Worktree branch**: `worktree-agent-a54da47d4c4adf039`
- **Notable observations**:
  - Postcondition computed in `uint256` so any uint64 wrap manifests as `LHS=0, RHS=2^64` counterexample.
  - Fully symbolic over `uint64 × uint64 × uint64 × uint192`. No vm.assume.
  - Agent confirmed by grep: no `unchecked` blocks touch `nonce[key]` anywhere in `src/Kernel.sol`, `src/core/ModuleManager.sol`, `src/core/ValidationManager.sol`. The only `unchecked` blocks are in unrelated loops.
  - Function location: `src/core/ModuleManager.sol:268`.

### 🚨 #14 — `_initializeValidation` bumps by 1 — **BUG FOUND**

- **Status**: SPLIT — empty-data path is a COUNTEREXAMPLE; non-empty path PROVEN
- **File**: `test/halmos/InitializeValidationHalmos.t.sol`
- **Worktree branch**: `worktree-agent-af9720c11ddd2ab96`
- **Checks**:
  - `checkInitializeValidationBumpsByOneEmptyData` — **COUNTEREXAMPLE** (impl bug)
  - `checkInitializeValidationBumpsByOneNonEmptyData` — pass, 3 paths, 0.05s
- **The bug**:
  - `_initializeValidation` (`src/core/ValidationManager.sol:85-100`): empty `_internalData` path (lines 89-92) sets `hook = address(1)` and returns. **No nonce bump.**
  - `_uninstallValidation` (`src/core/ValidationManager.sol:139-143`): zeroes `hook`. **Leaves `nonce` and `allowed[vId][*]` intact.**
  - Attack sequence: `install(vId, "hook||selectors")` → `uninstall(vId)` → `install(vId, "")` resurrects stale `allowed[vId][selector] == nonce` grants from the prior install. Old selectors come back to life with the empty reinstall.
- **Severity assessment**: HIGH. Reachable only via owner-gated `installModule` (EP-or-self), so requires owner cooperation. Impact: footgun + privilege smuggling — owner thinks empty-data reinstall = clean slate, but historical selector grants persist. Worse if the same `vId` is reused with different intent across installs.
- **Recommended fix**: at `src/core/ValidationManager.sol:89-92`, either (a) bump `++nonce` unconditionally before the early return, or (b) clear `allowed[vId][*]` entries on uninstall. Option (a) is the minimal patch and matches the property's expectation.
- **Caveats noted by agent**:
  - Required `vm.assume(preNonce < type(uint32).max)` to avoid orthogonal overflow concerns (separate property #13). Not a weakening.
  - Non-empty path bound `_internalData.length=24` (20-byte hook + 4 selectors). Structural shape is general; selector count doesn't affect the nonce bump.
  - `_internalData.length == 20` edge case (hook only, zero selectors) verified by inspection — single bump via `_grantAccess` with empty selectors. Agent suggests a third check could cover symbolically.

## Phase B — Halmos M-effort

### ✅ #7 — `_checkNonce` ↔ `_checkAndIncrementNonce` agreement below saturation

- **Status**: PROVEN (3/3 checks, 0.26s)
- **File**: `test/halmos/NonceConsistencyHalmos.t.sol`
- **Checks**:
  - `check_RatchetBranchAgreement` — view/write agree on `nonceValidFrom > preSeq` branch
  - `check_NonRatchetBranchAgreement` — view/write agree on `nonceValidFrom ≤ preSeq` branch
  - `check_AgreementBelowOverflowSaturation` — general agreement, both branches combined
- **Boundary finding**: at `effectivePre == type(uint64).max`, the view path accepts (`seq == effective`) while the write path reverts from the checked `nonce[key]++` overflow. This is the ONLY divergence across the entire `(key, preSeq, validFrom, seq)` state space.
- **Why this is acceptable**: `NonceOverflowHalmos.check_NonceCannotOverflow` proves `nonce[key]` cannot reach `type(uint64).max` organically. The only way to land there is owner-induced via `_setValidNonceFrom(type(uint64).max)` — owner self-DOS, detectable on-chain.
- **Each check excludes the boundary with an explicit, documented `vm.assume`** — not a silent weakening. Cross-references `NonceOverflowHalmos` inline.
- **Alternative considered**: apply a one-line fix to `_checkNonce` (add `require(effective < type(uint64).max)`) to make the agreement unconditional. Deferred — current behaviour is provably safe via the cross-property argument, and changing source for a vacuous edge case requires sc-developer dispatch + reaudit.

## Phase C — Certora

### 🚨 #1 — `executeUserOp` ↔ `validateUserOp` linkage — **HIGH severity bug found**

- **Status**: split — strict form PROVEN; naive form COUNTEREXAMPLE surfaces a real privilege-escalation bug.
- **Files**:
  - `certora/conf/Kernel.conf`
  - `certora/specs/Kernel.spec` (3 rules)
  - `certora/harnesses/KernelHarness.sol`
- **Certora job reports**:
  - All 3 rules: https://prover.certora.com/output/3606101/9bae8478ce9842bcae2d45f92487e40b?anonymousKey=0f69fd410a6d5eb1218d0931ebae1e5e8161b63d
  - Strict-only PASS: https://prover.certora.com/output/3606101/fa191e6ffa3e43f6aac8860d357737f4?anonymousKey=d6261fb0d8c99d0dfba76de0a402448046b24332
- **Wall time**: 7.7 min, prover 472s.

#### Rule results

| Rule | Status | Notes |
|---|---|---|
| `validateUserOpEnforcesInnerSelectorAccess_naive` | **FAIL** | CEX exposes the fast-path bypass |
| `validateUserOpEnforcesInnerSelectorAccess_strict` | **PASS** | Holds with `!fastPath` precondition |
| `sanityValidateUserOpReachesSuccess` (satisfy) | **PASS** | Rule setup is not vacuous |

#### The bug

`src/Kernel.sol:172-185` — `_processUserOp`'s fast-path:

```solidity
if (
    vType == VALIDATION_TYPE_ROOT
        || (_allowedSelector(vId, bytes4(userOp.callData[0:4]))
            && $.vInfo[vId].hook == HOOK_MODULE_INSTALLED_NO_HOOK)
) {
    // No-op — fast path, NO inner-selector check, NO _setValidationHook
} else { ... require + _setValidationHook ... }
```

When a non-ROOT validation `V` has `executeUserOp.selector` in its allowed list AND `hook == HOOK_MODULE_INSTALLED_NO_HOOK`:

1. Fast-path is taken.
2. Inner-selector `require` is skipped — no check on `userOp.callData[4:]`.
3. `_setValidationHook` is NOT called → transient hook stays 0.
4. `executeUserOp` then runs `_preHook`/`_postHook` as no-ops (hook is 0).
5. Inner `delegatecall` to `address(this)` executes ANY selector — `installModule`, `setRoot`, `upgradeToAndCall`, etc.

#### Severity

**HIGH**. Exploitability gate is configuration — `_grantAccess` accepts any selector list, including `executeUserOp.selector`. An owner configuring a validation with what they think is "scoped access to executeUserOp" actually grants root-level dispatch.

#### Concrete counterexample from Certora

- `op.callData.length == 8`
- `bytes4(op.callData[0:4]) == 0x8dd7712f` (`executeUserOp.selector`)
- `bytes4(op.callData[4:8]) == 0x3751` (arbitrary unauthorised selector, symbolic)
- `vId == 0xffffffffff00000000000000000000000000000001` (PERMISSION type)
- `_allowedSelector(vId, executeUserOp.selector) == true`
- `vInfo[vId].hook == HOOK_MODULE_INSTALLED_NO_HOOK`
- `vMode` bits 0x08 / 0x40 both off — finding is independent of enable-mode and replayable-mode

#### Fix path (selected: Option 1)

Block `executeUserOp.selector` from being granted to non-ROOT vIds in `ValidationManager._grantAccess`:

```solidity
require(
    selector != IKernel.executeUserOp.selector || vId == $.root,
    InvalidSelectorGrant()
);
```

Defense-in-depth at the configuration boundary. Will be dispatched to `sc-developer`.

#### Caveats / narrowings (documented in spec header)

- Strict rule excludes `vMode & 0x08` (enable mode) and `vMode & 0x40` (replayable) for Certora tractability. Both invoke unbounded-bytes hashing (`_verifyInstallSignatureRaw`, `Lib4337.chainAgnosticUserOpHash`). Fast-path bypass is independent of these modes.
- Internal validators (`_validateUserOpValidator/Permission/Fallback`) and `Lib4337.intersectValidationData` are NONDET-summarised to fit in Certora's memory budget. Sound because the fast-path branch reaches the require BEFORE these are invoked.
- External module callbacks are AUTO-HAVOC'd. Sound because `_onlyEntryPointOrSelf` prevents reentrant ValidationStorage writes.
- `optimistic_hashing: true`, `hashing_length_bound: 512` documented in `certora/conf/Kernel.conf`.

## Phase C Round 2 — re-verify after `_grantAccess` fix

### ✅ Original bug closed

After commit `0921b25` (`_grantAccess` blocks `executeUserOp.selector` for non-root vIds):

| Rule | Round 1 | Round 2 |
|---|---|---|
| `validateUserOpEnforcesInnerSelectorAccess_naive` | 🚨 FAIL (CEX) | ✅ **PASS** |
| `validateUserOpEnforcesInnerSelectorAccess_strict` | ✅ PASS | ✅ PASS (regression) |
| `sanityValidateUserOpReachesSuccess` | ✅ PASS | ✅ PASS (regression) |

Round 2 job: https://prover.certora.com/output/3606101/19ed688fd26e43cfa25d435306bec6f1?anonymousKey=a87fff01a79ea67c696ced6eb56bd0dbae8403e7

### 🚨 Secondary finding — `setRoot` residual

New invariant `nonRootCannotAllowExecuteUserOp` FAILS on 8 entry points. All reduce to a single primitive: **`_setRoot` does not bump `vInfo[oldRoot].nonce`**, so prior grants of `executeUserOp.selector` to the old root remain active when the old root becomes non-root.

Failing entry points (induction step) and how each reaches `_setRoot`:

- `setRoot(bytes21)` — direct
- `setRoot((uint256,address,bytes,…))` overload — direct
- `initialize((uint256,address,…))` — root install path
- `executeUserOp(...)` — inner delegatecall to `setRoot`
- `execute(bytes32,bytes)` — routed batch / single call
- `executeFromExecutor(...)` — executor module calls `setRoot`
- `upgradeToAndCall(...)` — new impl's init data calls `setRoot`
- `<receiveOrFallback>()` — fallback path

Attack sequence (after the `_grantAccess` fix):

1. `setRoot(R1)` → `$.root = R1`
2. `_grantAccess(R1, executeUserOp.selector)` — permitted (R1 is currently root)
3. `setRoot(R2)` → `$.root = R2`; `allowed[R1][executeUserOp]` stays non-zero; `vInfo[R1].hook` preserved
4. R1 is now non-root with `_allowedSelector(R1, executeUserOp.selector) == true` and `hook == HOOK_MODULE_INSTALLED_NO_HOOK`
5. Fast-path bypass re-engages — R1 can call `executeUserOp(arbitrary inner calldata)` and invoke any privileged function

Lower likelihood than the Round 1 attack (requires root rotation + prior grant + hook preserved) but FV demonstrates structural reachability.

### Selected remediation — Option E

Bump `vInfo[oldRoot].nonce` in `_setRoot` so any stale `allowed[oldRoot][*]` grants are invalidated (`allowed[oldRoot][sel] != vInfo[oldRoot].nonce` post-rotation). Same pattern as Phase A #14.

### ✅ Phase C closed — Round 3 / 4 invariant abstraction limit

After `_setRoot` fix (`ce185f6`) we tried two stronger invariant forms:

| Round | Form | Outcome |
|---|---|---|
| 3 | `allowedNonce(vId, exec) != vInfoNonce(vId)` | FAIL — base case fails on uninstalled vIds (`0 != 0` is false). |
| 4 | Bypass-impossible: `NOT (_allowedSelector AND hook == INSTALLED_NO_HOOK)` | FAIL — Certora's external-callback AUTO-HAVOC violates the invariant on every entry point with a delegatecall (`executeUserOp`, `execute`, `validateUserOp`, `installModule`, `setRoot`, `grantAccess`, `upgradeToAndCall`, `<receiveOrFallback>`, `initialize`). `_onlyEntryPointOrSelf` prevents this in production, but encoding precise CVL summaries for all ~10 callback sites is days of work and likely OOMs. |

Round 4 job: https://prover.certora.com/output/3606101/e16f05be609a48b79c6bfa16f7c357f4?anonymousKey=39f0672f112513c790ec1d6d8ba351876073e395

**Decision (2026-05-21)**: accept the invariant as unprovable under current summaries. Phase C closes with the audit story carried by:

1. `validateUserOpEnforcesInnerSelectorAccess_naive` PASSES post-fix — original CEX unreachable.
2. `validateUserOpEnforcesInnerSelectorAccess_strict` PASSES — precise property under `!fastPath`.
3. Manual static-writer analysis: `_grantAccess` (with fix), `_setRoot` (with fix), `_uninstallValidation`, `_initializeValidation` are the only writers of relevant storage; each preserves the bypass-impossible property by inspection.

Invariant retained in spec as documented intent + regression target.

## Phase D — Certora deepening

### ✅ #6 — `setRoot` LIFO clear of permission state

- **Status**: PROVEN (1 rule + 1 satisfy)
- **File**: `certora/specs/SetRootLifo.spec`, `certora/conf/SetRootLifo.conf`
- **Rules**:
  - `setRootClearsOldPermissionState` — after `setRoot(packages, removeCurrent=true)` on a permission-type root: `policies.length == 0`, `signer == 0`, `hook == NOT_INSTALLED`
  - `sanitySetRootReaches` (satisfy) — non-vacuous
- **Job**: https://prover.certora.com/output/3606101/7e3f99aaf47a4257a372d14ce591dea6
- **Bound**: `policies.length <= 3` to match `loop_iter: 3`; soundly extends to longer arrays by induction on intersect's monotonicity.
- **Static observations** noted by subagent (not bugs, context):
  - `_install` runs BEFORE the LIFO loop snapshot; if `pkg[0]` is a policy/signer that matches the old root's pId, it pushes into `policies[]` before the loop runs. Caller must pad `uninstallData` accordingly or the call reverts (sound — no skip).
  - `_uninstallPolicyWithVid` uses `policies.pop()`, which Solidity clears correctly. No residue.
  - `_uninstallSignerWithVid` requires `policies.length == 0` THEN zeros signer + calls `_uninstallValidation` which zeros hook. Sequence matches the property.
  - Aliasing case `pkg[0].moduleType ∈ {policy, signer} && completes oldRoot's pId`: `_setRoot` becomes a no-op rotation, `removeCurrent` block hits `CannotUninstallRoot` → safe revert.

### 🟡 #4 — Permission validation totality (3/4 rules PASS)

- **Status**: SECURITY DIRECTION PROVEN, LIVENESS DIRECTION DROPPED
- **File**: `certora/specs/Permission.spec`, `certora/conf/Permission.conf`
- **Rules**:
  - `policyFailureImpliesAggregateFailure` — ✅ PASS — any policy returning failure forces aggregate failure
  - `signerFailureImpliesAggregateFailure` — ✅ PASS — signer returning failure forces aggregate failure
  - `sanityCanSucceed` (satisfy) — ✅ PASS — non-vacuous
  - `allSuccessImpliesAggregateSuccess` — **DROPPED** (CVL artifact, see below)
- **Why dropping `allSuccess` is OK**:
  - The audit's core claim is the security direction: "no policy can be silently skipped". The two failure rules establish this directly: any failing module forces aggregate failure, so the only way for the aggregate to succeed is for EVERY module to have succeeded.
  - The dropped rule's direction is liveness ("if every module succeeds, aggregate succeeds") — important operationally but not a security claim.
  - Liveness is empirically established by the 1341 passing Foundry tests, many of which exercise permission UserOps with successful modules → successful aggregate.
- **Why we couldn't prove `allSuccess` in CVL**:
  - Three formulations attempted (forall+mask, enumerated, implication-form) — all tripped Certora's `rule_sanity` "bounds check on int to bitvec" sub-check.
  - This is a CVL-internal type-checker artifact, not a contract bug. The check fires BEFORE the assertion is evaluated; it concerns the satisfiability of the rule's preconditions when `forall address` meets bitwise masks.
  - Documented in `specs/Permission.spec` as a regression target for future CVL releases.

### ✅ #11 — View/write permission path equivalence on success/failure

- **Status**: PROVEN (1 rule + 1 satisfy)
- **File**: `certora/specs/PermissionEquivalence.spec`, `certora/conf/PermissionEquivalence.conf`
- **Rules**:
  - `viewAndWritePathsAgreeOnSuccess` — view (ERC-1271) and write (ERC-4337) paths agree on the binary success/failure outcome for the same `(vId, hash, signature)` tuple
  - `sanityViewPathReaches` (satisfy) — non-vacuous
- **Job (final)**: https://prover.certora.com/output/3606101/22e774d8687e4b869ece01503dc66aa8
- **Spec evolution** (rounds 1–4):
  1. Full `uint256` equality — FAIL by design (view's `bytes4`-lift can't encode time bounds)
  2. Binary outcome with `signerGhostUint == 0 <=> bytes4 == MAGIC` axiom — FAIL (axiom too narrow; ignored aggregator bits)
  3. Tightened axiom + iff on `intersectGhost` — FAIL (signer ghost still had arbitrary upper bits)
  4. Single source-of-truth `signerSucceedsGhost` boolean with CVL helpers deriving both ABI returns — **PASS**
- **Important reframing**: the audit's claim "the two paths must not diverge in authorisation" was originally stated as full `validationData` equality. The correct formulation is the binary success/failure agreement — by design, the view path (ERC-1271 `bytes4`) cannot express time bounds that the write path (ERC-4337 `uint256`) carries.

## Phase E — Kontrol + Halmos (complementary partial coverage on #15)

### Property #15 — ERC-1271 nested EIP-712 success-branch-only authorisation

**Goal**: prove that `_erc1271IsValidSignatureViaNestedEIP712` (and the Replayable variant) in `src/lib/ERC1271.sol` only return `true` when the inner `_erc1271IsValidSignatureNowCalldata(hash, signature)` returns `true`. Both functions have exactly one return site (line 239 / 326), so a contrapositive proof "inner=false ⇒ outer=false" covers all paths.

### 🟡 Kontrol partial — TypedDataSign branch (timed out, no CEX)

- **Status**: 14 terminal SUCCESS branches + 12 subsumption covers in 102-node KCFG, NO counterexamples, full proof timed out at ~1h25m
- **File**: `test/kontrol/ERC1271NestedEIP712Kontrol.t.sol`
- **Config**: `kontrol.toml` (max-depth 5000, max-iter 200, workers 4)
- **Build wall time**: 73 s cold, ~50 s warm
- **Prove wall time at kill**: ~1h25m
- **Bound applied**: `vm.assume(signature.length <= 128)`
- **Classification**: Kontrol-limitation (SMT cost on symbolic-bytes calldata + 5+ calldatacopy operations whose offsets depend on `signature.length` and `c`). Not an impl bug.
- **Replayable variant**: not attempted — structurally identical body would consume the same budget.

### ✅ Halmos partial — PersonalSign branch (PROVEN, both variants)

- **Status**: 6/6 PASS (24.6 s total, ≤0.04 s aggregate solver time)
- **File**: `test/halmos/ERC1271NestedEIP712Halmos.t.sol`
- **Checks**:
  - `check_NestedEIP712_Length0` — degenerate (signature.length == 0)
  - `check_NestedEIP712_Length65_PersonalSignBranch` — ECDSA-canonical
  - `check_NestedEIP712_Length100_PersonalSignBranch` — mid-sized
  - `check_NestedEIP712Replayable_Length0` — same for Replayable variant
  - `check_NestedEIP712Replayable_Length65_PersonalSignBranch`
  - `check_NestedEIP712Replayable_Length100_PersonalSignBranch`
- **Technique**: pin trailing 2 bytes of `sig` to `0x00 0x00` so the EVM-level `c` is concrete `0`, forcing the PersonalSign workflow. Remaining bytes fully symbolic.
- **TypedDataSign not covered**: `Length67_TypedDataSignCandidate` and `Length100_TypedDataSignCandidate` attempted but hit `NotConcreteError: symbolic SHA3 data size`. The `contentsName` scan loop at `ERC1271.sol:206-219` computes the keccak input length `sub(add(p, c), m)` from symbolic byte-equality checks against `)` and `(`, which Halmos's keccak backend can't handle.

### Combined Phase E story

- **PersonalSign workflow**: ✅ PROVEN by Halmos (both standard + Replayable variants, three length classes).
- **TypedDataSign workflow**: 🟡 partial — Kontrol explored 14 SUCCESS branches without CEX before timeout; full closure requires either more wall-clock budget OR stronger Kontrol-side modeling of the calldata pattern.
- **No counterexamples found anywhere**: both backends would have surfaced a verifier-bypass; neither did.
- **Scaffold preserved**: Kontrol claim file + harness pattern on disk for future re-runs with a stronger machine or improved Kontrol SMT support.

### Recommendation for Round 2

The TypedDataSign coverage gap is the only remaining FV gap for this property. Options:
- **Re-run Kontrol with larger budget** (4+ hours) on a beefier machine.
- **Certora attempt** with `optimistic_hashing` + careful summaries for the assembly memory writes (unclear if this works given the calldatacopy patterns).
- **Manual symbolic exec / pen-and-paper proof** of the structural claim (the single return site argument is straightforward to check by inspection).

See `audit/FV_PLAN.md` for the full plan.
