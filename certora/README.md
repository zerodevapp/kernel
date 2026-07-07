# Certora — Kernel v4

Formal verification harness for properties that need multi-step traces or unbounded-array quantification (out of Halmos's reach).

## Layout

```
certora/
├── conf/        # certoraRun config (JSON)
├── specs/       # CVL rules + invariants
└── harnesses/   # Solidity wrappers when storage/inheritance tricks are needed
```

## Running

```bash
# 1) Activate the venv (certora-cli is installed there)
source ~/.certora-venv/bin/activate

# 2) Export the API key. Certora expects CERTORAKEY (no underscore); this
#    repo's machine has it under CERTORA_KEY — alias before running.
export CERTORAKEY="$CERTORA_KEY"

# 3) Verify Java 21+ is on PATH (Temurin recommended)
java --version

# 4) Run from repo root
certoraRun certora/conf/Kernel.conf
```

The run uploads to Certora cloud and prints a job URL. Open it for the report.

## Property #1 — executeUserOp ↔ validateUserOp linkage

`conf/Kernel.conf` is wired for property #1 from `audit/fv-gap-audit.md`:

> `executeUserOp`'s inner delegatecall to `address(this)` cannot execute any
> privileged kernel function unless `validateUserOp` already authorised the
> outer UserOp under a validation that owns the inner selector.

### Results (FV Round 1, Phase C — pre-fix)

| Rule | Status | Notes |
|---|---|---|
| `validateUserOpEnforcesInnerSelectorAccess_naive` | **FAIL** | CEX surfaced the fast-path bypass implementation finding |
| `validateUserOpEnforcesInnerSelectorAccess_strict` | **PASS** | Property held when the fast-path was explicitly excluded |
| `sanityValidateUserOpReachesSuccess` | **PASS** (satisfy) | Confirmed the rule setup was not vacuous |

Pre-fix job: `d52ccad8f4964f21b2e025a64b9292d3` (~7.5 min prover time, 8.13.1).

### Results (FV Round 2 — post-`_grantAccess`-fix, commit `0921b25`)

After the fix at commit `0921b25` (`src/core/ValidationManager.sol` —
`_grantAccess` blocks `executeUserOp.selector` for non-root vIds):

| Rule / Invariant | Status | Notes |
|---|---|---|
| `validateUserOpEnforcesInnerSelectorAccess_naive` | ✅ **PASS** | The original CEX witness is now structurally unreachable. The fix closes the immediate attack. |
| `validateUserOpEnforcesInnerSelectorAccess_strict` | ✅ **PASS** | Regression — still holds with `!fastPath` precondition. |
| `sanityValidateUserOpReachesSuccess` (satisfy) | ✅ **PASS** | Rule setup is not vacuous. |
| `nonRootCannotAllowExecuteUserOp` (invariant) | 🚨 **FAIL** | Secondary finding — root rotation leaves `allowed[oldRoot][executeUserOp]` non-zero. See breakdown below. |

Round 2 job URL: https://prover.certora.com/output/3606101/19ed688fd26e43cfa25d435306bec6f1?anonymousKey=a87fff01a79ea67c696ced6eb56bd0dbae8403e7

#### Secondary finding — `setRoot` residual

Certora's induction step on the invariant `nonRootCannotAllowExecuteUserOp` produced CEXes on 8 entry points. All 8 reduce to a single primitive: **`_setRoot` does not bump `vInfo[oldRoot].nonce`**, so any prior grant of `executeUserOp.selector` to the old root remains active when the old root becomes non-root.

Failing methods (induction step) and how each reaches `_setRoot`:

| Method | Path to `_setRoot` |
|---|---|
| `setRoot(bytes21)` | Direct |
| `setRoot((uint256,address,bytes,…))` (overload via install) | Direct |
| `initialize((uint256,address,bytes,…))` | Root install path |
| `executeUserOp((address,uint256,…))` | Inner delegatecall to `address(this).setRoot(...)` |
| `execute(bytes32,bytes)` | Batch / single call routed to `setRoot` |
| `executeFromExecutor(bytes32,…)` | Executor module calls `setRoot` |
| `upgradeToAndCall(address,…)` | New implementation's init data calls `setRoot` |
| `<receiveOrFallback>()` | Fallback path routes to `setRoot` |

Selected remediation: **Option E** — bump `vInfo[oldRoot].nonce` in `_setRoot` so stale `allowed[oldRoot][*]` grants become unreachable (`allowed[oldRoot][sel] != vInfo[oldRoot].nonce` post-rotation). Same pattern as the Phase A #14 fix. Applied at commit `ce185f6`.

### Round 3 / 4 — invariant abstraction limit (Phase C closure)

After the `_setRoot` fix we tried two stronger invariant formulations:

| Round | Invariant form | Result |
|---|---|---|
| 3 | `allowedNonce(vId, exec) != vInfoNonce(vId)` for non-root vId | FAIL — base case (uninstalled vIds have both sides = 0, so `0 != 0` is false). Helper invariant `installedValidationsHaveNonzeroNonce` timed out at 96 min on one induction step. |
| 4 | Bypass-impossible form: `NOT (_allowedSelector(vId, exec) AND hook == INSTALLED_NO_HOOK)` for non-root vId | FAIL — Certora's NONDET / AUTO-HAVOC abstraction for external module callbacks lets it imagine arbitrary writes to ValidationStorage on every entry point that involves a delegatecall or callback (`executeUserOp`, `execute`, `validateUserOp`, `installModule`, `setRoot`, `grantAccess`, `upgradeToAndCall`, `<receiveOrFallback>`, `initialize`). `_onlyEntryPointOrSelf` prevents this reentrant write in production, but encoding that as precise CVL summaries for ~10 sites is days of work and likely OOMs. |

Round 4 job URL: https://prover.certora.com/output/3606101/e16f05be609a48b79c6bfa16f7c357f4?anonymousKey=39f0672f112513c790ec1d6d8ba351876073e395

**Decision (2026-05-21)**: accept the invariant as unprovable under the current CVL summary set. The audit story is carried by:

1. `validateUserOpEnforcesInnerSelectorAccess_naive` PASSES (post-fix) — the original CEX witness is unreachable.
2. `validateUserOpEnforcesInnerSelectorAccess_strict` PASSES — precise property under `!fastPath` precondition.
3. Manual static-writer analysis: `_grantAccess` (with fix), `_setRoot` (with fix), `_uninstallValidation`, and `_initializeValidation` are the only writers of `allowed[]`, `vInfo`, and `$.root`. Each preserves the bypass-impossible property by inspection.

The invariant statement is retained in `specs/Kernel.spec` as documented intent and a regression target for future runs with stronger summaries.

### Implementation finding addressed by commit 0921b25

The fast-path branch in `_processUserOp` (Kernel.sol lines 172-176) bypassed the
inner-selector `require` when ALL of the following held:

- `vType != ROOT`,
- `_allowedSelector(vId, outerSel)` was true with `outerSel == executeUserOp.selector`,
- `vInfo[vId].hook == HOOK_MODULE_INSTALLED_NO_HOOK`.

When this happened, `_setValidationHook` was never called, the transient hook
stayed at 0, and `executeUserOp`'s inner delegatecall ran with NO selector
check — handing a non-ROOT validation the equivalent of root privileges.

**Fix (commit 0921b25)**: in `_grantAccess`, reject `executeUserOp.selector`
for non-root vIds:

```solidity
require(selector != IAccountExecute.executeUserOp.selector || vId == $.root, InvalidSelectorGrant());
```

`_grantAccess` is the sole writer of `$.allowed` (verified by static grep
over `src/`), so the new structural invariant
`nonRootCannotAllowExecuteUserOp` should hold for any reachable state. The
naive rule, which witnessed the pre-fix CEX, now uses `requireInvariant`
over this invariant and is expected to pass.

**Secondary concern to watch for**: if the invariant FAILS with a CEX
involving `setRoot`, that would indicate a residual hazard — root rotation
could leave the prior root's `allowed[oldRoot][executeUserOp]` non-zero
while the new root is different. Whether that is exploitable depends on
whether the prior root can still be used as a non-root validator after
rotation. Report any such CEX honestly to the orchestrator.

## Phase D — Certora deepening (3 properties)

### #4 — Permission validation totality

| Rule | Status | Notes |
|---|---|---|
| `policyFailureImpliesAggregateFailure` | ✅ PASS | If any policy returns failure, the aggregate is failure. |
| `signerFailureImpliesAggregateFailure` | ✅ PASS | If the signer returns failure, the aggregate is failure. |
| `sanityCanSucceed` (satisfy) | ✅ PASS | Non-vacuous: a non-reverting call exists. |
| `allSuccessImpliesAggregateSuccess` | **DROPPED** | Liveness direction — Certora's "sanity bounds check on int to bitvec" tripped on every CVL formulation attempted (forall+mask, enumerated, implication-form). Audit's security claim ("no policy silently skipped") is fully carried by the two failure rules. Documented in `specs/Permission.spec`. |

Files: `certora/specs/Permission.spec`, `certora/conf/Permission.conf`.

### #6 — `setRoot` LIFO clear of permission state

| Rule | Status |
|---|---|
| `setRootClearsOldPermissionState` | ✅ PASS |
| `sanitySetRootReaches` (satisfy) | ✅ PASS |

After `setRoot(packages, removeCurrent=true)` on a `VALIDATION_TYPE_PERMISSION` root, the old root's `policies.length == 0`, `signer == 0`, and `hook == HOOK_MODULE_NOT_INSTALLED`. LIFO loop bound at `policies.length <= 3`.

Files: `certora/specs/SetRootLifo.spec`, `certora/conf/SetRootLifo.conf`.

### #11 — View/write permission path equivalence

| Rule | Status | Notes |
|---|---|---|
| `viewAndWritePathsAgreeOnSuccess` | ✅ PASS | View (ERC-1271) and write (ERC-4337) paths agree on the success/failure binary outcome. |
| `sanityViewPathReaches` (satisfy) | ✅ PASS | Non-vacuous. |

Notable spec evolution (Rounds 1-4):
1. Full `uint256` equality assertion — FAIL by design (view path's `bytes4`-lift cannot represent ERC-4337 time bounds).
2. Binary outcome with `signerGhostUint == 0 <=> bytes4 == MAGIC` axiom — FAIL (axiom too narrow; ignored aggregator bits).
3. Tightened axiom to `AGG_OK(signerGhostUint) <=> bytes4 == MAGIC` + iff on intersectGhost — FAIL (signer ghost still had arbitrary upper bits).
4. Single source-of-truth `signerSucceedsGhost` boolean with CVL helper functions deriving both ABI returns — **PASS**.

Files: `certora/specs/PermissionEquivalence.spec`, `certora/conf/PermissionEquivalence.conf`.

## Round 2 — Phase C invariant closure (writer-local decomposition)

The Round 1 global invariant `nonRootCannotBypassFastPathWithExecuteUserOp` in `specs/Kernel.spec` is replaced for verification purposes by **four writer-local rules** in `specs/PhaseCWriterLocal.spec`:

| Rule | Status |
|---|---|
| `grantAccessPreservesNonBypass` | ✅ PASS |
| `setRootPreservesNonBypass` | ✅ PASS |
| `uninstallValidationPreservesNonBypass` | ✅ PASS |
| `initializeValidationPreservesNonBypass` | ✅ PASS |
| 4 corresponding `sanity*` rules | ✅ PASS (all 4) |

Job: https://prover.certora.com/output/3606101/37e8675776484e4998f16f528d2dd29a

**Implication chain** (documented in `specs/PhaseCWriterLocal.spec` docstring; not formally proven in CVL but verified by grep over `src/`): the four functions are the ONLY paths that write `$.allowed`, `$.vInfo[*].nonce`, `$.vInfo[*].hook`, or `$.root`. Genesis state trivially satisfies the bypass-impossible property. Each writer preserves it. Therefore by structural induction, every reachable state satisfies it. The conjunction of the 4 local rules + static-writer-completeness ⇒ the original global property.

The original `Kernel.spec` invariant remains as documented intent + regression target for future Certora releases with stronger summaries.

## Pitfalls baked in

- `optimistic_loop: true` + `loop_iter: 3`.
- `optimistic_hashing: true` + `hashing_length_bound: 512` — required because
  `_verifyInstallSignatureRaw` and `Lib4337.chainAgnosticUserOpHash` hash
  unbounded bytes.
- `solc_via_ir: false` — matches the project's `foundry.toml` (contract-size
  constraint).
- Internal summaries (`_validateUserOpValidator/Permission/Fallback`,
  `_verifyInstallSignatureRaw`, `Lib4337.chainAgnosticUserOpHash`,
  `Lib4337.intersectValidationData`) are NONDET — without them Certora OOMs
  on the full validateUserOp TAC graph (60GB+ memory).
- Rules constrain `vMode` bits 0x08 (enable mode) and 0x40 (replayable). The
  fast-path bypass is independent of those, so the finding stands.
- Remappings duplicate the project's `remappings.txt` via the `packages` array.
- Soldeer is used for deps — paths under `dependencies/`.

## Files

- `conf/Kernel.conf` — verifyer config (verifies `KernelHarness`).
- `specs/Kernel.spec` — CVL rules.
- `harnesses/KernelHarness.sol` — read-only accessors over namespaced storage
  and pure helpers; extends `KernelUUPS`. Does not modify production logic.
