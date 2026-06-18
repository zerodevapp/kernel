# Kernel v4 — Formal Verification Round 1 Plan

> **Branch**: `audit/fv-round-1` (off `master` @ `a836274`)
> **Base plan**: [`audit/fv-gap-audit.md`](./fv-gap-audit.md) — orchestrator's gap audit & dispatch decisions
> **Status as of 2026-05-20**: Phase A dispatched in parallel; B–E queued.

## Baseline note (important for subagents)

The orchestrator surveyed `fix/audit-internal-batch-1` which has 14 Halmos files. **This branch (master) has only `test/halmos/KernelExecutorHalmos.t.sol`.** Subagents should:

1. Treat the existing file as the file-naming + import convention (`SymTest`, `Test`, `MockCallee`, etc.).
2. Create new Halmos files alongside it; do not assume sibling files exist.
3. Mocks live in `test/mock/*.sol` and EntryPoint helper in `test/utils/EntryPointLib.sol`.
4. **No `halmos.toml` exists yet** — `/setup-halmos` skill can be invoked if a subagent wants one, but the existing file works without it.

### Project-specific Halmos quirks (encoded from project memory)

- Halmos v0.3.3. Prefix is `check…` / `invariant…` (no underscore in existing file). Match it.
- Run `forge clean` before `halmos` — artifacts may lack AST otherwise.
- `vm.expectRevert(bytes4)` is unsupported. Use `try { …; assert(false); } catch {}` or `(bool ok,) = …; assertFalse(ok);`.
- Moving `new Contract()` inside `vm.expectRevert` scope captures the constructor, not the call.

## Goals

- Land **10 new Halmos proofs** covering the highest-severity un-touched areas on `master`.
- Land **4 Certora proofs** for multi-step + unbounded-data claims that Halmos can't reach.
- Land **1 Kontrol proof** (or accept a Halmos partial) for heavy-assembly ERC-1271 nested EIP-712.
- Do **not** introduce Tama or Clear in this round (post-release v4 cost-benefit doesn't justify).

## Phase A — Halmos S-effort properties (in flight, parallel)

| #  | Property                                                                                                                                                          | File to create                                  | Owner subagent                  | Status     |
| -- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------------- | ---------- |
| 2  | `Lib4337.intersectValidationData` preserves aggregator authority across all six precedence rules.                                                                 | `test/halmos/Lib4337Halmos.t.sol`               | sc-fv-halmos #1                 | dispatched |
| 3  | `KernelUUPS.upgradeToAndCall` reverts unless `msg.sender == ENTRYPOINT \|\| msg.sender == address(this)`.                                                         | `test/halmos/KernelUUPSHalmos.t.sol`            | sc-fv-halmos #2                 | dispatched |
| 5  | `_verifyStatelessSignature` cannot consume a non-policy / non-signer module into the permission's signature chain (the `bfbef77` regression).                     | `test/halmos/PermissionStatelessHalmos.t.sol`   | sc-fv-halmos #3                 | dispatched |
| 8  | `parseNonce` round-trip recovers `(vMode, vType, vId)` for both `VALIDATION_TYPE_VALIDATOR` and `VALIDATION_TYPE_PERMISSION`.                                     | `test/halmos/ParseNonceHalmos.t.sol`            | sc-fv-halmos #4                 | dispatched |
| 9  | `Kernel7702` and `KernelImmutableECDSA` fallback signature accept iff `ECDSA.tryRecoverCalldata(hash, sig) == expectedSigner`.                                    | `test/halmos/FallbackSignatureHalmos.t.sol`     | sc-fv-halmos #5                 | dispatched |
| 10 | `Staker.approveFactoryWithSignature` is replay-safe (second call with same `(factory, approval, signature)` reverts) and EIP-712 digest is chain-agnostic.        | `test/halmos/StakerReplayHalmos.t.sol`          | sc-fv-halmos #6                 | dispatched |
| 12 | `KernelFactory.deploy` / `deployECDSA` are deterministic and idempotent (no double-init on second call).                                                          | `test/halmos/KernelFactoryHalmos.t.sol`         | sc-fv-halmos #7                 | dispatched |
| 13 | `_checkAndIncrementNonce` cannot overflow `uint64` (defensive spec property; practically unreachable).                                                            | `test/halmos/NonceOverflowHalmos.t.sol`         | sc-fv-halmos #8                 | dispatched |
| 14 | `_initializeValidation` bumps `vInfo[vId].nonce` by exactly 1 in both the empty-`_internalData` and non-empty paths (no double-bump, no zero-bump).               | `test/halmos/InitializeValidationHalmos.t.sol`  | sc-fv-halmos #9                 | dispatched |

Each subagent: writes one Halmos file, runs Halmos to green, returns structured findings (no commits — `/commit` skill handles git in a follow-up pass).

## Phase B — Halmos M-effort (queued)

| #  | Property                                                                                          | File                                | Status |
| -- | ------------------------------------------------------------------------------------------------- | ----------------------------------- | ------ |
| 7  | `_checkNonce` (view) and `_checkAndIncrementNonce` (write) agree on which `seq` is acceptable under the `nonceValidFrom` ratchet. | `test/halmos/NonceConsistencyHalmos.t.sol` | queued |

Trigger condition: Phase A all green.

## Phase C — Certora harness + #1 (queued)

- Invoke `/setup-certora` to install certora-cli, scaffold `certora/`, configure `CERTORAKEY`.
- Dispatch `sc-fv-certora` on property #1: `executeUserOp`'s inner delegatecall is gated by `validateUserOp` having authorised the outer UserOp under a validation owning the inner selector.
- Expected: `certora/conf/Kernel.conf`, `certora/specs/Kernel.spec`, one rule.

Trigger condition: Phase A green + user approval.

## Phase D — Certora deepening (queued)

| #  | Property                                                                                          | Status |
| -- | ------------------------------------------------------------------------------------------------- | ------ |
| 4  | Permission validation totality across the unbounded `policies[]` array, AND signer ERC-1271 must succeed. | queued |
| 6  | `setRoot(packages, removeCurrent=true)` LIFO uninstall fully clears the old root's state. | queued |
| 11 | `_verifySignaturePermission` (view) and `_validateUserOpPermission` (write) return the same aggregate `validationData`. | queued |

Trigger condition: Phase C harness up.

## Phase E — Kontrol experiment (queued)

| #  | Property                                                                                          | Status |
| -- | ------------------------------------------------------------------------------------------------- | ------ |
| 15 | `_erc1271IsValidSignatureViaNestedEIP712` only authorises on the explicit success branch (no spurious accepts from assembly path). | queued |

Trigger condition: Phase A green. May demote to "Halmos partial" if Kontrol setup is too costly.

## Not in scope for Round 1

- **Tama / Clear**: rewrite cost (Tama) and Yul-extraction setup (Clear) not justified for post-release v4 with `via_ir = false`. Reserve for v5 or new greenfield modules.
- **`supportsExecutionMode` exhaustiveness**, **validator-path hook bracketing**, **`isModuleInstalled` for type 7+**: either already proven on `fix/audit-internal-batch-1` (will be pulled forward separately) or out-of-band severity.
- **Gas semantics, full ERC-4337 EntryPoint replay**: belong to integration / fuzz / BTT layers, not FV.

## Commit & PR plan

- Each Phase A subagent writes its own file. No commits during dispatch.
- After all 9 land green: team lead invokes `/commit` skill once per file (per the working-tree-discipline rule — never bundle multi-file Halmos additions through one `/commit` call when files share `test/halmos/` and may need to be split).
- After Phase A commits: `/create-pr` opens PR against `master` from `audit/fv-round-1`.
- Phase B, C, D, E may be separate branches/PRs to keep review tractable.

## Tracking

- This file (`audit/FV_PLAN.md`) is the live status board.
- Per-property findings land back from subagents and get logged in `audit/fv-round-1-findings.md` (created on first finding).
- The orchestrator's reasoning is preserved verbatim in `audit/fv-gap-audit.md`.

## How to resume

If the session ends mid-Phase-A, the next session can:

1. Read `audit/FV_PLAN.md` (this file).
2. Check `git status` for any test files left in the working tree — those mark partial progress.
3. Re-dispatch `sc-fv-halmos` on any property whose target file is missing or whose `forge build && halmos --match-contract <Name>` fails.
4. When Phase A is all green, ask the user whether to proceed to Phase B (Halmos M) or jump to Phase C (Certora setup).
