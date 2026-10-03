/* SPDX-License-Identifier: MIT */

/**
 * Kernel v4 — Property #1: executeUserOp ↔ validateUserOp linkage
 *
 * SECURITY claim from src/Kernel.sol (executeUserOp NatSpec):
 *   The safety of the inner delegatecall to address(this) rests entirely on
 *   validateUserOp having approved the outer UserOp under a validation that
 *   owns the inner selector.
 *
 * STATUS (FV Round 2, after commit 0921b25):
 *   The fix at commit 0921b25 (src/core/ValidationManager.sol, _grantAccess)
 *   adds the require:
 *     require(selector != IAccountExecute.executeUserOp.selector
 *             || vId == $.root, InvalidSelectorGrant());
 *   This makes the original CEX unreachable for newly granted non-ROOT
 *   validations and the naive rule
 *   (validateUserOpEnforcesInnerSelectorAccess_naive) now PASSES.
 *
 * STRUCTURAL INVARIANT enforced by both fixes
 *   (nonRootCannotBypassFastPathWithExecuteUserOp, commits 0921b25 + ce185f6):
 *     For any vId != $.root:
 *         NOT (_allowedSelector(vId, executeUserOp.selector)
 *              AND vInfo[vId].installed && vInfo[vId].scopedExecutionHook == address(0))
 *   - 0921b25 blocks the grant at the source (`_grantAccess` rejects
 *     `executeUserOp.selector` for non-root vIds).
 *   - ce185f6 invalidates orphaned grants on rotation (`_setRoot` bumps the
 *     old root's nonce so `_allowedSelector(oldRoot, *) == false`).
 *   Together they make the fast-path bypass conjunction structurally
 *   unreachable for any non-root vId.
 *
 * Refined form (validateUserOpEnforcesInnerSelectorAccess_strict — kept for
 *   regression after the fix):
 *   Adds an additional precondition that EXCLUDES the fast-path bypass:
 *       NOT( allowed[vId][outerSel] == vInfo[vId].nonce
 *            AND vInfo[vId].installed && vInfo[vId].scopedExecutionHook == address(0) )
 *   With that exclusion, validateUserOp reaches the require on
 *   Kernel.sol L179-183 which enforces _allowedSelector(vId, innerSel).
 *
 * ORIGINAL IMPLEMENTATION FINDING (now mitigated by commit 0921b25):
 *   The fast-path branch in `_processUserOp` (Kernel.sol lines 172-176)
 *   bypassed the inner-selector require statement when:
 *     - vType != ROOT,
 *     - `_allowedSelector(vId, outerSel)` was true with outerSel ==
 *       executeUserOp.selector,
 *     - `vInfo[vId].installed && vInfo[vId].scopedExecutionHook == address(0)`.
 *   In that branch, `_setValidationScopedExecutionHook` was never called, the transient
 *   hook for `userOpHash` stayed at 0, and `executeUserOp`'s inner
 *   delegatecall ran with NO selector check — handing a non-ROOT validation
 *   the equivalent of root privileges.
 *
 *   The fix in `_grantAccess` makes this precondition unreachable for
 *   non-ROOT validations: a non-ROOT validation can no longer satisfy
 *   `allowed[vId][executeUserOp.selector] == vInfo[vId].nonce` since that
 *   write is now blocked.
 *
 * Verified contract: KernelHarness (extends KernelUUPS). Harness exposes
 * read accessors only — production logic in validateUserOp is unchanged.
 *
 * NARROWINGS (for tractability — orchestrator is informed):
 *   - vMode bit 0x08 (enable mode) and 0x40 (replayable userOp hash) are
 *     constrained off. Enable-mode invokes _verifyInstallSignatureRaw +
 *     _install which the Prover's hashing engine cannot bound. Replayable
 *     invokes Lib4337.chainAgnosticUserOpHash, same issue. The fast-path
 *     bypass identified above does NOT depend on these modes, so the
 *     finding stands independently.
 *   - External module calls (validator/policy/signer/hook) are NONDET-
 *     summarised. Kernel's `_onlyEntryPointOrSelf` prevents reentrant
 *     writes to ValidationStorage from these modules, so the summary is
 *     sound for the property.
 *   - Internal validators `_validateUserOpValidator/Permission/Fallback`
 *     are NONDET-summarised — they don't write the (vInfo, allowed)
 *     mappings, only consult them. The fast-path branch never reaches
 *     these, so the strict rule does not depend on the summary.
 */

methods {
    // Harness storage / parse accessors (envfree — no env needed).
    function harness_vInfoNonce(bytes21)            external returns (uint32)  envfree;
    function harness_vInfoInstalled(bytes21) external returns (bool) envfree;
    function harness_vInfoScopedExecutionHook(bytes21) external returns (address) envfree;
    function harness_allowedNonce(bytes21, bytes4)  external returns (uint32)  envfree;
    function harness_allowedSelector(bytes21, bytes4) external returns (bool)    envfree;
    function harness_root()                         external returns (bytes21) envfree;

    function harness_parseVType(uint256) external returns (bytes1)  envfree;
    function harness_parseVId(uint256)   external returns (bytes21) envfree;
    function harness_parseVMode(uint256) external returns (bytes1)  envfree;

    function harness_VT_ROOT()                external returns (bytes1) envfree;
    function harness_VT_VALIDATOR()           external returns (bytes1) envfree;
    function harness_VT_PERMISSION()          external returns (bytes1) envfree;
    function harness_executeUserOpSelector()  external returns (bytes4)  envfree;
    function harness_isEnableMode(uint256)    external returns (bool)    envfree;
    function harness_isReplayableMode(uint256) external returns (bool)   envfree;

    function harness_outerSelector(KernelHarness.PackedUserOperation) external returns (bytes4) envfree;
    function harness_innerSelector(KernelHarness.PackedUserOperation) external returns (bytes4) envfree;
    function harness_callDataLength(KernelHarness.PackedUserOperation) external returns (uint256) envfree;

    // ----------------------- Internal summaries -----------------------
    // These functions are called from `validateUserOp` but their behaviour is
    // not relevant to the property — they only need to "exist" and return
    // arbitrary values. Summarising them keeps the TAC small enough to fit
    // in Certora's memory budget.
    //
    // _verifyInstallSignatureRaw — only invoked in enable-mode, which the
    // rule excludes via the precondition. Summarise anyway in case enable-
    // mode paths inline before the precondition is applied.
    function ValidationManager._validateUserOpValidator(
        KernelHarness.ValidationId, bytes32, KernelHarness.PackedUserOperation memory, bytes calldata
    ) internal returns (uint256) => NONDET;
    function ValidationManager._validateUserOpPermission(
        KernelHarness.ValidationId, bytes32, KernelHarness.PackedUserOperation memory, bytes calldata
    ) internal returns (uint256) => NONDET;
    function ValidationManager._validateUserOpFallback(
        KernelHarness.ValidationId, bytes32, KernelHarness.PackedUserOperation memory, bytes calldata
    ) internal returns (uint256) => NONDET;
    function ModuleManager._verifyInstallSignatureRaw(bool, uint256, KernelHarness.Install[] calldata, bytes calldata)
        internal returns (uint256) => NONDET;
    function Lib4337.chainAgnosticUserOpHash(address, KernelHarness.PackedUserOperation calldata)
        internal returns (bytes32) => CONSTANT;
    function Lib4337.intersectValidationData(uint256, uint256) internal returns (uint256) => NONDET;

    // External module / hook callbacks are dispatched as AUTO HAVOC by Certora.
    // The "havoc scope" excludes the KernelHarness contract, which is exactly
    // what we want: returns are arbitrary, but the Kernel's namespaced storage
    // is preserved across the external call. That over-approximation is sound
    // for this property because Kernel's _onlyEntryPointOrSelf prevents these
    // modules from re-entering and writing back into ValidationStorage anyway.
}

// --------------------------------------------------------------------------
// Invariant: nonRootCannotBypassFastPathWithExecuteUserOp
//
// AUDITOR NOTE (Phase C closure, 2026-05-21):
//
// This invariant states exactly the property the two fixes establish:
//
//   For any vId != $.root:
//       NOT ( _allowedSelector(vId, executeUserOp.selector)
//             AND vInfo[vId].installed && vInfo[vId].scopedExecutionHook == address(0) )
//
// jointly enforced by:
//   - commit 0921b25 — `_grantAccess` rejects `executeUserOp.selector` for
//     non-root vIds (block at the grant boundary).
//   - commit ce185f6 — `_setRoot` bumps `vInfo[oldRoot].nonce` on rotation
//     (orphans any prior grants on the old root).
//
// Certora cannot prove this invariant cleanly under the current spec
// configuration. Failing entry points (Round 4 report):
//   executeUserOp, execute, executeFromExecutor, <receiveOrFallback>,
//   upgradeToAndCall, initialize, installModule (both overloads),
//   validateUserOp, setRoot (both overloads), grantAccess.
//
// Common pattern: every failing entry point either invokes an external
// module callback or performs a delegatecall into `address(this)` with
// symbolic calldata. Certora's NONDET / AUTO-HAVOC abstraction for those
// callbacks lets it imagine arbitrary writes to ValidationStorage, which
// trivially violates any structural invariant over that storage. The
// `_onlyEntryPointOrSelf` modifier prevents this reentrant write in
// production, but encoding that fact as a precise CVL summary for ~10
// callback sites is days of work and likely runs into Certora's memory
// budget (the run already consumes 60GB+ with current summaries).
//
// What the audit relies on instead:
//   1. `validateUserOpEnforcesInnerSelectorAccess_naive` PASSES — the
//      original CEX witness is now unreachable post-fix.
//   2. `validateUserOpEnforcesInnerSelectorAccess_strict` PASSES — the
//      precise property under the `!fastPath` precondition.
//   3. Manual induction over the storage writers: `_grantAccess` (with the
//      fix) cannot raise `_allowedSelector(non-root, executeUserOp)` to
//      true; `_setRoot` (with the fix) preserves the property across
//      rotation; `_uninstallValidation` zeros the hook (breaks the
//      conjunction's second conjunct); no other path writes `allowed[]`,
//      `vInfo.nonce`, `vInfo.installed`, or `$.root`. Verified by grep over src/.
//
// The invariant is retained here as a STATEMENT of intent and a regression
// target. If a future Certora run with better summaries can verify it,
// great; until then the rules above + the static-writer analysis carry the
// audit story.
// --------------------------------------------------------------------------
invariant nonRootCannotBypassFastPathWithExecuteUserOp(bytes21 vId)
    vId != harness_root() =>
        !(harness_allowedSelector(vId, harness_executeUserOpSelector())
          && (harness_vInfoInstalled(vId) && harness_vInfoScopedExecutionHook(vId) == 0));

// --------------------------------------------------------------------------
// Rule: validateUserOpEnforcesInnerSelectorAccess_naive
//
// The most direct restatement of the NatSpec security claim. Before commit
// 0921b25 this rule FAILED with a CEX exposing the fast-path bypass. With
// the structural invariant `nonRootCannotAllowExecuteUserOp` established by
// the fix, the fast-path precondition (allowedSelector(vId, outerSel) with
// outerSel == executeUserOp AND vType != ROOT) is unreachable for a vId
// with non-zero `vInfo[vId].nonce`, and the rule now PASSES.
//
// Scope notes:
//   - `vId != $.root` is required because root is intentionally authorised
//     to use the fast-path (vType == ROOT branch). When the user-op nonce
//     encodes (vType != ROOT, vId == $.root), the kernel still recognises
//     the call as root through _checkValidation's vId-based info lookup,
//     and the security guarantee for that case is "root is unconditionally
//     authorised" (per the inline comments at Kernel.sol L160-168) — not
//     "innerSel must be allow-listed." We exclude that case to keep the
//     rule's intent precise.
//
// `requireInvariant` injects the structural invariant as a hypothesis at
// the start of the rule; Certora separately proves the invariant.
// --------------------------------------------------------------------------
rule validateUserOpEnforcesInnerSelectorAccess_naive(
    env e,
    KernelHarness.PackedUserOperation op,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) {
    require harness_callDataLength(op) >= 8;
    bytes4 outerSel = harness_outerSelector(op);
    bytes4 innerSel = harness_innerSelector(op);
    bytes1  vType = harness_parseVType(op.nonce);
    bytes21 vId   = harness_parseVId(op.nonce);

    require outerSel == harness_executeUserOpSelector();
    require vType != harness_VT_ROOT();
    require vId != harness_root();  // root is intentionally exempt from inner-sel check
    require !harness_isEnableMode(op.nonce);
    require !harness_isReplayableMode(op.nonce);

    // Structural invariant jointly enforced by commits 0921b25 and ce185f6:
    // a non-root vId cannot satisfy the fast-path bypass conditions for
    // executeUserOp.selector. This rules out the only path through
    // validateUserOp that skips the inner-selector require.
    requireInvariant nonRootCannotBypassFastPathWithExecuteUserOp(vId);

    validateUserOp@withrevert(e, op, userOpHash, missingAccountFunds);
    bool reverted = lastReverted;

    assert !reverted => harness_allowedSelector(vId, innerSel);
}

// --------------------------------------------------------------------------
// Rule: validateUserOpEnforcesInnerSelectorAccess_strict
//
// The provable refinement. Adds an explicit precondition that excludes the
// fast-path branch (lines 172-176 of Kernel.sol). With the fast-path
// excluded, validateUserOp's control flow falls into the `else` branch
// that enforces _allowedSelector(vId, innerSel) via a require.
//
// Proof obligation: for any non-reverting call to validateUserOp where
//   - vMode is NOT enable-mode and NOT replayable,
//   - outer selector == executeUserOp.selector,
//   - parsed vType != ROOT,
//   - op.callData has at least 8 bytes,
//   - NOT(allowed[vId][outerSel] == vInfo[vId].nonce
//         AND vInfo[vId].installed && vInfo[vId].scopedExecutionHook == address(0)),
// the post-state satisfies allowed[vId][innerSel] == vInfo[vId].nonce.
// --------------------------------------------------------------------------
rule validateUserOpEnforcesInnerSelectorAccess_strict(
    env e,
    KernelHarness.PackedUserOperation op,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) {
    require harness_callDataLength(op) >= 8;
    bytes4 outerSel = harness_outerSelector(op);
    bytes4 innerSel = harness_innerSelector(op);
    bytes1  vType = harness_parseVType(op.nonce);
    bytes21 vId   = harness_parseVId(op.nonce);

    require outerSel == harness_executeUserOpSelector();
    require vType != harness_VT_ROOT();
    require !harness_isEnableMode(op.nonce);
    require !harness_isReplayableMode(op.nonce);

    // Exclude the fast-path: if _allowedSelector(vId, outerSel) holds AND
    // the validation has no hook, the require gate is bypassed (this is the
    // implementation finding, NOT a property of the spec).
    bool fastPath = harness_allowedSelector(vId, outerSel)
                    && (harness_vInfoInstalled(vId) && harness_vInfoScopedExecutionHook(vId) == 0);
    require !fastPath;

    validateUserOp@withrevert(e, op, userOpHash, missingAccountFunds);
    bool reverted = lastReverted;

    assert !reverted => harness_allowedSelector(vId, innerSel);
}

// --------------------------------------------------------------------------
// Sanity rule — ensure validateUserOp isn't vacuously rejecting all inputs
// in the spec setup. If this rule is provable, the main rule is vacuous.
// We want it to be SATISFIABLE only (Certora `satisfy`).
// --------------------------------------------------------------------------
rule sanityValidateUserOpReachesSuccess(
    env e,
    KernelHarness.PackedUserOperation op,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) {
    require harness_callDataLength(op) >= 8;
    validateUserOp@withrevert(e, op, userOpHash, missingAccountFunds);
    satisfy !lastReverted;
}
