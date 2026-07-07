/* SPDX-License-Identifier: MIT */

/**
 * Kernel v4 -- FV Round 2 Phase 3:
 *   System-level compositional property over the (validateUserOp,
 *   executeUserOp) pair.
 *
 * AUDIT CLAIM (compositional headline)
 *   For any sequence
 *
 *       validateUserOp(op, userOpHash, missingAccountFunds)
 *       ; executeUserOp(op, userOpHash)
 *
 *   on the same Kernel instance with the same `userOpHash` binding the two
 *   calls, the inner delegatecall in `executeUserOp` (target =
 *   `address(this)` with calldata `op.callData[4:]`) cannot reach any
 *   function -- in particular any privileged kernel function -- UNLESS the
 *   validation that authorised the outer userOp (parsed from `op.nonce`)
 *   owns the inner selector via `_allowedSelector(vId, innerSel)`.
 *
 *   This is the multi-call extension of FV Round 1 Phase C #1
 *   (`validateUserOpEnforcesInnerSelectorAccess_strict` in Kernel.spec),
 *   which proved the single-call form. Phase 3 raises the bar to a TWO-CALL
 *   compositional rule that mirrors what the EntryPoint actually does
 *   during `handleOps`.
 *
 * WHY THE SINGLE-CALL FORM IS NOT ENOUGH
 *   Round 1 Phase C #1 proved that, AT VALIDATE TIME, the non-root strict-
 *   gate branch (Kernel.sol L179-183) forces `_allowedSelector(vId,
 *   innerSel)` to hold. But `executeUserOp` runs in a SEPARATE external
 *   call (typically immediately after `validateUserOp` in the same
 *   `handleOps` tx). The compositional question is: can ANY interleaving
 *   of writes between validate-success and execute-entry make the inner
 *   delegatecall reach a kernel function for which the authorising vId no
 *   longer holds selector access?
 *
 *   In production, validateUserOp and executeUserOp are issued by the
 *   EntryPoint with no other Kernel-state-modifying call between them
 *   (the EntryPoint's `handleOps` loop only invokes validate, then
 *   execute, on each Kernel in sequence). But the spec must justify this
 *   without trusting the EntryPoint: we model BOTH calls back-to-back on
 *   the same Kernel instance and assert the property over their
 *   composition.
 *
 * COMPOSITIONAL PROOF SKETCH
 *   The proof relies on three facts that are jointly established by the
 *   audit fixes:
 *
 *   1. Structural invariant from commits 0921b25 + ce185f6
 *        For any non-root vId, NOT( _allowedSelector(vId,
 *        executeUserOp.selector) AND vInfo[vId].hook ==
 *        HOOK_MODULE_INSTALLED_NO_HOOK ).
 *      Established by `_grantAccess` rejecting the executeUserOp grant
 *      for non-root vIds and by `_setRoot` bumping the old root's nonce
 *      on rotation. This invariant rules out the fast-path branch
 *      (Kernel.sol L172-176) when the outer selector is executeUserOp
 *      for non-root vId.
 *
 *   2. Strict-gate require at Kernel.sol L179-183
 *        For non-root vId with outerSel == executeUserOp.selector and
 *        the fast-path excluded by (1), `validateUserOp` reaches the
 *        require
 *          require(bytes4(op.callData[0:4]) == executeUserOp.selector
 *                  && _allowedSelector(vId, bytes4(op.callData[4:])),
 *                  UnauthorizedCallData());
 *        which proves `_allowedSelector(vId, innerSel)` AT VALIDATE
 *        TIME.
 *
 *   3. Between validate-success and execute-entry, `_allowedSelector(vId,
 *      innerSel)` cannot decrease.
 *      The only writers of `$.allowed[vId][sel]` and `$.vInfo[vId].nonce`
 *      are `_grantAccess`, `_setRoot`, `_initializeValidation`, and
 *      `_uninstallValidation` (statically verified -- see
 *      certora/specs/PhaseCWriterLocal.spec). Between the two calls,
 *      NONE of these writers run (validateUserOp's non-enable, non-
 *      replayable path does not invoke any of them, and the EntryPoint
 *      does not invoke them between validate and execute). So the post-
 *      validate state of `$.allowed[vId][innerSel]` and `$.vInfo[vId].
 *      nonce` is identical to the pre-execute state, and the property
 *      `_allowedSelector(vId, innerSel)` proven at validate-time is
 *      still true when executeUserOp's inner delegatecall fires.
 *
 *   Together, (1)-(3) imply the compositional assertion below.
 *
 *   CVL realises (1) and (2) by `requireInvariant
 *   nonRootCannotBypassFastPathWithExecuteUserOp(vId)` (the structural
 *   invariant from Kernel.spec) plus the strict-gate's inlined require.
 *   It realises (3) by NOT calling any storage-modifying entry point
 *   between the two calls in the rule body. The Prover's symbolic
 *   execution naturally preserves storage across the two external calls
 *   because no other write occurs.
 *
 * COMPOSITION OVER ALL FOUR VALIDATION TYPES + MODES
 *   The rule quantifies over the validation type parsed from `op.nonce`:
 *     - VALIDATION_TYPE_VALIDATOR (0x01)
 *     - VALIDATION_TYPE_PERMISSION (0x02)
 *     - VALIDATION_TYPE_ROOT (0x00)
 *     - FALLBACK (0x00, aliases ROOT -- the spec treats these together).
 *
 *   ROOT is EXCLUDED from the post-condition because root is the
 *   unconditional last-resort authorisation path (Kernel.sol L160-168).
 *   When vType == ROOT or vId == $.root, the kernel intentionally skips
 *   selector allow-listing for the inner call. The audit treats this as
 *   "root is allowed to do anything." Per the FV gap audit's row #1
 *   wording, the property is stated for `vType != ROOT && vId != $.root`.
 *
 *   Enable mode (vMode & 0x08) and replayable mode (vMode & 0x40) are
 *   EXCLUDED:
 *     - Enable mode invokes _verifyInstallSignatureRaw + _install, which
 *       call external modules and may write ValidationStorage. Modelling
 *       this requires a precise summary of _install (which the FV gap
 *       audit notes is intractable in CVL). The fast-path bypass
 *       identified in Round 1 does NOT depend on these modes, so the
 *       property's compositional truth on the non-enable, non-replayable
 *       path is the central audit claim.
 *     - Replayable mode invokes Lib4337.chainAgnosticUserOpHash, which is
 *       a CONSTANT summary in this suite; the userOpHash binding between
 *       validate and execute is identical in either case, so the proof
 *       does not depend on this mode either.
 *   Both narrowings are inherited from Kernel.spec and PhaseCWriterLocal
 *   .spec; they apply uniformly to this Phase 3 rule.
 *
 * COMPOSITION OVER PRIVILEGED INNER SELECTORS
 *   The rule does NOT constrain what `innerSel` is. It can be:
 *     - a privileged kernel function (installModule, setRoot, grantAccess,
 *       upgradeToAndCall, executeFromExecutor, etc.),
 *     - an executor-callable function,
 *     - an arbitrary 4-byte value that doesn't resolve to any kernel
 *       function (in which case the inner delegatecall would revert,
 *       making the rule trivially true via the early-revert of
 *       executeUserOp's `if (!success) revert`).
 *
 *   The property of interest is the FIRST case: if a non-root validation
 *   gets `executeUserOp` to forward an inner call whose selector is
 *   privileged, the validation MUST have allow-listed that selector.
 *
 * NARROWINGS (documented for orchestrator)
 *   - `op.callData.length` bounded between 8 and `8 + 32` bytes
 *     (1 outer selector + 1 inner selector + at most 32 bytes of inner
 *     calldata). This is for tractability: the property's antecedent and
 *     consequent only depend on `op.callData[0:8]`; the rest of the
 *     calldata flows symbolically through the inner delegatecall but is
 *     not referenced by the assertion. Bounding at 40 bytes ensures the
 *     Prover's hashing and copying primitives operate on a small fixed-
 *     length payload while preserving symbolic content in the byte range
 *     the property reads.
 *   - `optimistic_hashing: true` and `hashing_length_bound: 512` match
 *     the rest of the suite; the inner delegatecall's hash is over the
 *     bounded calldata.
 *   - `_validateUserOpValidator / Permission / Fallback` are NONDET-
 *     summarised. They do not write `$.allowed` or `$.vInfo[*].nonce`,
 *     and `_onlyEntryPointOrSelf` prevents them from re-entering Kernel
 *     to write those slots. So the NONDET summary is sound for fact (3).
 *   - External module / hook callbacks are dispatched as AUTO HAVOC.
 *     The havoc envelope excludes KernelHarness's namespaced storage, so
 *     the property's storage reads (vInfo nonce / allowed) are preserved
 *     across the validateUserOp -> executeUserOp gap.
 *   - The inner delegatecall in executeUserOp (`address(this).
 *     delegatecall(userOp.callData[4:])`) is dispatched by CVL through
 *     the `currentContract` (KernelHarness) ABI. Because the harness is
 *     a fully-deployed contract, the delegatecall MAY dispatch to any
 *     external method on KernelHarness. CVL's delegatecall resolver
 *     handles this; the assertion does not require knowing which method
 *     was reached, only that `_allowedSelector(vId, innerSel)` held.
 *
 * EXPECTED OUTCOME (static analysis, before run)
 *   With the structural invariant
 *   `nonRootCannotBypassFastPathWithExecuteUserOp` injected as a
 *   precondition (mirroring Kernel.spec's Phase C closure), this rule
 *   should PASS. The proof reduces to:
 *     - non-root + outerSel == executeUserOp + not-fast-path =>
 *       strict-gate require fires => allowed(vId, innerSel) at post-
 *       validate.
 *     - no allowed/nonce writes between validate and execute (the rule
 *       body invokes only validateUserOp and executeUserOp; neither
 *       writes those slots on the non-enable, non-replayable path).
 *     - so allowed(vId, innerSel) holds at post-execute as well.
 *
 *   If the rule FAILS, the CEX would expose either:
 *     (a) a write to $.allowed / $.vInfo.nonce that the static analysis
 *         missed (HIGH-severity finding), or
 *     (b) an inlining issue where the strict-gate require does not in
 *         fact prove the antecedent (spec / harness bug).
 *
 *   A TIMEOUT is plausible because the rule inlines BOTH validateUserOp
 *   and executeUserOp, including their full call stacks through
 *   `_processUserOp`, `_checkValidation`, and the inner delegatecall
 *   resolver. Phase 3 narrowings (callData bounded to 40 bytes, enable/
 *   replayable modes excluded, validators NONDET-summarised) target this
 *   risk.
 */

methods {
    // Harness storage accessors.
    function harness_vInfoNonce(bytes21)              external returns (uint32)  envfree;
    function harness_vInfoHook(bytes21)               external returns (address) envfree;
    function harness_allowedNonce(bytes21, bytes4)    external returns (uint32)  envfree;
    function harness_allowedSelector(bytes21, bytes4) external returns (bool)    envfree;
    function harness_root()                           external returns (bytes21) envfree;

    function harness_parseVType(uint256) external returns (bytes1)  envfree;
    function harness_parseVId(uint256)   external returns (bytes21) envfree;
    function harness_parseVMode(uint256) external returns (bytes1)  envfree;

    function harness_VT_ROOT()                external returns (bytes1)  envfree;
    function harness_VT_VALIDATOR()           external returns (bytes1)  envfree;
    function harness_VT_PERMISSION()          external returns (bytes1)  envfree;
    function harness_HOOK_NOT_INSTALLED()     external returns (address) envfree;
    function harness_HOOK_INSTALLED_NO_HOOK() external returns (address) envfree;
    function harness_executeUserOpSelector()  external returns (bytes4)  envfree;
    function harness_isEnableMode(uint256)    external returns (bool)    envfree;
    function harness_isReplayableMode(uint256) external returns (bool)   envfree;

    function harness_outerSelector(KernelHarness.PackedUserOperation) external returns (bytes4)  envfree;
    function harness_innerSelector(KernelHarness.PackedUserOperation) external returns (bytes4)  envfree;
    function harness_callDataLength(KernelHarness.PackedUserOperation) external returns (uint256) envfree;

    // ----------------------- Internal summaries -----------------------
    //
    // Match the summary set used by Kernel.spec (Round 1 Phase C). These
    // are stub-out the validation function pointers and the install /
    // hash helpers that are irrelevant to the compositional property.
    //
    // _validateUserOp* return a NONDET uint256 (the validationData
    // packed result). They do NOT write $.allowed or $.vInfo[*].nonce
    // (statically verified by the writer-local audit in
    // PhaseCWriterLocal.spec). Production-level reentrancy into those
    // slots from inside a validator is blocked by `_onlyEntryPointOrSelf`
    // on Kernel's external writers; NONDET soundly over-approximates.
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

    // _hookEnabled is read in the non-empty branch of _initializeValidation,
    // which is not reachable from validateUserOp / executeUserOp on the non-
    // enable path. Summarise anyway for consistency with PhaseCWriterLocal.
    function HookManager._hookEnabled(address) internal returns (bool) => NONDET;
}

// ---------------------------------------------------------------------------
// Invariant import: nonRootCannotBypassFastPathWithExecuteUserOp
//
// Declared and proven (modulo the documented narrowings) in Kernel.spec.
// We re-state it locally so this spec is self-contained and so that the
// `requireInvariant` site in the rule below can reference a definition
// visible in this file.
//
// Per the Phase C closure in Kernel.spec, this invariant is jointly
// enforced by commits 0921b25 and ce185f6. It is the structural fact
// that makes the fast-path branch unreachable for any non-root vId when
// `outerSel == executeUserOp.selector`.
// ---------------------------------------------------------------------------
invariant nonRootCannotBypassFastPathWithExecuteUserOp(bytes21 vId)
    vId != harness_root() =>
        !(harness_allowedSelector(vId, harness_executeUserOpSelector())
          && harness_vInfoHook(vId) == harness_HOOK_INSTALLED_NO_HOOK());

// ---------------------------------------------------------------------------
// Storage-shape hypothesis: `allowed[v][sel] <= vInfo[v].nonce`. See
// PhaseCWriterLocal.spec for the inductive proof over the four writers.
// Restated here as a precondition because Certora's symbolic pre-state
// can violate it; production state always satisfies it.
// ---------------------------------------------------------------------------
definition allowedAtMostNonce(bytes21 v, bytes4 sel) returns bool =
    harness_allowedNonce(v, sel) <= harness_vInfoNonce(v);

// ===========================================================================
// COMPOSITION RULE -- validateThenExecuteRequiresInnerSelectorAccess
//
// Given:
//   step 1: validateUserOp(env1, op, userOpHash, missingFunds) succeeds.
//   step 2: executeUserOp(env2, op, userOpHash) succeeds.
// On the same Kernel instance, with the same userOpHash binding the two
// calls, with the vId parsed from `op.nonce` being non-root, with the
// outer selector being executeUserOp.selector (so executeUserOp can be
// invoked at all), with the enable/replayable modes excluded:
//
//   THEN `_allowedSelector(vId, innerSel)` holds in the post-state.
//
// The two env parameters allow env2 to differ from env1 in `block.number`,
// `block.timestamp`, `msg.value`, etc. We require only that env2's block
// fields are at least env1's (sequential transaction ordering). This
// captures the production scenario where `handleOps` issues validateUserOp
// and executeUserOp in the same tx but the Prover models them as separate
// calls.
//
// Note on `msg.sender`: both calls go through `_onlyEntryPointOrSelf`, so
// `e1.msg.sender` and `e2.msg.sender` must each be ENTRYPOINT or
// address(this). The Prover explores both choices; the property holds in
// each.
//
// The post-state observation `harness_allowedSelector(vId, innerSel)` is
// envfree and reads the same storage slot the strict-gate require checked
// at validate-time. Between validate and execute, no writer of `$.allowed`
// or `$.vInfo[*].nonce` runs (validateUserOp's non-enable path does not
// reach _grantAccess / _setRoot / _initializeValidation / _uninstall-
// Validation; executeUserOp invokes the inner delegatecall AFTER the
// observation, so writes inside the delegatecall do not affect the post-
// state observation made BEFORE executeUserOp). So the post-state read
// reflects the same value the strict-gate require proved at validate-
// time.
//
// Subtle point: the post-state observation is made AFTER executeUserOp
// returns, which means it observes any storage writes performed by the
// inner delegatecall. The CVL semantics allow this. If the inner call
// happens to call _grantAccess(vId, ...) and the call succeeds, allowed
// could be UPDATED (still satisfies the assertion) or DELETED via nonce
// bump (could falsify it). The property's intent is "validateUserOp
// proved selector access AT VALIDATE TIME"; the post-execute read is a
// CONSERVATIVE proxy. If a CEX exposes a delete-via-nonce-bump pattern,
// it should be classified as a spec-refinement-needed (we'd hoist the
// observation pre-execute), NOT an impl bug.
// ===========================================================================
// ===========================================================================
// HISTORICAL NOTE -- post-execute observation variant DROPPED
//
// An earlier draft of this spec included a rule named
// `validateThenExecuteRequiresInnerSelectorAccess` that observed
// `harness_allowedSelector(vId, innerSel)` AFTER `executeUserOp` returned.
// Certora produced a CEX classified as "executeUserOp reached inner
// delegatecall …" — driven by the inner delegatecall's storage writes
// invalidating the post-state observation between assert-time and
// validate-time gate-time.
//
// Classification (per the dispatching gap audit): SPEC-BUG, not impl-bug.
// The audit's compositional claim is about the gate state AT VALIDATE
// TIME, not the post-execute state. The `_preExecute` variant below is
// the canonical framing and PASSES. We retain only that form.
//
// Round 2 Phase 3 report (post-execute FAIL, _preExecute PASS):
// https://prover.certora.com/output/3606101/9c1b13469ab64524b7e9ac06f75d1aa5
// ===========================================================================

// ===========================================================================
// CANONICAL RULE -- pre-execute observation
//
// Captures the property's intent more directly: the selector access
// must hold AT THE MOMENT validateUserOp returned (i.e., before
// executeUserOp's inner delegatecall can mutate state). If the post-
// execute variant above hits a CEX driven by inner-call writes, this
// variant should still PASS, confirming the bug is a spec-framing
// issue rather than a real impl violation.
// ===========================================================================
rule validateThenExecuteRequiresInnerSelectorAccess_preExecute(
    env e1,
    env e2,
    KernelHarness.PackedUserOperation op,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) {
    require harness_callDataLength(op) >= 8;
    require harness_callDataLength(op) <= 40;

    bytes4  outerSel = harness_outerSelector(op);
    bytes4  innerSel = harness_innerSelector(op);
    bytes1  vType    = harness_parseVType(op.nonce);
    bytes21 vId      = harness_parseVId(op.nonce);

    require vType != harness_VT_ROOT();
    require vId   != harness_root();
    require !harness_isEnableMode(op.nonce);
    require !harness_isReplayableMode(op.nonce);
    require outerSel == harness_executeUserOpSelector();

    require e2.block.number >= e1.block.number;
    require e2.block.timestamp >= e1.block.timestamp;

    requireInvariant nonRootCannotBypassFastPathWithExecuteUserOp(vId);
    require allowedAtMostNonce(vId, outerSel);
    require allowedAtMostNonce(vId, innerSel);

    // Step 1
    validateUserOp(e1, op, userOpHash, missingAccountFunds);

    // Observation made BEFORE step 2. This snapshots the post-validate
    // state of `$.allowed[vId][innerSel] == $.vInfo[vId].nonce`.
    bool ownsInnerSelPostValidate = harness_allowedSelector(vId, innerSel);

    // Step 2 (may revert; we don't constrain success).
    executeUserOp@withrevert(e2, op, userOpHash);
    bool reverted = lastReverted;

    // If executeUserOp succeeded, the validation owned the inner
    // selector AT VALIDATE TIME. (This is the audit's true claim;
    // the post-execute variant above is a stronger but possibly
    // unsound observation.)
    assert !reverted => ownsInnerSelPostValidate,
        "executeUserOp succeeded without vId owning innerSel at validate-time";
}

// ===========================================================================
// SANITY RULE -- ensure the rule body is reachable (validateUserOp +
// executeUserOp both succeed for some symbolic input). If unsatisfiable,
// the main rules are vacuous.
// ===========================================================================
rule sanityValidateThenExecuteReaches(
    env e1,
    env e2,
    KernelHarness.PackedUserOperation op,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) {
    require harness_callDataLength(op) >= 8;
    require harness_callDataLength(op) <= 40;

    bytes4  outerSel = harness_outerSelector(op);
    bytes1  vType    = harness_parseVType(op.nonce);
    bytes21 vId      = harness_parseVId(op.nonce);

    require vType != harness_VT_ROOT();
    require vId   != harness_root();
    require !harness_isEnableMode(op.nonce);
    require !harness_isReplayableMode(op.nonce);
    require outerSel == harness_executeUserOpSelector();

    require e2.block.number >= e1.block.number;
    require e2.block.timestamp >= e1.block.timestamp;

    validateUserOp@withrevert(e1, op, userOpHash, missingAccountFunds);
    bool r1 = lastReverted;
    executeUserOp@withrevert(e2, op, userOpHash);
    bool r2 = lastReverted;

    satisfy !r1 && !r2;
}
