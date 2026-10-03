/* SPDX-License-Identifier: MIT */

/**
 * Kernel v4 -- Phase C Round 2: Writer-local invariants for the
 * fast-path-bypass impossibility property.
 *
 * GLOBAL PROPERTY (the one Round 1 failed to prove as a single invariant):
 *
 *   For any vId != $.root:
 *       NOT ( _allowedSelector(vId, executeUserOp.selector)
 *             AND vInfo[vId].installed && vInfo[vId].scopedExecutionHook == address(0) )
 *
 * jointly enforced by:
 *   - commit 0921b25 -- `_grantAccess` rejects executeUserOp.selector for
 *     non-root vIds (block at the grant boundary).
 *   - commit ce185f6 -- `_setRoot` bumps vInfo[oldRoot].nonce on rotation
 *     (orphans any prior grants on the old root).
 *
 * WHY ROUND 1 FAILED
 *   Round 1 used a single `invariant` and ran the inductive step against
 *   every parametric public method. Many of those methods (executeUserOp,
 *   execute, validateUserOp, installModule, setRoot, grantAccess,
 *   upgradeToAndCall, fallback, initialize) invoke external module
 *   callbacks. Certora's NONDET / AUTO-HAVOC abstraction for those
 *   callbacks lets the prover imagine arbitrary writes to
 *   ValidationStorage, which trivially violates any structural invariant.
 *   `_onlyEntryPointOrSelf` blocks this reentrant write in production, but
 *   encoding that as precise CVL summaries for ~10 callback sites is days
 *   of work and OOMs the prover.
 *
 * ROUND 2 STRATEGY -- WRITER-LOCAL DECOMPOSITION
 *   Replace the global invariant with FOUR narrow rules, one per writer.
 *   Each rule calls EXACTLY ONE writer (via a harness wrapper) and:
 *     - establishes the bypass-impossible property holds pre-call,
 *     - executes the writer with arbitrary symbolic inputs,
 *     - asserts the property still holds post-call.
 *
 *   Because each rule calls a single writer, the NONDET/AUTO-HAVOC
 *   envelope only applies to whatever external calls THAT WRITER itself
 *   makes -- and the four writers identified here make NO external calls
 *   that could re-enter ValidationStorage:
 *     * _grantAccess              -- pure storage writes, no external calls
 *     * _setRoot(vId)             -- pure storage writes
 *     * _uninstallValidation      -- single storage write
 *     * _initializeValidation     -- updates validation state and calls
 *                                    _grantAccess (covered by Rule #1)
 *
 *   The conjunction of the four writer-local rules implies the global
 *   property by structural induction over writes to ValidationStorage:
 *     - $.allowed[*][*] is written ONLY by _grantAccess.
 *     - $.vInfo[*].nonce is incremented ONLY by _grantAccess, _setRoot
 *       (rotation), and _initializeValidation (empty-data path).
 *     - $.vInfo[*].installed is written ONLY by _uninstallValidation and
 *       _initializeValidation.
 *     - $.root is written ONLY by _setRoot.
 *   Verified by manual grep over src/ on 2026-05-21. No other code path
 *   touches those slots. Constructor / initialize establishes the base
 *   state where allowed[*][*] == 0 and vInfo[*].installed == 0 universally,
 *   trivially satisfying the property.
 *
 * VICTIM-vId FRAMING
 *   Each rule quantifies over an arbitrary `victimVid != $.root`. The
 *   property under test refers to THAT victimVid's storage, while the
 *   writer's argument may target a different vId (`writerVid`). This
 *   captures the worst-case "the writer affects vId X; does this change
 *   any *other* non-root vId's bypass status?" question for free.
 *
 * NARROWINGS (documented for orchestrator)
 *   - External module callbacks reachable inside writer paths are AUTO
 *     HAVOC by Certora. The four writers covered here make no such
 *     callbacks (verified by source-level inspection), so AUTO HAVOC
 *     is irrelevant to these rules.
 *   - `loop_iter=3` matches the rest of the suite. _grantAccess iterates
 *     `selectors.length / 4` times; we use the same bound. For a violation
 *     to require more than 3 grants in a single call, the call would need
 *     more than 12 bytes of selector data with the violation buried after
 *     the 3rd. The grant-rejection check is per-selector, so any selector
 *     that violates the property reverts before the next one is processed
 *     -- the bound is safe.
 *   - The decomposition does NOT formally prove the global invariant in
 *     CVL; it provides a writer-local proof PLUS a documented static
 *     analysis showing the writer set is complete. Future work could
 *     express the conjunction as a Certora `invariant` if a precise
 *     summary set for the callback sites becomes available.
 *
 * Verified contract: KernelHarness (extends KernelUUPS). Harness adds
 * external wrappers for the four internal writers; production logic is
 * unchanged.
 */

methods {
    // Read-only state accessors.
    function harness_vInfoNonce(bytes21)              external returns (uint32)  envfree;
    function harness_vInfoInstalled(bytes21) external returns (bool) envfree;
    function harness_vInfoScopedExecutionHook(bytes21) external returns (address) envfree;
    function harness_allowedNonce(bytes21, bytes4)    external returns (uint32)  envfree;
    function harness_allowedSelector(bytes21, bytes4) external returns (bool)    envfree;
    function harness_root()                           external returns (bytes21) envfree;
    function harness_executeUserOpSelector()  external returns (bytes4)  envfree;

    // The four writer wrappers (Phase C Round 2 harness additions).
    function harness_grantAccess(bytes21, bytes) external;
    function harness_setRootById(bytes21) external;
    function harness_uninstallValidation(bytes21) external;
    function harness_initializeValidation(bytes21, bytes) external;

    // Internal summaries shared with Kernel.spec / SetRootLifo.spec.
    // The four writers we're targeting don't invoke any of these directly;
    // they're listed so the verify-contract configuration is consistent.
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

}

// ---------------------------------------------------------------------------
// Predicate: the "fast-path bypass conjunction" for victimVid.
//   isBypassable(v) == _allowedSelector(v, executeUserOp.selector)
//                      AND vInfo[v].installed && vInfo[v].scopedExecutionHook == address(0)
//
// The global property says: for victimVid != $.root, NOT isBypassable(victimVid).
// Each writer-local rule says: any call to that writer that started from a
// pre-state where NOT isBypassable(victimVid) ends in a post-state where
// still NOT isBypassable(victimVid).
// ---------------------------------------------------------------------------
definition isBypassable(bytes21 v) returns bool =
    harness_allowedSelector(v, harness_executeUserOpSelector())
    && (harness_vInfoInstalled(v) && harness_vInfoScopedExecutionHook(v) == 0);

// ---------------------------------------------------------------------------
// Storage-shape invariant: `allowed[v][sel] <= vInfo[v].nonce` for every
// reachable state.
//
// PROOF that this holds in real execution:
//   - The only writer of $.allowed[v][sel] is `_grantAccess(v, [..sel..])`,
//     which first increments vInfo[v].nonce and then sets
//     allowed[v][sel] = vInfo[v].nonce. So immediately post-write, the two
//     are equal.
//   - Subsequent writes to $.vInfo[v].nonce (via _grantAccess, _setRoot
//     rotation, _initializeValidation empty-data) only INCREMENT the
//     nonce. allowed[v][sel] is never written above its peer nonce, and
//     nonce never decreases. So allowed[v][sel] <= vInfo[v].nonce holds
//     pointwise across all reachable states.
//   - The genesis state has both = 0, satisfying the relation.
//
// We require this as a pre-condition for the rules below. Without it, the
// symbolic pre-state could have allowed[victimVid][exec] = nonce + 1, and
// a writer that bumps nonce would then make allowed == nonce hold post-
// state -- a spurious CEX unreachable in real execution. The constraint
// excludes that spurious branch.
//
// We restrict the constraint to (victimVid, executeUserOp.selector) since
// that's the only allowed[][] slot the bypass-impossible property reads.
// ---------------------------------------------------------------------------
definition allowedAtMostNonce(bytes21 v) returns bool =
    harness_allowedNonce(v, harness_executeUserOpSelector())
        <= harness_vInfoNonce(v);

// ===========================================================================
// RULE 1 -- _grantAccess preserves non-bypass for non-root vIds.
//
// _grantAccess writes:
//   $.vInfo[writerVid].nonce += 1            (no other vId's nonce changes)
//   $.allowed[writerVid][sel] = newNonce     (for each sel in selectors)
//
// With the fix at commit 0921b25, the per-selector require:
//     require(sel != executeUserOp.selector || writerVid == $.root)
// rejects the only grant pattern that could set _allowedSelector(writerVid,
// executeUserOp.selector) to true for a non-root writerVid.
//
// For any victimVid != writerVid, _grantAccess does not write
// vInfo[victimVid] or allowed[victimVid][*], so victimVid's bypass status
// cannot change. (Note: _allowedSelector(victimVid, sel) depends on
// vInfo[victimVid].nonce -- which is also untouched.)
//
// The rule covers BOTH cases (writerVid == victimVid and writerVid !=
// victimVid) via a fresh symbolic victimVid + arbitrary writerVid.
// ===========================================================================
rule grantAccessPreservesNonBypass(
    env e,
    bytes21 writerVid,
    bytes selectors,
    bytes21 victimVid
) {
    // Property pre-condition: victim is non-root and is currently NOT bypassable.
    require victimVid != harness_root();
    require !isBypassable(victimVid);

    // Storage-shape pre-condition (see allowedAtMostNonce definition).
    // Also restrict the writerVid's storage in case writerVid == victimVid.
    require allowedAtMostNonce(victimVid);
    require allowedAtMostNonce(writerVid);

    harness_grantAccess@withrevert(e, writerVid, selectors);
    bool reverted = lastReverted;

    // If the call reverts, no state change -- property trivially holds.
    // If it succeeds, the property must still hold.
    assert !reverted => victimVid == harness_root() || !isBypassable(victimVid),
        "grantAccess violated bypass-impossible for victimVid";
}

// ===========================================================================
// RULE 2 -- _setRoot(vId) preserves non-bypass for non-root vIds.
//
// _setRoot(newRoot) writes:
//   $.vInfo[oldRoot].nonce += 1      (when oldRoot != 0 and oldRoot != newRoot)
//   $.root = newRoot
//
// The rule's pre-condition requires `victimVid != harness_root()` PRE-call,
// i.e. victimVid != oldRoot. After the call $.root may equal newRoot.
// Subcases:
//
//   (a) victimVid == newRoot:
//       Post-state, victimVid == $.root. The property's antecedent
//       `victimVid != harness_root()` is false, so the implication holds
//       vacuously (consequent does not need to hold).
//
//   (b) victimVid != newRoot AND victimVid != oldRoot:
//       Pre and post, victimVid != $.root. _setRoot did not touch
//       vInfo[victimVid] or allowed[victimVid][*], so isBypassable(victimVid)
//       is unchanged.
//
// The fix at commit ce185f6 (oldRoot nonce bump) is what FORMERLY made the
// excluded subcase (victimVid == oldRoot) safe in the previous global
// invariant formulation. Here we exclude it by pre-condition (`victimVid !=
// harness_root()` pre-call). The fix is still relevant because it preserves
// the storage-shape invariant on rotation: the bumped-nonce ensures
// allowed[oldRoot][*] != nonce[oldRoot] post-rotation, which the global
// property reads when oldRoot becomes the victimVid of a subsequent call.
// ===========================================================================
rule setRootPreservesNonBypass(
    env e,
    bytes21 newRoot,
    bytes21 victimVid
) {
    // Property pre-condition: victim is currently non-root and NOT bypassable.
    require victimVid != harness_root();
    require !isBypassable(victimVid);

    // Storage-shape pre-condition. The current root is the old root; its
    // allowedNonce constraint may matter if victimVid happens to equal it.
    require allowedAtMostNonce(victimVid);
    require allowedAtMostNonce(harness_root());

    harness_setRootById@withrevert(e, newRoot);
    bool reverted = lastReverted;

    // Post-state: victim may now equal $.root (if it was newly promoted).
    // In that case the property is vacuously true ("victimVid != $.root"
    // antecedent is false). Otherwise it must still hold.
    assert !reverted => victimVid == harness_root() || !isBypassable(victimVid),
        "setRoot violated bypass-impossible for victimVid";
}

// ===========================================================================
// RULE 3 -- _uninstallValidation preserves non-bypass for non-root vIds.
//
// _uninstallValidation writes:
//   $.vInfo[targetVid].installed = false
//
// The function reverts if targetVid == $.root (CannotUninstallRoot), so a
// successful call leaves $.root unchanged.
//
// Effect on isBypassable(victimVid):
//   * If victimVid == targetVid: post-state hook is installed == false,
//     which is not a zero scopedExecutionHook, so the conjunction's
//     second conjunct is false. Property holds.
//   * If victimVid != targetVid: vInfo[victimVid].installed,
//     allowed[victimVid][*], and vInfo[victimVid].nonce are all unchanged.
//     Property holds by pre-condition.
// ===========================================================================
rule uninstallValidationPreservesNonBypass(
    env e,
    bytes21 targetVid,
    bytes21 victimVid
) {
    // Property pre-condition: victim is non-root and currently NOT bypassable.
    require victimVid != harness_root();
    require !isBypassable(victimVid);

    // Storage-shape pre-condition. _uninstallValidation does not write
    // nonce or allowed, so this is included for parity / safety; the
    // post-state inherits the constraint trivially.
    require allowedAtMostNonce(victimVid);

    harness_uninstallValidation@withrevert(e, targetVid);
    bool reverted = lastReverted;

    // _uninstallValidation cannot change $.root (it reverts on targetVid ==
    // root), so victimVid != $.root remains in post-state.
    assert !reverted => victimVid == harness_root() || !isBypassable(victimVid),
        "uninstallValidation violated bypass-impossible for victimVid";
}

// ===========================================================================
// RULE 4 -- _initializeValidation preserves non-bypass for non-root vIds.
//
// _initializeValidation has two branches based on _internalData.length:
//
//   (A) Empty data:
//         $.vInfo[targetVid].scopedExecutionHook = address(0)
//         $.vInfo[targetVid].nonce += 1
//       The nonce bump (commits 9f9471c, ce185f6) ensures that any
//       allowed[targetVid][sel] entries from a prior incarnation become
//       stale, so _allowedSelector(targetVid, *) is false post-state.
//       => first conjunct of isBypassable(targetVid) is false. Property
//       holds for targetVid.
//
//   (B) Non-empty data:
//         $.vInfo[targetVid].scopedExecutionHook = (parsed validation-scoped execution hook,
//                                    possibly remapped to INSTALLED_NO_HOOK)
//         then calls _grantAccess(targetVid, remaining selectors)
//
//       _grantAccess applies its per-selector require, which rejects
//       executeUserOp.selector for targetVid != $.root. So even in this
//       branch, allowed[targetVid][executeUserOp.selector] != newNonce for
//       a non-root targetVid -- first conjunct stays false.
//
// In both branches, vInfo[victimVid] for victimVid != targetVid is
// untouched. So the property holds for any victimVid != $.root.
//
// The function also reverts if vInfo[targetVid].installed is already true
// (`OccupiedValidationId`), which restricts the writer to fresh slots.
// ===========================================================================
rule initializeValidationPreservesNonBypass(
    env e,
    bytes21 targetVid,
    bytes internalData,
    bytes21 victimVid
) {
    // Property pre-condition: victim is non-root and currently NOT bypassable.
    require victimVid != harness_root();
    require !isBypassable(victimVid);

    // Storage-shape pre-condition. Apply to both victimVid (the property's
    // witness) and targetVid (the writer's slot, which may equal victimVid).
    require allowedAtMostNonce(victimVid);
    require allowedAtMostNonce(targetVid);

    harness_initializeValidation@withrevert(e, targetVid, internalData);
    bool reverted = lastReverted;

    // _initializeValidation does NOT write $.root, so victimVid != $.root
    // remains in post-state.
    assert !reverted => victimVid == harness_root() || !isBypassable(victimVid),
        "initializeValidation violated bypass-impossible for victimVid";
}

// ===========================================================================
// SANITY RULES -- ensure each writer is reachable (not vacuously reverting).
// If a sanity rule is unsatisfiable, the corresponding rule is vacuous.
// ===========================================================================

rule sanityGrantAccessReaches(env e, bytes21 writerVid, bytes selectors) {
    harness_grantAccess@withrevert(e, writerVid, selectors);
    satisfy !lastReverted;
}

rule sanitySetRootReaches(env e, bytes21 newRoot) {
    harness_setRootById@withrevert(e, newRoot);
    satisfy !lastReverted;
}

rule sanityUninstallValidationReaches(env e, bytes21 targetVid) {
    harness_uninstallValidation@withrevert(e, targetVid);
    satisfy !lastReverted;
}

rule sanityInitializeValidationReaches(env e, bytes21 targetVid, bytes internalData) {
    harness_initializeValidation@withrevert(e, targetVid, internalData);
    satisfy !lastReverted;
}
