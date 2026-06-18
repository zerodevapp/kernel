/* SPDX-License-Identifier: MIT */

/**
 * Kernel v4 — Property #6: setRoot LIFO permission-cleanup
 *
 * SPEC CLAIM (audit/fv-gap-audit.md row #6):
 *   `setRoot(packages, removeCurrent=true, uninstallData)` invoked while the
 *   current root is a VALIDATION_TYPE_PERMISSION must, after the call:
 *     - vInfo[oldRoot].policies.length == 0
 *     - vInfo[oldRoot].signer == address(0)
 *     - vInfo[oldRoot].hook == HOOK_MODULE_NOT_INSTALLED
 *
 * The Kernel.sol implementation (lines 343-385) walks the policies array in
 * LIFO order (`for (i = policies.length; i > 0; i--)`) calling
 * `_uninstallPolicyWithVid` (which pops the last element) then finally
 * `_uninstallSignerWithVid` (which requires policies.length == 0, zeroes the
 * signer, and zeros the hook).
 *
 * This rule proves the multi-step state-machine property: starting from a
 * permission-type old root with K policies, after `setRoot(... removeCurrent
 * = true ...)` returns successfully the old root's permission state is
 * fully cleared.
 *
 * NARROWINGS (documented for orchestrator):
 *   - `optimistic_loop=true` + `loop_iter=3` means we structurally bound the
 *     symbolic loop unrolling to 3 iterations. For loops over
 *     `policies.length` that exceed 3, Certora treats them as unbounded and
 *     `optimistic_loop` axiomatises termination. This is the same pitfall
 *     baked into conf/Kernel.conf and matches the project convention.
 *   - External module callbacks (onUninstall) are AUTO HAVOC. The kernel's
 *     `_onlyEntryPointOrSelf` modifier prevents reentrancy back into
 *     ValidationStorage, so AUTO HAVOC is a sound over-approximation.
 *   - `Lib4337.intersectValidationData` and the internal validator summaries
 *     are NONDET (matching conf/Kernel.conf). The setRoot path does not
 *     invoke them.
 *   - The `_install(pkg)` pre-pass is real production code. To keep the
 *     proof tractable, the rule constrains pkg to a single package of
 *     module type validator (not policy/signer), so the install pass does
 *     NOT touch the old-root permission entry. The LIFO-cleanup property
 *     is independent of what type of package replaces the old root — only
 *     that the old root is a permission with non-empty policies.
 *
 * Verified contract: KernelHarness (extends KernelUUPS). Harness adds
 * read-only accessors for vInfo[vId].{policies.length, signer, hook}.
 */

methods {
    // Harness accessors used by the rule.
    function harness_vInfoNonce(bytes21)              external returns (uint32)  envfree;
    function harness_vInfoHook(bytes21)               external returns (address) envfree;
    function harness_vInfoSigner(bytes21)             external returns (address) envfree;
    function harness_vInfoPoliciesLength(bytes21)     external returns (uint256) envfree;
    function harness_vInfoPolicyAt(bytes21, uint256)  external returns (address) envfree;
    function harness_root()                           external returns (bytes21) envfree;
    function harness_getType(bytes21)                 external returns (bytes1)  envfree;
    function harness_permissionToVid(bytes4)          external returns (bytes21) envfree;

    function harness_VT_VALIDATOR()           external returns (bytes1)  envfree;
    function harness_VT_PERMISSION()          external returns (bytes1)  envfree;
    function harness_HOOK_NOT_INSTALLED()     external returns (address) envfree;
    function harness_HOOK_INSTALLED_NO_HOOK() external returns (address) envfree;

    // Disambiguate the two `setRoot` overloads on Kernel.sol so the rule can
    // call the one taking (Install[], bool, bytes). The other overload takes
    // a single ValidationId argument.
    function setRoot(KernelHarness.Install[], bool, bytes) external;
    function setRoot(bytes21) external;

    // Internal summaries to match conf/Kernel.conf. setRoot does not invoke
    // these (they're only reachable through validateUserOp), but they're
    // listed for consistency with the Kernel.spec configuration.
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

// --------------------------------------------------------------------------
// Rule: setRootClearsOldPermissionState
//
// PROOF OBLIGATION:
//   Pre:
//     - $.root != 0, root is permission-type
//     - policies.length > 0
//     - removeCurrent == true
//     - the new root package is validator-type (so install pass doesn't
//       touch the old permission entry)
//   Action: setRoot(pkg, true, uninstallData)
//   Post (on success):
//     - vInfo[oldRoot].policies.length == 0
//     - vInfo[oldRoot].signer == 0
//     - vInfo[oldRoot].hook == HOOK_MODULE_NOT_INSTALLED
//
// The `loop_iter=3` config bounds the symbolic unrolling at 3 iterations.
// `optimistic_loop=true` axiomatises termination beyond that bound. The
// rule is therefore proved up to policies.length <= loop_iter, with
// optimistic-loop fall-through above. To gain confidence at greater
// depth, bump `loop_iter` (documented trade-off).
// --------------------------------------------------------------------------
rule setRootClearsOldPermissionState(
    env e,
    KernelHarness.Install[] pkg,
    bool removeCurrent,
    bytes uninstallData
) {
    bytes21 oldRoot = harness_root();

    // The current root must be an installed permission-type ValidationId.
    require oldRoot != to_bytes21(0);
    require harness_getType(oldRoot) == harness_VT_PERMISSION();
    require harness_vInfoHook(oldRoot) != harness_HOOK_NOT_INSTALLED();

    // Permission has at least one policy installed.
    require harness_vInfoPoliciesLength(oldRoot) > 0;

    // The action is `removeCurrent = true`.
    require removeCurrent;

    // The replacement package is a validator (moduleType == 1). This ensures
    // the pre-pass `_install(pkg)` does not push into vInfo[oldRoot].policies.
    require pkg.length == 1;
    require pkg[0].moduleType == 1;

    // The new validator must differ from the old permission's identifier so
    // that the resulting root != oldRoot and `_setRoot` actually rotates.
    // (We cannot directly compute the new validator vid here; instead we
    // observe that a validator-type vId has first-byte 0x01 while the
    // permission-type oldRoot has first-byte 0x02, so they're necessarily
    // distinct — no extra precondition needed.)

    setRoot@withrevert(e, pkg, removeCurrent, uninstallData);
    bool reverted = lastReverted;

    // The cleanup post-condition must hold on every non-reverting path.
    assert !reverted => harness_vInfoPoliciesLength(oldRoot) == 0,
        "old permission policies.length not cleared";
    assert !reverted => harness_vInfoSigner(oldRoot) == 0,
        "old permission signer not zeroed";
    assert !reverted => harness_vInfoHook(oldRoot) == harness_HOOK_NOT_INSTALLED(),
        "old permission hook not zeroed";
}

// --------------------------------------------------------------------------
// Sanity rule: ensure the setRoot precondition is satisfiable.
// If this rule cannot find a satisfying execution, the main rule is
// vacuous and provides no real evidence.
// --------------------------------------------------------------------------
rule sanitySetRootReachesSuccess(
    env e,
    KernelHarness.Install[] pkg,
    bool removeCurrent,
    bytes uninstallData
) {
    bytes21 oldRoot = harness_root();
    require oldRoot != to_bytes21(0);
    require harness_getType(oldRoot) == harness_VT_PERMISSION();
    require harness_vInfoHook(oldRoot) != harness_HOOK_NOT_INSTALLED();
    require harness_vInfoPoliciesLength(oldRoot) > 0;
    require removeCurrent;
    require pkg.length == 1;
    require pkg[0].moduleType == 1;

    setRoot@withrevert(e, pkg, removeCurrent, uninstallData);
    satisfy !lastReverted;
}
