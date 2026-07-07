/* SPDX-License-Identifier: MIT */

/**
 * Kernel v4 -- FV Round 2, Phase 2:
 *   `_checkValidation(vType, vId)` is a routing predicate in
 *   `src/core/ValidationManager.sol` (lines 268-296).
 *
 * AUDIT CLAIM
 *   `_checkValidation` selects the correct `validateUserOp*` dispatch
 *   function based on `vType`, and only returns successfully when the routed
 *   validation is installed.
 *
 * SPEC PER vType
 *   1. vType == VALIDATION_TYPE_VALIDATOR (0x01):
 *        resolves `v = vId`, requires `vInfo[vId].hook > HOOK_MODULE_NOT_INSTALLED`,
 *        and routes to `_validateUserOpValidator`.
 *   2. vType == VALIDATION_TYPE_PERMISSION (0x02):
 *        resolves `v = vId`, requires `vInfo[vId].hook > HOOK_MODULE_NOT_INSTALLED`,
 *        and routes to `_validateUserOpPermission`.
 *   3. vType == VALIDATION_TYPE_ROOT (0x00):
 *        a) if `$.root == 0`: returns `(0, _validateUserOpFallback)` WITHOUT
 *           checking the hook (the production invariant `$.root == 0 =>
 *           _fallbackValidatorAvailable()` is enforced by `_setRoot`, not by
 *           `_checkValidation`).
 *        b) otherwise: resolves `v = $.root`, requires `vInfo[$.root].hook >
 *           HOOK_MODULE_NOT_INSTALLED`, and routes by `getType($.root)`
 *           (VALIDATOR -> validator, PERMISSION -> permission).
 *   4. There is NO separate VALIDATION_TYPE_FALLBACK branch:
 *      `VALIDATION_TYPE_FALLBACK == VALIDATION_TYPE_ROOT == 0x00`. Both alias
 *      to the same byte. The fallback route is reachable only via the ROOT
 *      branch with `$.root == 0`.
 *
 * STRATEGY -- how we observe the function-pointer return
 *   CVL cannot directly inspect an internal Solidity function pointer, and
 *   `==` on internal function pointers emits Solidity warning 3075
 *   ("comparison can yield unexpected results in the legacy pipeline with
 *   the optimizer enabled"). The project's `via_ir = false` + `optimizer =
 *   true` config means `==` is unsound.
 *
 *   Instead, the harness wrapper `harness_invokeCheckValidationRoute(vType,
 *   vId)` invokes the returned function pointer with dummy arguments. With
 *   per-function CVL summaries returning DISTINCT sentinel values
 *   (7 / 11 / 13), the wrapper's return value identifies which `validateUserOp*`
 *   was routed. The resolved `v` (first tuple element) is exposed separately
 *   via `harness_checkValidationResolvedV`.
 *
 *   Sentinels chosen as small primes to make CEX traces self-documenting.
 *
 * NARROWINGS
 *   - `_validateUserOpValidator/Permission/Fallback` are summarised to
 *     CONSTANT sentinels for routing identification. The summaries are
 *     SOUND for this property: we're not proving anything about what those
 *     functions COMPUTE, only which one is SELECTED.
 *   - `_fallbackValidatorAvailable` is virtual; the base ValidationManager
 *     returns `false`. The harness exposes it via `harness_fallbackAvailable`
 *     so the spec can reason about both production variants. Notably,
 *     `_checkValidation` itself does NOT consult this predicate.
 *
 * Verified contract: KernelHarness (extends KernelUUPS). Harness adds the
 * routing-probe wrappers; production logic is unchanged.
 */

// --------------------------------------------------------------------------
// Sentinel constants used by the per-function CVL summaries to identify the
// routed function via the harness wrapper's return value.
//
// Small primes are deliberately chosen: any CEX trace will display the literal
// returned uint, making the route immediately self-documenting.
// --------------------------------------------------------------------------
definition ROUTE_VALIDATOR()  returns uint256 = 7;
definition ROUTE_PERMISSION() returns uint256 = 11;
definition ROUTE_FALLBACK()   returns uint256 = 13;

methods {
    // Routing probes (Phase 2 harness additions).
    function harness_checkValidationResolvedV(bytes1, bytes21)
        external returns (bytes21) envfree;
    function harness_invokeCheckValidationRoute(bytes1, bytes21)
        external returns (uint256);

    // State accessors.
    function harness_vInfoHook(bytes21)         external returns (address) envfree;
    function harness_root()                     external returns (bytes21) envfree;
    function harness_getType(bytes21)           external returns (bytes1)  envfree;
    function harness_fallbackAvailable()        external returns (bool)    envfree;

    // Constant exposers.
    function harness_VT_ROOT()                external returns (bytes1) envfree;
    function harness_VT_VALIDATOR()           external returns (bytes1) envfree;
    function harness_VT_PERMISSION()          external returns (bytes1) envfree;
    function harness_VT_FALLBACK()            external returns (bytes1) envfree;
    function harness_HOOK_NOT_INSTALLED()     external returns (address) envfree;
    function harness_HOOK_INSTALLED_NO_HOOK() external returns (address) envfree;

    // --- Per-function summaries that return DISTINCT sentinels ---
    // These are the SOLE observation channel for which function `_checkValidation`
    // routed to. The harness wrapper invokes the returned pointer with dummy
    // args and surfaces the sentinel as its return value.
    //
    // CVL allows constant literal expressions as summary bodies. We use the
    // ROUTE_* definitions for readability.
    function ValidationManager._validateUserOpValidator(
        KernelHarness.ValidationId, bytes32, KernelHarness.PackedUserOperation memory, bytes calldata
    ) internal returns (uint256) => ROUTE_VALIDATOR();
    function ValidationManager._validateUserOpPermission(
        KernelHarness.ValidationId, bytes32, KernelHarness.PackedUserOperation memory, bytes calldata
    ) internal returns (uint256) => ROUTE_PERMISSION();
    function ValidationManager._validateUserOpFallback(
        KernelHarness.ValidationId, bytes32, KernelHarness.PackedUserOperation memory, bytes calldata
    ) internal returns (uint256) => ROUTE_FALLBACK();
}

// ===========================================================================
// RULE 1a -- VALIDATOR branch resolves `v = vId`.
//
// Precondition:
//   vType == VALIDATION_TYPE_VALIDATOR
//   vInfo[vId].hook > HOOK_MODULE_NOT_INSTALLED   (installed)
//
// Postcondition: harness_checkValidationResolvedV(vType, vId) == vId
//
// The hook precondition matches the production require:
//   require(info.hook > HOOK_MODULE_NOT_INSTALLED, InvalidVid(v));
// HOOK_MODULE_NOT_INSTALLED is address(0); HOOK_MODULE_INSTALLED_NO_HOOK is
// address(1). "Installed" means hook is any non-zero address.
//
// Expected outcome: PASS.
// ===========================================================================
rule routeValidatorResolvesV(bytes21 vId) {
    bytes1 vType = harness_VT_VALIDATOR();
    require harness_vInfoHook(vId) != harness_HOOK_NOT_INSTALLED();
    bytes21 v = harness_checkValidationResolvedV(vType, vId);
    assert v == vId, "VALIDATOR branch should resolve v = vId";
}

// ===========================================================================
// RULE 1b -- VALIDATOR branch routes to _validateUserOpValidator.
//
// Precondition: same as 1a.
// Postcondition: harness_invokeCheckValidationRoute returns ROUTE_VALIDATOR
//
// Expected outcome: PASS.
// ===========================================================================
rule routeValidatorRoutesValidator(bytes21 vId) {
    env e;
    bytes1 vType = harness_VT_VALIDATOR();
    require harness_vInfoHook(vId) != harness_HOOK_NOT_INSTALLED();
    uint256 route = harness_invokeCheckValidationRoute(e, vType, vId);
    assert route == ROUTE_VALIDATOR(),
        "VALIDATOR branch should route to _validateUserOpValidator";
}

// ===========================================================================
// RULE 2a -- PERMISSION branch resolves `v = vId`.
//
// Precondition:
//   vType == VALIDATION_TYPE_PERMISSION
//   vInfo[vId].hook > HOOK_MODULE_NOT_INSTALLED
//
// Postcondition: harness_checkValidationResolvedV == vId
//
// Expected outcome: PASS.
// ===========================================================================
rule routePermissionResolvesV(bytes21 vId) {
    bytes1 vType = harness_VT_PERMISSION();
    require harness_vInfoHook(vId) != harness_HOOK_NOT_INSTALLED();
    bytes21 v = harness_checkValidationResolvedV(vType, vId);
    assert v == vId, "PERMISSION branch should resolve v = vId";
}

// ===========================================================================
// RULE 2b -- PERMISSION branch routes to _validateUserOpPermission.
//
// Precondition: same as 2a.
// Postcondition: route == ROUTE_PERMISSION
//
// Expected outcome: PASS.
// ===========================================================================
rule routePermissionRoutesPermission(bytes21 vId) {
    env e;
    bytes1 vType = harness_VT_PERMISSION();
    require harness_vInfoHook(vId) != harness_HOOK_NOT_INSTALLED();
    uint256 route = harness_invokeCheckValidationRoute(e, vType, vId);
    assert route == ROUTE_PERMISSION(),
        "PERMISSION branch should route to _validateUserOpPermission";
}

// ===========================================================================
// RULE 3a -- ROOT branch resolves `v = $.root` when root is set.
//
// Precondition:
//   vType == VALIDATION_TYPE_ROOT
//   $.root != bytes21(0)
//   vInfo[$.root].hook > HOOK_MODULE_NOT_INSTALLED
//   getType($.root) ∈ {VALIDATOR, PERMISSION}
//
// Postcondition:
//   harness_checkValidationResolvedV == $.root
//
// Expected outcome: PASS.
// ===========================================================================
rule routeRootResolvesV {
    bytes1  vTypeRoot = harness_VT_ROOT();
    bytes21 anyVid;          // ignored by the ROOT branch (v gets rewritten to $.root)

    bytes21 currentRoot = harness_root();
    require currentRoot != to_bytes21(0);
    require harness_vInfoHook(currentRoot) != harness_HOOK_NOT_INSTALLED();
    bytes1 rootType = harness_getType(currentRoot);
    require rootType == harness_VT_VALIDATOR() || rootType == harness_VT_PERMISSION();

    bytes21 v = harness_checkValidationResolvedV(vTypeRoot, anyVid);
    assert v == currentRoot, "ROOT branch should resolve v = $.root";
}

// ===========================================================================
// RULE 3b -- ROOT-of-VALIDATOR routes to _validateUserOpValidator.
//
// This is the recursive case: ROOT branch rewrites vType to getType($.root),
// then dispatches. When getType($.root) == VALIDATOR, the function should
// route through the validator path. Captures the "ROOT routing follows the
// type encoded in $.root" semantics.
//
// Expected outcome: PASS.
// ===========================================================================
rule routeRootOfValidatorRoutesValidator {
    env e;
    bytes1  vTypeRoot = harness_VT_ROOT();
    bytes21 anyVid;

    bytes21 currentRoot = harness_root();
    require currentRoot != to_bytes21(0);
    require harness_vInfoHook(currentRoot) != harness_HOOK_NOT_INSTALLED();
    require harness_getType(currentRoot) == harness_VT_VALIDATOR();

    uint256 route = harness_invokeCheckValidationRoute(e, vTypeRoot, anyVid);
    assert route == ROUTE_VALIDATOR(),
        "ROOT-of-VALIDATOR should route to _validateUserOpValidator";
}

// ===========================================================================
// RULE 3c -- ROOT-of-PERMISSION routes to _validateUserOpPermission.
//
// Mirror of 3b for the permission case.
//
// Expected outcome: PASS.
// ===========================================================================
rule routeRootOfPermissionRoutesPermission {
    env e;
    bytes1  vTypeRoot = harness_VT_ROOT();
    bytes21 anyVid;

    bytes21 currentRoot = harness_root();
    require currentRoot != to_bytes21(0);
    require harness_vInfoHook(currentRoot) != harness_HOOK_NOT_INSTALLED();
    require harness_getType(currentRoot) == harness_VT_PERMISSION();

    uint256 route = harness_invokeCheckValidationRoute(e, vTypeRoot, anyVid);
    assert route == ROUTE_PERMISSION(),
        "ROOT-of-PERMISSION should route to _validateUserOpPermission";
}

// ===========================================================================
// RULE 4a -- ROOT branch with `$.root == 0` resolves `v = bytes21(0)`.
//
// This rule captures the early-return branch in `_checkValidation`:
//     if (vType == VALIDATION_TYPE_ROOT) {
//         v = $.root;
//         if (ValidationId.unwrap(v) == bytes21(0)) {
//             return (v, _validateUserOpFallback);   // <-- here
//         }
//         ...
//     }
//
// Precondition:
//   vType == VALIDATION_TYPE_ROOT
//   $.root == bytes21(0)
//
// Postcondition: harness_checkValidationResolvedV == bytes21(0)
//
// Expected outcome: PASS.
// ===========================================================================
rule routeRootZeroResolvesZero {
    bytes1  vTypeRoot = harness_VT_ROOT();
    bytes21 anyVid;
    require harness_root() == to_bytes21(0);
    bytes21 v = harness_checkValidationResolvedV(vTypeRoot, anyVid);
    assert v == to_bytes21(0),
        "ROOT branch with $.root == 0 should resolve v = bytes21(0)";
}

// ===========================================================================
// RULE 4b -- ROOT branch with `$.root == 0` routes to _validateUserOpFallback.
//
// Precondition: same as 4a.
// Postcondition: route == ROUTE_FALLBACK
//
// IMPORTANT AUDIT NOTE:
//   `_checkValidation` does NOT consult `_fallbackValidatorAvailable()` here.
//   The production invariant `$.root == 0 => _fallbackValidatorAvailable()`
//   is enforced by `_setRoot` (line 463). If a deployment subclass can reach
//   `$.root == 0` while `_fallbackValidatorAvailable() == false`, the
//   fallback route returns successfully but the caller will then invoke
//   `_validateUserOpFallback` whose `_verifyFallbackSignature` override
//   decides the outcome. The base ValidationManager's override (in Kernel
//   itself) always returns false, so the call ultimately rejects -- but the
//   ROUTING decision is decoupled from availability.
//
// Expected outcome: PASS.
// ===========================================================================
rule routeRootZeroRoutesFallback {
    env e;
    bytes1  vTypeRoot = harness_VT_ROOT();
    bytes21 anyVid;
    require harness_root() == to_bytes21(0);
    uint256 route = harness_invokeCheckValidationRoute(e, vTypeRoot, anyVid);
    assert route == ROUTE_FALLBACK(),
        "ROOT branch with $.root == 0 should route to _validateUserOpFallback";
}

// ===========================================================================
// RULE 5 -- _checkValidation reverts for VALIDATOR/PERMISSION when the
// validation is not installed.
//
// Precondition:
//   vType ∈ {VALIDATION_TYPE_VALIDATOR, VALIDATION_TYPE_PERMISSION}
//   vInfo[vId].hook == HOOK_MODULE_NOT_INSTALLED
//
// Postcondition:
//   Both probe wrappers revert (the production require:
//     require(info.hook > HOOK_MODULE_NOT_INSTALLED, InvalidVid(v));
//   ).
//
// This is the "only succeeds when the routed validation is installed" half
// of the audit claim.
//
// Expected outcome: PASS.
// ===========================================================================
rule routeRevertsWhenNotInstalled(bytes21 vId, bool useValidator) {
    env e;
    bytes1 vType = useValidator ? harness_VT_VALIDATOR() : harness_VT_PERMISSION();

    require harness_vInfoHook(vId) == harness_HOOK_NOT_INSTALLED();

    harness_invokeCheckValidationRoute@withrevert(e, vType, vId);
    assert lastReverted,
        "Uninstalled VALIDATOR/PERMISSION should revert in _checkValidation";
}

// ===========================================================================
// RULE 6 -- HIGH-SEVERITY AUDIT CHECK
// `_validateUserOpFallback` is reached only when `$.root == 0`.
//
// This is the contrapositive of Rule 4 -- if the routed function is the
// fallback, then `$.root` MUST be zero. Captures the invariant that
// `_checkValidation` does NOT silently route to fallback for any non-ROOT
// vType (which would be a bug, since VALIDATOR/PERMISSION must dispatch to
// their respective handlers).
//
// NOTE: The base ValidationManager's `_fallbackValidatorAvailable() => false`
// implies `$.root != 0` for any installed root. If a subclass overrides
// `_fallbackValidatorAvailable()` to true AND `$.root` can become zero, then
// fallback routing is reachable. The rule asserts the structural property
// independently of the override.
//
// Precondition (any vType, any vId):
// Postcondition:
//   route == ROUTE_FALLBACK  =>  $.root == 0
//
// Expected outcome: PASS. If FAIL, the CEX reveals a state where fallback
// is dispatched for non-zero root -- a HIGH-severity routing bug.
// ===========================================================================
rule fallbackRoutedOnlyWhenRootZero(bytes1 vType, bytes21 vId) {
    env e;

    // Snapshot `$.root` BEFORE the probe call.
    bytes21 rootBefore = harness_root();

    uint256 route = harness_invokeCheckValidationRoute@withrevert(e, vType, vId);
    bool reverted = lastReverted;

    assert !reverted && route == ROUTE_FALLBACK() => rootBefore == to_bytes21(0),
        "Fallback routed but $.root != 0 -- routing bug";
}

// ===========================================================================
// SANITY -- exercise that the spec is not vacuous. There exists an input
// for which the wrapper succeeds and returns each of the three sentinels.
// ===========================================================================
rule sanityValidatorRouteReachable {
    env e;
    bytes21 vId;
    require harness_vInfoHook(vId) != harness_HOOK_NOT_INSTALLED();
    uint256 route = harness_invokeCheckValidationRoute(e, harness_VT_VALIDATOR(), vId);
    satisfy route == ROUTE_VALIDATOR();
}

rule sanityPermissionRouteReachable {
    env e;
    bytes21 vId;
    require harness_vInfoHook(vId) != harness_HOOK_NOT_INSTALLED();
    uint256 route = harness_invokeCheckValidationRoute(e, harness_VT_PERMISSION(), vId);
    satisfy route == ROUTE_PERMISSION();
}

rule sanityFallbackRouteReachable {
    env e;
    bytes21 anyVid;
    require harness_root() == to_bytes21(0);
    uint256 route = harness_invokeCheckValidationRoute(e, harness_VT_ROOT(), anyVid);
    satisfy route == ROUTE_FALLBACK();
}
