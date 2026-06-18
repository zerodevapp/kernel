// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {ValidationId, ValidationType, ValidationMode, PermissionId} from "src/types/Types.sol";
import {ValidationInfo, ValidationStorage} from "src/types/Structs.sol";
import {IHook, IExecutor} from "src/interfaces/IERC7579Modules.sol";
import {CallType} from "src/types/Types.sol";
import {ExecutorStorage, SelectorStorage, HookStorage} from "src/types/Structs.sol";
import {parseNonce, getType, permissionToIdentifier} from "src/lib/Utils.sol";
import {
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    VALIDATION_MANAGER_STORAGE_SLOT,
    EXECUTOR_MANAGER_STORAGE_SLOT,
    SELECTOR_MANAGER_STORAGE_SLOT,
    HOOK_MANAGER_STORAGE_SLOT,
    HOOK_MODULE_NOT_INSTALLED,
    HOOK_MODULE_INSTALLED_NO_HOOK
} from "src/types/Constants.sol";

/// @title KernelHarness — Certora-only wrapper exposing internal views.
/// @notice DO NOT DEPLOY. Used only for formal verification. Adds public
///         accessors over the namespaced ValidationStorage so CVL rules can
///         read nonce / allowed entries without bypassing the production
///         storage layout, plus pure helpers that re-export `parseNonce`,
///         module-type constants, and `bytes4(op.callData[0:4]/[4:8])`
///         extraction. Production logic in `validateUserOp` / `executeUserOp`
///         is unchanged; the harness only adds new external read functions.
contract KernelHarness is KernelUUPS {
    constructor(IEntryPoint _entryPoint) KernelUUPS(_entryPoint) {}

    // ------------------------------------------------------------------
    // Storage accessors (mirror ValidationManager._allowedSelector / _validationStorage)
    // ------------------------------------------------------------------

    function harness_vInfoNonce(bytes21 vId) external view returns (uint32) {
        return _vs().vInfo[ValidationId.wrap(vId)].nonce;
    }

    function harness_vInfoHook(bytes21 vId) external view returns (address) {
        return _vs().vInfo[ValidationId.wrap(vId)].hook;
    }

    function harness_allowedNonce(bytes21 vId, bytes4 sel) external view returns (uint32) {
        return _vs().allowed[ValidationId.wrap(vId)][sel];
    }

    function harness_allowedSelector(bytes21 vId, bytes4 sel) external view returns (bool) {
        ValidationStorage storage $ = _vs();
        ValidationId v = ValidationId.wrap(vId);
        return $.allowed[v][sel] == $.vInfo[v].nonce;
    }

    function harness_root() external view returns (bytes21) {
        return ValidationId.unwrap(_vs().root);
    }

    // ------------------------------------------------------------------
    // Permission-state accessors (used by SetRootLifo property).
    // ------------------------------------------------------------------

    /// @notice The number of policies installed under `vId`'s permission entry.
    function harness_vInfoPoliciesLength(bytes21 vId) external view returns (uint256) {
        return _vs().vInfo[ValidationId.wrap(vId)].policies.length;
    }

    /// @notice The signer module installed for `vId` (only meaningful for permission vIds).
    function harness_vInfoSigner(bytes21 vId) external view returns (address) {
        return _vs().vInfo[ValidationId.wrap(vId)].signer;
    }

    /// @notice Returns the policy address stored at index `i` for `vId`'s permission entry.
    /// @dev Reverts (out of bounds) if `i >= policies.length`.
    function harness_vInfoPolicyAt(bytes21 vId, uint256 i) external view returns (address) {
        return _vs().vInfo[ValidationId.wrap(vId)].policies[i];
    }

    /// @notice Returns the ValidationType (first byte) of a ValidationId.
    function harness_getType(bytes21 vId) external pure returns (bytes1) {
        return ValidationType.unwrap(getType(ValidationId.wrap(vId)));
    }

    /// @notice Encodes a 4-byte PermissionId into the corresponding permission-type ValidationId.
    function harness_permissionToVid(bytes4 permissionId) external pure returns (bytes21) {
        return ValidationId.unwrap(permissionToIdentifier(PermissionId.wrap(permissionId)));
    }

    // ------------------------------------------------------------------
    // Pure helpers.
    // ------------------------------------------------------------------

    function harness_parseVType(uint256 nonce) external pure returns (bytes1) {
        (, ValidationType vType,) = parseNonce(nonce);
        return ValidationType.unwrap(vType);
    }

    function harness_parseVId(uint256 nonce) external pure returns (bytes21) {
        (,, ValidationId vId) = parseNonce(nonce);
        return ValidationId.unwrap(vId);
    }

    function harness_parseVMode(uint256 nonce) external pure returns (bytes1) {
        (ValidationMode vMode,,) = parseNonce(nonce);
        return ValidationMode.unwrap(vMode);
    }

    function harness_validationHook(bytes32 userOpHash) external view returns (address) {
        IHook h;
        assembly {
            h := tload(userOpHash)
        }
        return address(h);
    }

    // ------------------------------------------------------------------
    // Constant exposers.
    // ------------------------------------------------------------------

    function harness_VT_ROOT() external pure returns (bytes1) {
        return ValidationType.unwrap(VALIDATION_TYPE_ROOT);
    }

    function harness_VT_VALIDATOR() external pure returns (bytes1) {
        return ValidationType.unwrap(VALIDATION_TYPE_VALIDATOR);
    }

    function harness_VT_PERMISSION() external pure returns (bytes1) {
        return ValidationType.unwrap(VALIDATION_TYPE_PERMISSION);
    }

    function harness_HOOK_NOT_INSTALLED() external pure returns (address) {
        return HOOK_MODULE_NOT_INSTALLED;
    }

    function harness_HOOK_INSTALLED_NO_HOOK() external pure returns (address) {
        return HOOK_MODULE_INSTALLED_NO_HOOK;
    }

    function harness_executeUserOpSelector() external pure returns (bytes4) {
        return this.executeUserOp.selector;
    }

    function harness_isEnableMode(uint256 nonce) external pure returns (bool) {
        (ValidationMode vMode,,) = parseNonce(nonce);
        return ValidationMode.unwrap(vMode) & bytes1(0x08) != 0;
    }

    function harness_isReplayableMode(uint256 nonce) external pure returns (bool) {
        (ValidationMode vMode,,) = parseNonce(nonce);
        return ValidationMode.unwrap(vMode) & bytes1(0x40) != 0;
    }

    // ------------------------------------------------------------------
    // Extraction helpers — return the (outer, inner) selectors of a
    // PackedUserOperation calldata, mirroring how validateUserOp / executeUserOp
    // read them. Reverts if calldata is too short.
    // ------------------------------------------------------------------

    function harness_outerSelector(PackedUserOperation calldata op) external pure returns (bytes4) {
        require(op.callData.length >= 4, "callData<4");
        return bytes4(op.callData[0:4]);
    }

    function harness_innerSelector(PackedUserOperation calldata op) external pure returns (bytes4) {
        require(op.callData.length >= 8, "callData<8");
        return bytes4(op.callData[4:8]);
    }

    function harness_callDataLength(PackedUserOperation calldata op) external pure returns (uint256) {
        return op.callData.length;
    }

    // ------------------------------------------------------------------
    // Wrappers exposing the view (ERC-1271) and write (ERC-4337) permission
    // paths. Used by certora/specs/PermissionEquivalence.spec to compare the
    // two aggregate `validationData` results for the same inputs.
    //
    // Both functions read the same ValidationInfo (vInfo[vId]) and the same
    // PermissionId-derived `paddedVId`, iterate `vInfo[vId].policies` in the
    // same order, and intersect via Lib4337.intersectValidationData. The
    // STRUCTURAL difference is which external interface methods they invoke:
    //
    //   view path :  IPolicy.checkSignaturePolicy(paddedVId, requester, hash, sig)
    //                ISigner.checkSignature(paddedVId, requester, hash, sig)    -> bytes4
    //   write path:  IPolicy.checkUserOpPolicy(paddedVId, op)                   -> uint256
    //                ISigner.checkUserOpSignature(paddedVId, op, opHash)        -> uint256
    //
    // The audit property is "kernel-side framing is identical." The spec
    // CVL-summarises the four module entry points to a shared ghost so that,
    // under the assumption each module is deterministic with respect to its
    // inputs, the two paths must produce the same aggregate -- unless the
    // kernel itself diverges. Any divergence is a HIGH-severity finding.
    function harness_verifySignaturePermission(bytes21 vId, address requester, bytes32 hash, bytes calldata signature)
        external
        view
        returns (uint256)
    {
        ValidationStorage storage $ = _vs();
        ValidationId v = ValidationId.wrap(vId);
        return _verifySignaturePermission(v, $.vInfo[v], requester, hash, signature);
    }

    function harness_validateUserOpPermission(
        bytes21 vId,
        bytes32 opHash,
        PackedUserOperation memory op,
        bytes calldata userOpSignature
    ) external returns (uint256) {
        return _validateUserOpPermission(ValidationId.wrap(vId), opHash, op, userOpSignature);
    }

    // Length of the policies array for a vId (used as a loop bound in CVL).
    function harness_policiesLength(bytes21 vId) external view returns (uint256) {
        return _vs().vInfo[ValidationId.wrap(vId)].policies.length;
    }

    function harness_policyAt(bytes21 vId, uint256 i) external view returns (address) {
        return _vs().vInfo[ValidationId.wrap(vId)].policies[i];
    }

    function harness_signer(bytes21 vId) external view returns (address) {
        return _vs().vInfo[ValidationId.wrap(vId)].signer;
    }

    // ------------------------------------------------------------------
    // Writer-local invariant wrappers (Phase C Round 2)
    //
    // These expose the four ValidationStorage writers as external functions so
    // CVL rules can call exactly one writer at a time. The wrappers preserve
    // production semantics 1:1 -- they only adapt the parameter type
    // (bytes21 / ValidationId / Install) at the boundary.
    //
    // The four writers (verified by static grep over src/ on 2026-05-21):
    //   1. _grantAccess(vId, selectors)                  -- ValidationManager.sol:101
    //   2. _setRoot(vId)                                 -- ValidationManager.sol:461
    //   3. _uninstallValidation(_vId)                    -- ValidationManager.sol:210
    //   4. _initializeValidation(vId, _internalData)     -- ValidationManager.sol:125
    //
    // No other path writes $.allowed, $.vInfo[*].nonce, $.vInfo[*].hook, or
    // $.root. Public entry points (installModule, executeUserOp, etc.) reach
    // these writers via internal call chains, but the writers themselves are
    // the only place where the relevant storage slots are mutated.
    // ------------------------------------------------------------------

    function harness_grantAccess(bytes21 vId, bytes calldata selectors) external {
        _grantAccess(ValidationId.wrap(vId), selectors);
    }

    function harness_setRootById(bytes21 vId) external {
        _setRoot(ValidationId.wrap(vId));
    }

    function harness_uninstallValidation(bytes21 vId) external {
        _uninstallValidation(ValidationId.wrap(vId));
    }

    function harness_initializeValidation(bytes21 vId, bytes calldata internalData) external {
        _initializeValidation(ValidationId.wrap(vId), internalData);
    }

    // ------------------------------------------------------------------
    // Module-storage accessors (Phase 2 — ExecutorManager / SelectorManager /
    // HookManager). Mirror the production storage layout reads so CVL can
    // observe the per-slot post-state of each module writer.
    // ------------------------------------------------------------------

    function harness_executorHook(address executor) external view returns (address) {
        return address(_es().executorConfig[IExecutor(executor)].hook);
    }

    function harness_selectorTarget(bytes4 selector) external view returns (address) {
        return _ss().selectorConfig[selector].target;
    }

    function harness_selectorHook(bytes4 selector) external view returns (address) {
        return address(_ss().selectorConfig[selector].hook);
    }

    function harness_selectorCallType(bytes4 selector) external view returns (bytes1) {
        return CallType.unwrap(_ss().selectorConfig[selector].callType);
    }

    function harness_hookEnabled(address hook) external view returns (bool) {
        return _hs().enabled[hook];
    }

    /// @notice Returns `bytes4(_internalData[0:4])` -- the selector key
    /// that `_installSelector` / `_uninstallSelector` derive from
    /// internalData. Pure projection; reverts if length < 4.
    function harness_internalDataSelector(bytes calldata internalData) external pure returns (bytes4) {
        return bytes4(internalData[0:4]);
    }

    // ------------------------------------------------------------------
    // Writer wrappers for the six module writers covered by
    // certora/specs/ModuleWriters.spec. Each wrapper preserves production
    // semantics 1:1; the wrapper exists only so CVL rules can call exactly
    // one writer at a time with arbitrary symbolic inputs.
    //
    // The writers (verified by static grep over src/core/ on 2026-05-24):
    //   1. _installExecutor(_executor, _internalData, _installSuccess)   -- ExecutorManager.sol:41
    //   2. _uninstallExecutor(_executor, _, _)                           -- ExecutorManager.sol:54
    //   3. _installSelector(_module, _internalData, _installSuccess)     -- SelectorManager.sol:45
    //   4. _uninstallSelector(_, _internalData, _)                       -- SelectorManager.sol:62
    //   5. _installHook(_hook, _internalData, _installSuccess)           -- HookManager.sol:36
    //   6. _uninstallHook(_hook, _, _)                                   -- HookManager.sol:45
    //
    // No other code path writes ExecutorStorage, SelectorStorage, or
    // HookStorage in src/. Verified by grep on 2026-05-24.
    // ------------------------------------------------------------------

    function harness_installExecutor(address executor, bytes calldata internalData, bool installSuccess) external {
        _installExecutor(executor, internalData, installSuccess);
    }

    function harness_uninstallExecutor(address executor, bytes calldata internalData, bool installSuccess) external {
        _uninstallExecutor(executor, internalData, installSuccess);
    }

    function harness_installSelector(address module, bytes calldata internalData, bool installSuccess) external {
        _installSelector(module, internalData, installSuccess);
    }

    function harness_uninstallSelector(address module, bytes calldata internalData, bool installSuccess) external {
        _uninstallSelector(module, internalData, installSuccess);
    }

    function harness_installHook(address hook, bytes calldata internalData, bool installSuccess) external {
        _installHook(hook, internalData, installSuccess);
    }

    function harness_uninstallHook(address hook, bytes calldata internalData, bool installSuccess) external {
        _uninstallHook(hook, internalData, installSuccess);
    }

    // ------------------------------------------------------------------
    // `_checkValidation` routing probes (FV Round 2, Phase 2)
    //
    // `_checkValidation(vType, vId)` returns `(ValidationId v, function-ptr
    // validateUserOp)`. CVL cannot directly inspect an internal Solidity
    // function pointer, AND direct `==` equality on internal function pointers
    // emits Solidity warning 3075 ("comparison can yield unexpected results in
    // the legacy pipeline with the optimizer enabled"). Foundry config uses
    // `via_ir = false` + `optimizer = true`, so `==` is unsound here.
    //
    // Approach used: a single wrapper INVOKES the returned function pointer
    // with dummy arguments. Combined with per-function CVL summaries that
    // return DISTINCT sentinel values, the wrapper's return value identifies
    // which validateUserOp* was routed without any function-pointer equality.
    //
    //   Summary mapping (in CheckValidation.spec):
    //     _validateUserOpValidator   => returns 7      (ROUTE_VALIDATOR)
    //     _validateUserOpPermission  => returns 11     (ROUTE_PERMISSION)
    //     _validateUserOpFallback    => returns 13     (ROUTE_FALLBACK)
    //
    //   The wrapper returns whatever the routed function returns; the CVL
    //   rules assert the expected sentinel against the actual return.
    //
    // The wrapper resolves `_checkValidation` (which may revert on
    // uninstalled-validator paths — matching production behaviour), then
    // invokes the returned function pointer. The function pointer call is the
    // ONLY observation channel for the routing decision.
    //
    // `harness_checkValidationResolvedV` returns the resolved `v` (the first
    // tuple element) separately, so rules can also assert recursion-target
    // identity (e.g. ROOT branch resolves `v = $.root`).
    //
    // `harness_fallbackAvailable` exposes the virtual predicate that
    // `_setRoot` enforces but `_checkValidation` itself does NOT re-check.
    //
    // VALIDATION_TYPE_FALLBACK (0x00) and VALIDATION_TYPE_ROOT (0x00) ALIAS to
    // the same byte value. Both enter the same first-branch in
    // `_checkValidation`. So routing to `_validateUserOpFallback` is reachable
    // only via the ROOT branch with `$.root == 0`.
    // ------------------------------------------------------------------

    function harness_checkValidationResolvedV(bytes1 vType, bytes21 vId) external view returns (bytes21) {
        (ValidationId v,) = _checkValidation(ValidationType.wrap(vType), ValidationId.wrap(vId));
        return ValidationId.unwrap(v);
    }

    /// @notice Invokes `_checkValidation` and then calls the returned function
    ///         pointer with dummy arguments. With the spec's per-function
    ///         summaries returning distinct sentinels, the return value
    ///         identifies the routed function.
    function harness_invokeCheckValidationRoute(bytes1 vType, bytes21 vId) external returns (uint256) {
        (
            ValidationId v,
            function(ValidationId, bytes32, PackedUserOperation memory, bytes calldata) internal returns (uint256) f
        ) = _checkValidation(ValidationType.wrap(vType), ValidationId.wrap(vId));
        PackedUserOperation memory op;
        return f(v, bytes32(0), op, msg.data[0:0]);
    }

    function harness_fallbackAvailable() external pure returns (bool) {
        return _fallbackValidatorAvailable();
    }

    function harness_VT_FALLBACK() external pure returns (bytes1) {
        // VALIDATION_TYPE_FALLBACK and VALIDATION_TYPE_ROOT alias to 0x00.
        return bytes1(0x00);
    }

    // ------------------------------------------------------------------
    function _vs() internal pure returns (ValidationStorage storage $) {
        bytes32 slot = VALIDATION_MANAGER_STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }

    function _es() internal pure returns (ExecutorStorage storage $) {
        bytes32 slot = EXECUTOR_MANAGER_STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }

    function _ss() internal pure returns (SelectorStorage storage $) {
        bytes32 slot = SELECTOR_MANAGER_STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }

    function _hs() internal pure returns (HookStorage storage $) {
        bytes32 slot = HOOK_MANAGER_STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }
}
