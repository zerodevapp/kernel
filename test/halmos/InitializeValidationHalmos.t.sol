// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

import {ValidationManager} from "src/core/ValidationManager.sol";
import {IHook} from "src/interfaces/IERC7579Modules.sol";
import {ValidationStorage} from "src/types/Structs.sol";
import {ValidationId} from "src/types/Types.sol";

/// @notice Test harness exposing `_initializeValidation` and a nonce getter.
/// @dev The override of `_hookEnabled` lets us treat hook validity symbolically.
contract InitializeValidationHarness is ValidationManager {
    // Symbolic toggle used by the test to either allow any hook or simulate a
    // disabled hook. Halmos can branch on this if the test exposes it.
    bool public hookAlwaysEnabled;

    function setHookAlwaysEnabled(bool v) external {
        hookAlwaysEnabled = v;
    }

    function _hookEnabled(
        IHook /*_hook*/
    )
        internal
        view
        override
        returns (bool)
    {
        return hookAlwaysEnabled;
    }

    /// @notice Public wrapper around the internal `_initializeValidation`.
    function initializeValidation(ValidationId vId, bytes calldata _internalData) external {
        _initializeValidation(vId, _internalData);
    }

    /// @notice Direct read of `vInfo[vId].nonce` from the namespaced storage slot.
    function nonceOf(ValidationId vId) external view returns (uint32) {
        ValidationStorage storage $ = _validationStorage();
        return $.vInfo[vId].nonce;
    }

    /// @notice Direct read of `vInfo[vId].hook`.
    function hookOf(ValidationId vId) external view returns (address) {
        ValidationStorage storage $ = _validationStorage();
        return $.vInfo[vId].hook;
    }

    /// @notice Manually clear hook to satisfy the OccupiedValidationId precondition
    /// without going through full install/uninstall. Used by setUp only.
    function sudoSetHook(ValidationId vId, address h) external {
        ValidationStorage storage $ = _validationStorage();
        $.vInfo[vId].hook = h;
    }

    /// @notice Manually seed the pre-state nonce so Halmos can explore arbitrary
    /// pre-nonces (otherwise the storage slot is concretely zero).
    function sudoSetNonce(ValidationId vId, uint32 n) external {
        ValidationStorage storage $ = _validationStorage();
        $.vInfo[vId].nonce = n;
    }
}

/// @notice Halmos proofs for `ValidationManager._initializeValidation`.
///
/// Property (per FV plan):
///   After a successful call, `vInfo[vId].nonce_post == vInfo[vId].nonce_pre + 1`.
///   Two paths are dispatched:
///     1. Empty `_internalData` (early return).
///     2. Non-empty `_internalData` (hook + selectors path).
///
/// Implementation reality:
///   - Empty path: the function returns early WITHOUT bumping nonce.
///   - Non-empty path: `_grantAccess` performs `++nonce` exactly once.
///
/// The empty-path check is expected to produce a counterexample. That
/// counterexample is the security finding: a fresh `_initializeValidation`
/// with empty data leaves stale `allowed[vId][selector]` entries from a
/// prior install reachable, because the nonce that gates them is unchanged.
contract InitializeValidationHalmos is SymTest, Test {
    InitializeValidationHarness harness;

    function setUp() external {
        harness = new InitializeValidationHarness();
    }

    /// @notice EMPTY-DATA path: bumps nonce by exactly 1.
    /// @dev Expected to fail with a counterexample, exposing the zero-bump bug
    ///      where re-initialization with empty data preserves stale allowed[] entries.
    function checkInitializeValidationBumpsByOneEmptyData() external {
        ValidationId vId = ValidationId.wrap(bytes21(svm.createBytes32("vId")));
        uint32 preNonce = uint32(svm.createUint(32, "preNonce"));

        // Precondition: slot is empty (not OccupiedValidationId).
        harness.sudoSetHook(vId, address(0));
        harness.sudoSetNonce(vId, preNonce);

        // Avoid 32-bit overflow in the post-condition arithmetic.
        vm.assume(preNonce < type(uint32).max);

        bytes memory empty = "";
        harness.initializeValidation(vId, empty);

        uint32 postNonce = harness.nonceOf(vId);
        assertEq(uint256(postNonce), uint256(preNonce) + 1, "empty data must bump nonce by 1");
    }

    /// @notice NON-EMPTY path: bumps nonce by exactly 1.
    /// @dev `_internalData = hook(20) || selectors(symbolic)`. We symbolicize a
    ///      length-32 buffer (20-byte hook + 3 four-byte selectors). The
    ///      modulo-4 selector-length requirement is satisfied at every covered
    ///      length 20, 24, 28, 32. We fix length to 24 (one selector) to
    ///      keep the path tractable while still hitting the `_grantAccess`
    ///      branch.
    function checkInitializeValidationBumpsByOneNonEmptyData() external {
        ValidationId vId = ValidationId.wrap(bytes21(svm.createBytes32("vId")));
        uint32 preNonce = uint32(svm.createUint(32, "preNonce"));

        // Precondition: slot is empty.
        harness.sudoSetHook(vId, address(0));
        harness.sudoSetNonce(vId, preNonce);

        // Avoid 32-bit overflow.
        vm.assume(preNonce < type(uint32).max);

        // Make the hook check pass for any non-sentinel hook address by
        // enabling the symbolic-hook bypass.
        harness.setHookAlwaysEnabled(true);

        // _internalData = 20-byte hook || 4-byte selector
        bytes memory internalData = svm.createBytes(24, "internalData");
        harness.initializeValidation(vId, internalData);

        uint32 postNonce = harness.nonceOf(vId);
        assertEq(uint256(postNonce), uint256(preNonce) + 1, "non-empty data must bump nonce by 1");
    }
}
