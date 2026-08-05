// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

import {ValidationManager} from "src/core/ValidationManager.sol";
import {ValidationStorage} from "src/types/Structs.sol";
import {ValidationId} from "src/types/Types.sol";

/// @notice Test harness exposing `_initializeValidation` and a nonce getter.
contract InitializeValidationHarness is ValidationManager {
    /// @notice Public wrapper around the internal `_initializeValidation`.
    function initializeValidation(ValidationId vId, bytes calldata _internalData) external {
        _initializeValidation(vId, _internalData);
    }

    /// @notice Direct read of `vInfo[vId].nonce` from the namespaced storage slot.
    function nonceOf(ValidationId vId) external view returns (uint32) {
        ValidationStorage storage $ = _validationStorage();
        return $.vInfo[vId].nonce;
    }

    /// @notice Manually set installation state to satisfy the OccupiedValidationId precondition.
    function sudoSetInstalled(ValidationId vId, bool installed) external {
        ValidationStorage storage $ = _validationStorage();
        $.vInfo[vId].installed = installed;
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

        // Precondition: validation is not installed.
        harness.sudoSetInstalled(vId, false);
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

        // Precondition: validation is not installed.
        harness.sudoSetInstalled(vId, false);
        harness.sudoSetNonce(vId, preNonce);

        // Avoid 32-bit overflow.
        vm.assume(preNonce < type(uint32).max);

        bytes memory internalData = svm.createBytes(4, "internalData");
        harness.initializeValidation(vId, internalData);

        uint32 postNonce = harness.nonceOf(vId);
        assertEq(uint256(postNonce), uint256(preNonce) + 1, "non-empty data must bump nonce by 1");
    }
}
