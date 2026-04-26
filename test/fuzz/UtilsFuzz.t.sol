// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {ValidationId, ValidationType, ValidationMode, PermissionId} from "src/types/Types.sol";
import {
    parseNonce,
    getType,
    getValidator,
    getPermissionId,
    validatorToIdentifier,
    permissionToIdentifier
} from "src/lib/Utils.sol";
import {VALIDATION_TYPE_VALIDATOR, VALIDATION_TYPE_PERMISSION, VALIDATION_TYPE_ROOT} from "src/types/Constants.sol";

contract UtilsFuzz is Test {
    /// @dev parseNonce round trip: parse a nonce, reconstruct the original nonce components
    function testFuzz_parseNonce_roundTrip(uint256 nonce) public pure {
        (ValidationMode vMode, ValidationType vType, ValidationId vId) = parseNonce(nonce);

        // The mode byte is the top byte of the 256-bit nonce
        bytes1 expectedMode = bytes1(bytes32(nonce));
        assertEq(ValidationMode.unwrap(vMode), expectedMode, "mode mismatch");

        // The type byte is the second byte
        bytes1 expectedType = bytes1(bytes32(nonce << 8));
        assertEq(ValidationType.unwrap(vType), expectedType, "type mismatch");

        // The vId should be 21 bytes: type byte + 20 bytes of identifier data
        // For VALIDATION_TYPE_PERMISSION, only first 4 bytes of non-type vId part are used
        if (vType == VALIDATION_TYPE_PERMISSION) {
            // Permission: vId = bytes21(bytes32((nonce >> 208) << 216))
            bytes21 expectedVId = bytes21(bytes32((nonce >> 208) << 216));
            assertEq(ValidationId.unwrap(vId), expectedVId, "permission vId mismatch");
        } else {
            // Validator/Root: vId = bytes21(bytes32(nonce << 8))
            bytes21 expectedVId = bytes21(bytes32(nonce << 8));
            assertEq(ValidationId.unwrap(vId), expectedVId, "validator vId mismatch");
        }
    }

    /// @dev validatorToIdentifier round trip: getValidator(validatorToIdentifier(v)) == v
    function testFuzz_validatorToIdentifier_roundTrip(address validator) public pure {
        ValidationId vId = validatorToIdentifier(IValidator(validator));
        IValidator recovered = getValidator(vId);
        assertEq(address(recovered), validator, "validator round trip failed");
    }

    /// @dev permissionToIdentifier round trip: getPermissionId(permissionToIdentifier(p)) == p
    function testFuzz_permissionToIdentifier_roundTrip(bytes4 permId) public pure {
        ValidationId vId = permissionToIdentifier(PermissionId.wrap(permId));
        PermissionId recovered = getPermissionId(vId);
        assertEq(PermissionId.unwrap(recovered), permId, "permissionId round trip failed");
    }

    /// @dev getType(validatorToIdentifier(v)) == VALIDATION_TYPE_VALIDATOR
    function testFuzz_getType_validator(address v) public pure {
        ValidationId vId = validatorToIdentifier(IValidator(v));
        ValidationType vType = getType(vId);
        assertEq(
            ValidationType.unwrap(vType), ValidationType.unwrap(VALIDATION_TYPE_VALIDATOR), "validator type mismatch"
        );
    }

    /// @dev getType(permissionToIdentifier(p)) == VALIDATION_TYPE_PERMISSION
    function testFuzz_getType_permission(bytes4 p) public pure {
        ValidationId vId = permissionToIdentifier(PermissionId.wrap(p));
        ValidationType vType = getType(vId);
        assertEq(
            ValidationType.unwrap(vType), ValidationType.unwrap(VALIDATION_TYPE_PERMISSION), "permission type mismatch"
        );
    }
}
