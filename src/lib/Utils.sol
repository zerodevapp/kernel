// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IValidator} from "../interfaces/IERC7579Modules.sol";
import {ValidationMode, ValidationId, ValidationType, PermissionId} from "../types/Types.sol";
import {VALIDATION_TYPE_PERMISSION} from "../types/Constants.sol";

/// @notice Extracts the ValidationType (first byte) from a ValidationId.
function getType(ValidationId validator) pure returns (ValidationType vType) {
    assembly {
        vType := validator
    }
}

/// @notice Extracts the validator address from a ValidationId (bytes 1-20, right-shifted by 88 bits).
function getValidator(ValidationId validator) pure returns (IValidator v) {
    assembly {
        v := shr(88, validator)
    }
}

/// @notice Extracts the PermissionId (bytes4) from a permission-type ValidationId.
function getPermissionId(ValidationId validator) pure returns (PermissionId id) {
    assembly {
        id := shl(8, validator)
    }
}

/// @notice Encodes a validator address into a ValidationId with type 0x01.
/// @dev Layout: `[0x01 | address(validator) | 0x0000000000000000]` (21 bytes).
function validatorToIdentifier(IValidator validator) pure returns (ValidationId vId) {
    assembly {
        vId := 0x0100000000000000000000000000000000000000000000000000000000000000
        vId := or(vId, shl(88, validator))
        vId := and(0xffffffffffffffffffffffffffffffffffffffffff0000000000000000000000, vId)
    }
}

/// @notice Encodes a PermissionId into a ValidationId with type 0x02.
/// @dev Layout: `[0x02 | bytes4(permissionId) | 0x00..00]` (21 bytes).
function permissionToIdentifier(PermissionId permissionId) pure returns (ValidationId vId) {
    assembly {
        vId := 0x0200000000000000000000000000000000000000000000000000000000000000
        vId := or(vId, shr(8, permissionId))
        vId := and(0xffffffffff000000000000000000000000000000000000000000000000000000, vId)
    }
}

/// @notice Parses a 256-bit ERC-4337 nonce into validation mode, type, and identifier.
/// @dev Nonce layout (32 bytes, big-endian):
///      ```
///      [1 byte vMode | 1 byte vType | 20 bytes vId | 2 bytes nonceKey | 8 bytes sequence]
///      ```
///      For permission type (0x02): only the first 4 bytes of the vId part are used as PermissionId.
///      For validator type (0x01): all 20 bytes are the validator address.
function parseNonce(uint256 nonce) pure returns (ValidationMode vMode, ValidationType vType, ValidationId vId) {
    vMode = ValidationMode.wrap(bytes1(bytes32(nonce)));
    vType = ValidationType.wrap(bytes1(bytes32(nonce << 8)));
    if (vType == VALIDATION_TYPE_PERMISSION) {
        // only use first 4 bytes of non-type vId part
        vId = ValidationId.wrap(bytes21(bytes32((nonce >> 208) << 216)));
    } else {
        vId = ValidationId.wrap(bytes21(bytes32(nonce << 8)));
    }
}

