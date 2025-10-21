pragma solidity ^0.8.0;

import {IValidator} from "../interfaces/IERC7579Modules.sol";
import {ValidationMode, ValidationId, ValidationType, PermissionId} from "../types/Types.sol";
import {VALIDATION_TYPE_PERMISSION} from "../types/Constants.sol";

function getType(ValidationId validator) pure returns (ValidationType vType) {
    assembly {
        vType := validator
    }
}

function getValidator(ValidationId validator) pure returns (IValidator v) {
    assembly {
        v := shr(88, validator)
    }
}

function getPermissionId(ValidationId validator) pure returns (PermissionId id) {
    assembly {
        id := shl(8, validator)
    }
}

function validatorToIdentifier(IValidator validator) pure returns (ValidationId vId) {
    assembly {
        vId := 0x0100000000000000000000000000000000000000000000000000000000000000
        vId := or(vId, shl(88, validator))
        vId := and(0xffffffffffffffffffffffffffffffffffffffffff0000000000000000000000, vId)
    }
}

function permissionToIdentifier(PermissionId permissionId) pure returns (ValidationId vId) {
    assembly {
        vId := 0x0200000000000000000000000000000000000000000000000000000000000000
        vId := or(vId, shr(8, permissionId))
        vId := and(0xffffffffff000000000000000000000000000000000000000000000000000000, vId)
    }
}

function parseNonce(uint256 nonce) pure returns (ValidationMode vMode, ValidationType vType, ValidationId vId) {
    // 2bytes mode (1byte currentMode, 1byte type)
    // 20bytes identifier
    // 1byte mode | (1byte type | 20bytes vId except type) | 2byte nonceKey | 8byte nonce == 32bytes
    vMode = ValidationMode.wrap(bytes1(bytes32(nonce)));
    vType = ValidationType.wrap(bytes1(bytes32(nonce << 8)));
    if (vType == VALIDATION_TYPE_PERMISSION) {
        // only use first 4 bytes of non-type vId part
        vId = ValidationId.wrap(bytes21(bytes32((nonce >> 208) << 216)));
    } else {
        vId = ValidationId.wrap(bytes21(bytes32(nonce << 8)));
    }
}

