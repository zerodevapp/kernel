pragma solidity ^0.8.0;

import {IValidator} from "../interfaces/IERC7579Modules.sol";
import {ValidationId, ValidationType, PermissionId} from "../types/Types.sol";

function calldataKeccak(bytes calldata data) pure returns (bytes32 ret) {
    assembly ("memory-safe") {
        let mem := mload(0x40)
        let len := data.length
        calldatacopy(mem, data.offset, len)
        ret := keccak256(mem, len)
    }
}

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
