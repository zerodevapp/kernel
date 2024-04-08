// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

// Custom type for improved developer experience
type ExecMode is bytes32;

type CallType is bytes1;

type ExecType is bytes1;

type ExecModeSelector is bytes4;

type ExecModePayload is bytes22;

using {eqModeSelector as ==} for ExecModeSelector global;
using {eqCallType as ==} for CallType global;
using {notEqCallType as !=} for CallType global;
using {eqExecType as ==} for ExecType global;

function eqCallType(CallType a, CallType b) pure returns (bool) {
    return CallType.unwrap(a) == CallType.unwrap(b);
}

function notEqCallType(CallType a, CallType b) pure returns (bool) {
    return CallType.unwrap(a) != CallType.unwrap(b);
}

function eqExecType(ExecType a, ExecType b) pure returns (bool) {
    return ExecType.unwrap(a) == ExecType.unwrap(b);
}

function eqModeSelector(ExecModeSelector a, ExecModeSelector b) pure returns (bool) {
    return ExecModeSelector.unwrap(a) == ExecModeSelector.unwrap(b);
}

type ValidationMode is bytes1;

type ValidationId is bytes21;

type ValidationType is bytes1;

type PermissionId is bytes4;

type PolicyData is bytes22; // 2bytes for flag on skip, 20 bytes for validator address

type PassFlag is bytes2;

using {vModeEqual as ==} for ValidationMode global;
using {vTypeEqual as ==} for ValidationType global;
using {vIdentifierEqual as ==} for ValidationId global;
using {vModeNotEqual as !=} for ValidationMode global;
using {vTypeNotEqual as !=} for ValidationType global;
using {vIdentifierNotEqual as !=} for ValidationId global;

// nonce = uint192(key) + nonce
// key = mode + (vtype + validationDataWithoutType) + 2bytes parallelNonceKey
// key = 0x00 + 0x00 + 0x000 .. 00 + 0x0000
// key = 0x00 + 0x01 + 0x1234...ff + 0x0000
// key = 0x00 + 0x02 + ( ) + 0x000

function vModeEqual(ValidationMode a, ValidationMode b) pure returns (bool) {
    return ValidationMode.unwrap(a) == ValidationMode.unwrap(b);
}

function vModeNotEqual(ValidationMode a, ValidationMode b) pure returns (bool) {
    return ValidationMode.unwrap(a) != ValidationMode.unwrap(b);
}

function vTypeEqual(ValidationType a, ValidationType b) pure returns (bool) {
    return ValidationType.unwrap(a) == ValidationType.unwrap(b);
}

function vTypeNotEqual(ValidationType a, ValidationType b) pure returns (bool) {
    return ValidationType.unwrap(a) != ValidationType.unwrap(b);
}

function vIdentifierEqual(ValidationId a, ValidationId b) pure returns (bool) {
    return ValidationId.unwrap(a) == ValidationId.unwrap(b);
}

function vIdentifierNotEqual(ValidationId a, ValidationId b) pure returns (bool) {
    return ValidationId.unwrap(a) != ValidationId.unwrap(b);
}

type ValidationData is uint256;

type ValidAfter is uint48;

type ValidUntil is uint48;

function getValidationResult(ValidationData validationData) pure returns (address result) {
    assembly {
        result := validationData
    }
}

function packValidationData(ValidAfter validAfter, ValidUntil validUntil) pure returns (uint256) {
    return uint256(ValidAfter.unwrap(validAfter)) << 208 | uint256(ValidUntil.unwrap(validUntil)) << 160;
}

function parseValidationData(uint256 validationData)
    pure
    returns (ValidAfter validAfter, ValidUntil validUntil, address result)
{
    assembly {
        result := validationData
        validUntil := and(shr(160, validationData), 0xffffffffffff)
        switch iszero(validUntil)
        case 1 { validUntil := 0xffffffffffff }
        validAfter := shr(208, validationData)
    }
}
