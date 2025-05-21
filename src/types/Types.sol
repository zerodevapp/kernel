pragma solidity ^0.8.0;

// --- Kernel validation modes ---
// ValidationMode = bytes1
// ValidationMode = ________
//                   _ => userOpSignature Replayable flag
//                      _ => enable flag
//                       _ => relayable enable signature flag
type ValidationMode is bytes1;

type ValidationId is bytes20;

type ValidationType is bytes1;

// Custom type for improved developer experience
type ExecMode is bytes32;

type CallType is bytes1;

type ExecType is bytes1;

type ExecModeSelector is bytes4;

type ExecModePayload is bytes22;

using {vTypeEqual as ==} for ValidationType global;
using {eqCallType as ==} for CallType global;
using {notEqCallType as !=} for CallType global;
using {vIdentifierNotEqual as !=} for ValidationId global;
using {vIdentifierEqual as ==} for ValidationId global;

function vIdentifierEqual(ValidationId a, ValidationId b) pure returns (bool) {
    return ValidationId.unwrap(a) == ValidationId.unwrap(b);
}

function vIdentifierNotEqual(ValidationId a, ValidationId b) pure returns (bool) {
    return ValidationId.unwrap(a) != ValidationId.unwrap(b);
}

function eqCallType(CallType a, CallType b) pure returns (bool) {
    return CallType.unwrap(a) == CallType.unwrap(b);
}

function notEqCallType(CallType a, CallType b) pure returns (bool) {
    return CallType.unwrap(a) != CallType.unwrap(b);
}

function vTypeEqual(ValidationType a, ValidationType b) pure returns (bool) {
    return ValidationType.unwrap(a) == ValidationType.unwrap(b);
}

function isEnable(ValidationMode vMode) pure returns (bool enable) {
    assembly {
        enable := iszero(iszero(and(vMode, 8)))
    }
}

function isReplayable(ValidationMode vMode) pure returns (bool replayable) {
    assembly {
        replayable := iszero(iszero(and(vMode, 64)))
    }
}

function isEnableReplayable(ValidationMode vMode) pure returns (bool replayable) {
    assembly {
        replayable := iszero(iszero(and(vMode, 4)))
    }
}
