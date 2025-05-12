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

using {vTypeEqual as ==} for ValidationType global;

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
