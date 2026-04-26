// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @dev Kernel validation mode flags encoded in a single byte.
///
///      ValidationMode bit layout (bytes1):
///      ```
///      Bit 6 (0x40): userOp signature replayable flag — if set, userOpHash is computed chain-agnostically
///      Bit 3 (0x08): enable flag — if set, the signature includes inline module install packages
///      Bit 2 (0x04): enable-signature replayable flag — if set, the enable signature is chain-agnostic
///      ```
///
///      Common values:
///      - 0x00: standard mode (chain-specific, no enable)
///      - 0x08: enable mode (install modules inline, chain-specific)
///      - 0x0C: enable mode with replayable enable signature
///      - 0x40: replayable userOp signature
///      - 0x48: enable mode with replayable userOp signature
type ValidationMode is bytes1;

/// @notice Returns true if enable-mode is active (inline module installation).
function isEnable(ValidationMode vMode) pure returns (bool enable) {
    return ValidationMode.unwrap(vMode) & bytes1(0x08) != 0;
}

/// @notice Returns true if the userOp signature should be verified chain-agnostically.
function isReplayable(ValidationMode vMode) pure returns (bool replayable) {
    return ValidationMode.unwrap(vMode) & bytes1(0x40) != 0;
}

/// @notice Returns true if the enable signature itself should be verified chain-agnostically.
function isEnableReplayable(ValidationMode vMode) pure returns (bool replayable) {
    return ValidationMode.unwrap(vMode) & bytes1(0x04) != 0;
}

/// @dev A 21-byte validation identifier encoding the validation type and module identity.
///
///      ValidationId layout (bytes21):
///      ```
///      [1 byte ValidationType | 20 bytes identifier]
///      ```
///
///      For validators (type 0x01): identifier = validator contract address
///      For permissions (type 0x02): identifier = bytes4 PermissionId (left-padded to 20 bytes)
///      For root/fallback (type 0x00): bytes21(0) indicates fallback validator
type ValidationId is bytes21;

/// @dev A 4-byte permission identifier that groups policies and a signer into a single validation.
type PermissionId is bytes4;

/// @dev Validation type discriminator: 0x00 = root/fallback, 0x01 = validator, 0x02 = permission.
type ValidationType is bytes1;

/// @dev Call type for execution/fallback: 0x00 = single call, 0x01 = batch, 0xFF = delegatecall.
type CallType is bytes1;

using {vTypeEqual as ==} for ValidationType global;
using {notVTypeEqual as !=} for ValidationType global;
using {eqCallType as ==} for CallType global;
using {notEqCallType as !=} for CallType global;
using {vIdentifierNotEqual as !=} for ValidationId global;
using {vIdentifierEqual as ==} for ValidationId global;
using {pIdEqual as ==} for PermissionId global;

function pIdEqual(PermissionId a, PermissionId b) pure returns (bool) {
    return PermissionId.unwrap(a) == PermissionId.unwrap(b);
}

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

function notVTypeEqual(ValidationType a, ValidationType b) pure returns (bool) {
    return ValidationType.unwrap(a) != ValidationType.unwrap(b);
}
