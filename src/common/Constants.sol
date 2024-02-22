pragma solidity ^0.8.0;

import {ValidationData} from "./Types.sol";

// Constants for kernel metadata
string constant KERNEL_NAME = "Kernel";
string constant KERNEL_VERSION = "0.2.4";

// ERC4337 constants
uint256 constant SIG_VALIDATION_FAILED_UINT = 1;
ValidationData constant SIG_VALIDATION_FAILED = ValidationData.wrap(SIG_VALIDATION_FAILED_UINT);

// STRUCT_HASH

/// @dev Struct hash for the ValidatorApproved struct -> keccak256("ValidatorApproved(bytes4 sig,uint256 validatorData,address executor,bytes enableData)")
bytes32 constant VALIDATOR_APPROVED_STRUCT_HASH = 0x3ce406685c1b3551d706d85a68afdaa49ac4e07b451ad9b8ff8b58c3ee964176;

/* -------------------------------------------------------------------------- */
/*                                Storage slots                               */
/* -------------------------------------------------------------------------- */

/// @dev Storage slot for the kernel storage
bytes32 constant KERNEL_STORAGE_SLOT = 0x439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dd8;
/// @dev Storage pointer inside the kernel storage, with 1 offset, to access directly disblaedMode, disabled date and default validator
bytes32 constant KERNEL_STORAGE_SLOT_1 = 0x439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dd9;
/// @dev Storage slot for the logic implementation address
bytes32 constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
