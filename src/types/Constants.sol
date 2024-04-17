// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {CallType, ExecType, ExecModeSelector} from "./Types.sol";
import {PassFlag, ValidationMode, ValidationType} from "./Types.sol";
import {ValidationData} from "./Types.sol";

// --- ERC7579 calltypes ---
// Default CallType
CallType constant CALLTYPE_SINGLE = CallType.wrap(0x00);
// Batched CallType
CallType constant CALLTYPE_BATCH = CallType.wrap(0x01);
CallType constant CALLTYPE_STATIC = CallType.wrap(0xFE);
// @dev Implementing delegatecall is OPTIONAL!
// implement delegatecall with extreme care.
CallType constant CALLTYPE_DELEGATECALL = CallType.wrap(0xFF);

// --- ERC7579 exectypes ---
// @dev default behavior is to revert on failure
// To allow very simple accounts to use mode encoding, the default behavior is to revert on failure
// Since this is value 0x00, no additional encoding is required for simple accounts
ExecType constant EXECTYPE_DEFAULT = ExecType.wrap(0x00);
// @dev account may elect to change execution behavior. For example "try exec" / "allow fail"
ExecType constant EXECTYPE_TRY = ExecType.wrap(0x01);

// --- ERC7579 mode selector ---
ExecModeSelector constant EXEC_MODE_DEFAULT = ExecModeSelector.wrap(bytes4(0x00000000));

// --- Kernel permission skip flags ---
PassFlag constant SKIP_USEROP = PassFlag.wrap(0x0001);
PassFlag constant SKIP_SIGNATURE = PassFlag.wrap(0x0002);

// --- Kernel validation modes ---
ValidationMode constant VALIDATION_MODE_DEFAULT = ValidationMode.wrap(0x00);
ValidationMode constant VALIDATION_MODE_ENABLE = ValidationMode.wrap(0x01);
ValidationMode constant VALIDATION_MODE_INSTALL = ValidationMode.wrap(0x02);

// --- Kernel validation types ---
ValidationType constant VALIDATION_TYPE_ROOT = ValidationType.wrap(0x00);
ValidationType constant VALIDATION_TYPE_VALIDATOR = ValidationType.wrap(0x01);
ValidationType constant VALIDATION_TYPE_PERMISSION = ValidationType.wrap(0x02);

// --- storage slots ---
// bytes32(uint256(keccak256('kernel.v3.selector')) - 1)
bytes32 constant SELECTOR_MANAGER_STORAGE_SLOT = 0x7c341349a4360fdd5d5bc07e69f325dc6aaea3eb018b3e0ea7e53cc0bb0d6f3b;
// bytes32(uint256(keccak256('kernel.v3.executor')) - 1)
bytes32 constant EXECUTOR_MANAGER_STORAGE_SLOT = 0x1bbee3173dbdc223633258c9f337a0fff8115f206d302bea0ed3eac003b68b86;
// bytes32(uint256(keccak256('kernel.v3.hook')) - 1)
bytes32 constant HOOK_MANAGER_STORAGE_SLOT = 0x4605d5f70bb605094b2e761eccdc27bed9a362d8612792676bf3fb9b12832ffc;
// bytes32(uint256(keccak256('kernel.v3.validation')) - 1)
bytes32 constant VALIDATION_MANAGER_STORAGE_SLOT = 0x7bcaa2ced2a71450ed5a9a1b4848e8e5206dbc3f06011e595f7f55428cc6f84f;
bytes32 constant ERC1967_IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

// --- Kernel validation nonce incremental size limit ---
uint32 constant MAX_NONCE_INCREMENT_SIZE = 10;

// -- EIP712 type hash ---
bytes32 constant ENABLE_TYPE_HASH = 0xb17ab1224aca0d4255ef8161acaf2ac121b8faa32a4b2258c912cc5f8308c505;
bytes32 constant KERNEL_WRAPPER_TYPE_HASH = 0x1547321c374afde8a591d972a084b071c594c275e36724931ff96c25f2999c83;

// --- ERC constants ---
// ERC4337 constants
uint256 constant SIG_VALIDATION_FAILED_UINT = 1;
uint256 constant SIG_VALIDATION_SUCCESS_UINT = 0;
ValidationData constant SIG_VALIDATION_FAILED = ValidationData.wrap(SIG_VALIDATION_FAILED_UINT);

// ERC-1271 constants
bytes4 constant ERC1271_MAGICVALUE = 0x1626ba7e;
bytes4 constant ERC1271_INVALID = 0xffffffff;

uint256 constant MODULE_TYPE_VALIDATOR = 1;
uint256 constant MODULE_TYPE_EXECUTOR = 2;
uint256 constant MODULE_TYPE_FALLBACK = 3;
uint256 constant MODULE_TYPE_HOOK = 4;
uint256 constant MODULE_TYPE_POLICY = 5;
uint256 constant MODULE_TYPE_SIGNER = 6;
