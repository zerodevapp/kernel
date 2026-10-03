// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {CallType, ValidationType} from "./Types.sol";

// Default CallType
CallType constant CALLTYPE_SINGLE = CallType.wrap(0x00);
// Batched CallType
CallType constant CALLTYPE_BATCH = CallType.wrap(0x01);
// @dev Implementing delegatecall is OPTIONAL!
// implement delegatecall with extreme care.
CallType constant CALLTYPE_DELEGATECALL = CallType.wrap(0xFF);

uint256 constant MODULE_TYPE_VALIDATOR = 1;
uint256 constant MODULE_TYPE_EXECUTOR = 2;
uint256 constant MODULE_TYPE_FALLBACK = 3;
uint256 constant MODULE_TYPE_POLICY = 5;
uint256 constant MODULE_TYPE_SIGNER = 6;
uint256 constant MODULE_TYPE_SCOPED_EXECUTION_HOOK = 11;

bytes1 constant SCOPED_EXECUTION_HOOK_VALIDATION_SCOPE = 0x01;
bytes1 constant SCOPED_EXECUTION_HOOK_EXECUTOR_SCOPE = 0x02;
bytes1 constant SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE = 0x03;

address constant SELECTOR_NOT_INSTALLED = address(0);
address constant SCOPED_EXECUTION_HOOK_NOT_INSTALLED = address(0);

uint256 constant SCOPED_EXECUTION_HOOK_TARGET_OFFSET = 1;
uint256 constant SCOPED_EXECUTION_HOOK_VALIDATION_DATA_LENGTH = 22;
uint256 constant SCOPED_EXECUTION_HOOK_EXECUTOR_DATA_LENGTH = 21;
uint256 constant SCOPED_EXECUTION_HOOK_SELECTOR_DATA_LENGTH = 5;

// note : ROOT == FALLBACK, they do indicate same value but to have different meanings in different context
// FALLBACK - usually used when using 7702 validation logic
// ROOT - mostly used when identifying that you are using root validation on userOp.nonce
ValidationType constant VALIDATION_TYPE_ROOT = ValidationType.wrap(0x00);
ValidationType constant VALIDATION_TYPE_FALLBACK = ValidationType.wrap(0x00);
ValidationType constant VALIDATION_TYPE_VALIDATOR = ValidationType.wrap(0x01);
ValidationType constant VALIDATION_TYPE_PERMISSION = ValidationType.wrap(0x02);

// --- storage slots ---
///@custom:storage-location bytes32(uint256(keccak256('kernel.v4.selector')) - 1)
bytes32 constant SELECTOR_MANAGER_STORAGE_SLOT = 0x550d18e77e0b3e646dcc27a9961c73d7867a7c5f6c2c65424629353cdc97dcc0;
///@custom:storage-location bytes32(uint256(keccak256('kernel.v4.module')) - 1)
bytes32 constant MODULE_MANAGER_STORAGE_SLOT = 0x9bc558e75ed0a57385e96d6b87fd2864d462eed29668be6fed742168fd90ab0f;
///@custom:storage-location bytes32(uint256(keccak256('kernel.v4.executor')) - 1)
bytes32 constant EXECUTOR_MANAGER_STORAGE_SLOT = 0xc98f19fae81314cbf0302e1e3c0554f60c259fab8e2d5d392893489d40eb0045;
///@custom:storage-location bytes32(uint256(keccak256('kernel.v4.validation')) - 1)
bytes32 constant VALIDATION_MANAGER_STORAGE_SLOT = 0xded5d420c407eac3c615e6abe13ab4a0bd7173e5045ea543765b46f0df6e260c;
///@custom:storage-location bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
bytes32 constant ERC1967_IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
bytes4 constant ERC1271_MAGICVALUE = 0x1626ba7e;
bytes4 constant ERC1271_INVALID = 0xffffffff;
uint256 constant SIG_VALIDATION_FAILED_UINT = 1;
uint256 constant SIG_VALIDATION_SUCCESS_UINT = 0;

//InstallPackages(uint256 nonce,Install[] packages)Install(uint256 moduleType,address module,bytes moduleData,bytes internalData)
bytes32 constant INSTALL_PACKAGES_STRUCT_HASH = 0x633d6810f7f4053622dad4c187707d9c3cd7f57b8b68943473d3437060aefc6d;
//keccak256("Install(uint256 moduleType,address module,bytes moduleData,bytes internalData)"),
bytes32 constant INSTALL_STRUCT_HASH = 0x50c63c739a5f8d2e99954b3d4c7008fcdcef795a1b755ab9287372b01d6ac239;
//ApproveFactory(address factory,bool approval,uint256 nonce)
bytes32 constant APPROVE_FACTORY_STRUCT_HASH = 0xefd04fcbcf7166a7a34d3a97718e39af7d5bac9fe12232a5041ce5fbe04fe44d;

// --- EIP-712 type hashes ---
/// @dev `keccak256("PersonalSign(bytes prefixed)")`.
bytes32 constant PERSONAL_SIGN_TYPEHASH = 0x983e65e5148e570cd828ead231ee759a8d7958721a768f93bc4483ba005c32de;

///@custom:struct-hash EIP712Domain(string name,string version,address verifyingContract)
bytes32 constant DOMAIN_TYPEHASH_SANS_CHAIN_ID = 0x91ab3d17e3a50a9d89e63fd30b92be7f5336b03b287bb946787a83a9d62a2766;
