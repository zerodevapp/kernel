// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ValidationId, CallType} from "./Types.sol";
import {IScopedExecutionHook, IExecutor} from "../interfaces/IERC7579Modules.sol";

/// @notice Describes a module installation: the module type, address, and its data payloads.
/// @dev The `moduleData` is forwarded to the module's onInstall/onUninstall callback.
///      The `internalData` configures Kernel-internal state and its format varies by module type:
///      - Validators (type 1): `[bytes4[] allowedSelectors]`
///      - Executors (type 2): ignored (empty OK)
///      - Fallback/Selectors (type 3): `[bytes4 selector | bytes1 callType]`
///      - Policies (type 5): `[bytes4 permissionId | ...]`
///      - Signers (type 6): `[bytes4 permissionId | bytes4[] allowedSelectors]`
///      - Execution hooks (type 11): `[bytes1 scope | target]`
struct Install {
    /// @dev The module type identifier (1=validator, 2=executor, 3=fallback, 5=policy, 6=signer, 11=scoped execution hook).
    uint256 moduleType;
    /// @dev The module contract address.
    address module;
    /// @dev Data forwarded to the module's onInstall callback.
    bytes moduleData;
    /// @dev Kernel-internal configuration data (format varies by moduleType, see above).
    bytes internalData;
}

/// @notice Stores per-validation state: installation, selector nonce, scoped execution hook, signer, and policies.
struct ValidationInfo {
    /// @dev Incremented when selectors are (re)granted; used to invalidate old selector allowances.
    uint32 nonce;
    /// @dev Whether this validator or permission is installed.
    bool installed;
    /// @dev Optional execution hook scoped to this validation.
    IScopedExecutionHook scopedExecutionHook;
    /// @dev The signer module address (only for permission-based validations).
    address signer;
    /// @dev Array of policy module addresses (only for permission-based validations).
    address[] policies;
}

/// @notice Top-level validation storage holding the root and all validation infos.
struct ValidationStorage {
    /// @dev The root validation identifier used for default userOp and signature verification.
    ValidationId root;
    /// @dev Maps ValidationId to its ValidationInfo.
    mapping(ValidationId vId => ValidationInfo) vInfo;
    /// @dev Maps (ValidationId, selector) to the nonce at which the selector was allowed.
    mapping(ValidationId vId => mapping(bytes4 selector => uint32)) allowed;
}

/// @notice A standard call tuple used in batch execution.
struct Call {
    /// @dev The target address to call.
    address to;
    /// @dev The ETH value to send with the call.
    uint256 value;
    /// @dev The calldata to send.
    bytes data;
}

/// @notice Signature format for enable-mode: installs modules inline during validation.
struct EnableModeSignature {
    /// @dev The install nonce for replay protection.
    uint256 nonce;
    /// @dev The array of module packages to install.
    Install[] packages;
    /// @dev The root validator's signature authorizing the install.
    bytes enableSignature;
    /// @dev The actual UserOperation signature after the enable portion.
    bytes userOpSignature;
}

/// @notice Wrapper for the two-part data format used by installModule/uninstallModule.
struct InstallModuleDataFormat {
    /// @dev Data forwarded to the module's onInstall/onUninstall callback.
    bytes installData;
    /// @dev Kernel-internal configuration data.
    bytes internalData;
}

/// @notice Wrapper containing per-module uninstall payloads for a validation.
struct ValidationUninstallData {
    /// @dev Permission order is policies, signer, then optional hook; validator order is validator, then hook.
    bytes[] uninstallData;
}

/// @notice Fallback selector routing configuration.
struct SelectorConfig {
    /// @dev The fallback module that handles calls to this selector.
    address target;
    /// @dev The call type: CALLTYPE_SINGLE (0x00) for call, CALLTYPE_DELEGATECALL (0xFF) for delegatecall.
    CallType callType;
    /// @dev Optional execution hook scoped to this selector.
    IScopedExecutionHook scopedExecutionHook;
}

/// @notice Storage for all selector configurations.
struct SelectorStorage {
    /// @dev Maps function selector to its routing configuration.
    mapping(bytes4 => SelectorConfig) selectorConfig;
}

/// @notice Configuration for an executor module.
struct ExecutorConfig {
    /// @dev Whether the executor is installed.
    bool installed;
    /// @dev Optional execution hook scoped to this executor.
    IScopedExecutionHook scopedExecutionHook;
}

/// @notice Storage for all executor configurations.
struct ExecutorStorage {
    /// @dev Maps executor address to its configuration.
    mapping(IExecutor => ExecutorConfig) executorConfig;
}

/// @notice Storage for module-level nonce management and optional registry.
struct ModuleStorage {
    /// @dev ERC-7484 module registry address (reserved for future use, not used in vanilla Kernel).
    address registry;
    /// @dev Global minimum nonce sequence; nonces below this are invalid across all keys.
    uint64 nonceValidFrom;
    /// @dev Maps nonce key to its current sequence number.
    mapping(uint192 key => uint64) nonce;
}

/// @notice Signature format for permission-based validations containing per-policy + signer signatures.
struct PermissionSignature {
    /// @dev Array of signatures: one per policy (in order) plus one for the signer (last).
    bytes[] signatures;
}
