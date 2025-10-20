pragma solidity ^0.8.0;

import {ValidationId, ValidationType, CallType} from "./Types.sol";
import {IHook, IExecutor} from "../interfaces/IERC7579Modules.sol";

struct Install {
    uint256 moduleType;
    address module;
    bytes moduleData;
    bytes internalData;
}

struct Uninstall {
    uint256 moduleType;
    address module;
    bytes data;
}

struct ValidationInfo {
    address hook;
    address signer;
    address[] policies;
}

struct ValidationStorage {
    ValidationId root;
    mapping(ValidationId vId => ValidationInfo) vInfo;
    mapping(ValidationId vId => mapping(bytes4 selector => bool)) allowed;
}

struct Call {
    address to;
    uint256 value;
    bytes data;
}

struct InstallAndExecute {
    bool replayable;
    uint256 nonce;
    Install[] packages;
    bytes signature;
}

/// authentication
struct EnableModeSignature {
    uint256 nonce;
    Install[] packages;
    bytes enableSignature;
    bytes userOpSignature;
}

/// management
struct InstallModuleDataFormat {
    bytes installData;
    bytes internalData;
}

struct PermissionUninstallData {
    bytes[] uninstallData;
}

struct SelectorConfig {
    IHook hook; // 20 bytes for hook address
    address target; // 20 bytes target will be fallback module, called with call
    CallType callType;
}

struct SelectorStorage {
    mapping(bytes4 => SelectorConfig) selectorConfig;
}

struct ExecutorConfig {
    IHook hook; // address(1) : hook not required, address(0) : validator not installed
}

struct ExecutorStorage {
    mapping(IExecutor => ExecutorConfig) executorConfig;
}

struct HookStorage {
    mapping(address => bool) enabled;
}

struct ModuleStorage {
    address registry; // Note : not used on vanila kernel but saving the storage slot for future usage
    uint64 nonceValidFrom;
    mapping(uint192 key => uint64) nonce;
}

struct PermissionSignature {
    bytes[] signatures;
}
