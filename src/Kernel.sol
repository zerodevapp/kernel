// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC7579Account} from "./interfaces/IERC7579Account.sol";
import {IValidator, IExecutor, IScopedExecutionHook, IModule} from "./interfaces/IERC7579Modules.sol";
import {ModuleManager, Install} from "./core/ModuleManager.sol";
import {ExecutionManager} from "./core/ExecutionManager.sol";
import {Lib4337} from "./lib/Lib4337.sol";
import {ERC1271} from "./lib/ERC1271.sol";
import {
    parseNonce,
    getType,
    getValidator,
    validatorToIdentifier,
    permissionToIdentifier,
    executorScopedExecutionHookId,
    selectorScopedExecutionHookId
} from "./lib/Utils.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {
    ValidationId,
    PermissionId,
    ValidationMode,
    ValidationType,
    isEnable,
    isReplayable,
    isEnableReplayable
} from "./types/Types.sol";
import {
    NotImplemented,
    Unauthorized,
    UnauthorizedCallData,
    InvalidSelector,
    InvalidCallType,
    InstallSignatureVerificationFailed,
    InvalidDataLength,
    InvalidRootValidation,
    InvalidInitialization,
    InvalidVid
} from "./types/Error.sol";
import {Received} from "./types/Events.sol";
import {
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_PERMISSION,
    VALIDATION_TYPE_VALIDATOR,
    CALLTYPE_SINGLE,
    CALLTYPE_DELEGATECALL,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    MODULE_TYPE_SCOPED_EXECUTION_HOOK,
    SELECTOR_NOT_INSTALLED,
    SCOPED_EXECUTION_HOOK_NOT_INSTALLED,
    SIG_VALIDATION_FAILED_UINT
} from "./types/Constants.sol";
import {
    ValidationStorage,
    ValidationInfo,
    ExecutorConfig,
    EnableModeSignature,
    SelectorConfig,
    InstallModuleDataFormat,
    ValidationUninstallData
} from "./types/Structs.sol";

/// @title Kernel
/// @author taek <leekt216@gmail.com>
/// @notice ERC-7579 compliant modular smart account with pluggable validation and execution modules.
abstract contract Kernel is ModuleManager, ExecutionManager, IERC7579Account {
    IEntryPoint immutable ENTRYPOINT;

    function _onlyEntryPointOrSelf() internal view {
        require(msg.sender == address(ENTRYPOINT) || msg.sender == address(this), Unauthorized());
    }

    function _onlyEntryPoint() internal view {
        require(msg.sender == address(ENTRYPOINT), Unauthorized());
    }

    constructor(IEntryPoint _entrypoint) {
        ENTRYPOINT = _entrypoint;
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Kernel";
        version = "0.4.0";
    }

    /// @notice Initializes the account with the given module packages. Must be overridden by concrete implementations.
    /// @param packages The array of module install packages; the first package becomes the root validator.
    function initialize(Install[] calldata packages) external payable virtual;

    /// @notice Internal initialization that installs packages and sets the first as root.
    /// @param packages The array of module install packages; must be non-empty.
    function _initialize(Install[] calldata packages) internal virtual {
        require(packages.length > 0, InvalidInitialization());
        Install calldata root = packages[0];
        _install(packages);
        _setRoot(root);
    }

    /// @notice Validates a UserOperation for ERC-4337 entry point compatibility.
    /// @dev Parses the nonce to determine validation mode and type, optionally installs modules
    ///      via enable-mode signatures, then delegates to the appropriate validator.
    ///      Nonce layout (32 bytes): `[1 byte vMode | 1 byte vType | 20 bytes vId | 2 bytes nonceKey | 8 bytes seq]`.
    /// @param userOp The packed user operation to validate.
    /// @param userOpHash The hash of the user operation as computed by the entry point.
    /// @param missingAccountFunds The amount of funds the account must prefund to the entry point.
    /// @return validationData Packed validation result: `[20 bytes aggregator | 6 bytes validUntil | 6 bytes validAfter]`.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        payable
        returns (uint256 validationData)
    {
        _onlyEntryPoint();
        validationData = _processUserOp(userOp, userOpHash);
        assembly {
            if missingAccountFunds {
                pop(call(gas(), caller(), missingAccountFunds, callvalue(), callvalue(), callvalue(), callvalue()))
                //ignore failure (its EntryPoint's job to verify, not account.)
            }
        }
    }

    /// @notice ERC-1271 signature validation with nested EIP-712 support (ERC-7739).
    /// @param hash The hash that was signed.
    /// @param signature The signature bytes to verify.
    /// @return The ERC-1271 magic value on success, or 0xffffffff on failure.
    function isValidSignature(bytes32 hash, bytes calldata signature)
        public
        view
        override(ERC1271, IERC7579Account)
        returns (bytes4)
    {
        return ERC1271.isValidSignature(hash, signature);
    }

    function _processUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        returns (uint256 validationData)
    {
        bytes4 callDataSelector = bytes4(userOp.callData[0:4]);
        // Block recursive validation both directly and through the executeUserOp wrapper.
        require(callDataSelector != this.validateUserOp.selector, UnauthorizedCallData());
        if (callDataSelector == this.executeUserOp.selector && userOp.callData.length >= 8) {
            require(bytes4(userOp.callData[4:8]) != this.validateUserOp.selector, UnauthorizedCallData());
        }
        /*
         userOp.nonce = vMode | vType | vId
        */
        ValidationMode vMode;
        ValidationType vType;
        ValidationId vId;
        function(ValidationId, bytes32, PackedUserOperation memory, bytes calldata) returns (uint256) validateUserOpFn;
        (vMode, vType, vId) = parseNonce(userOp.nonce);

        bytes calldata signature = userOp.signature;
        if (isEnable(vMode)) {
            bool enableReplayable = isEnableReplayable(vMode);
            EnableModeSignature calldata sig;
            assembly {
                sig := signature.offset
            }
            validationData = _verifyInstallSignatureRaw(enableReplayable, sig.nonce, sig.packages, sig.enableSignature);
            // EntryPoint owns validity-window enforcement. Reject hard signature failures before
            // mutating state; EntryPoint rolls back installs for all other invalid results.
            if (uint160(validationData) == SIG_VALIDATION_FAILED_UINT) {
                return validationData;
            }
            _checkAndIncrementNonce(sig.nonce);
            _install(sig.packages);
            signature = sig.userOpSignature;
        }
        ValidationStorage storage $ = _validationStorage();

        // Root is the unconditional recovery path and bypasses validation-scoped execution hooks.
        if (vType != VALIDATION_TYPE_ROOT) {
            ValidationInfo storage info = $.vInfo[vId];
            require(info.installed, InvalidVid(vId));
            bool hasScopedExecutionHook = address(info.scopedExecutionHook) != SCOPED_EXECUTION_HOOK_NOT_INSTALLED;
            // Validation-scoped hooks must wrap execution even when the outer selector is directly allowed.
            if (hasScopedExecutionHook || !_allowedSelector(vId, callDataSelector)) {
                require(
                    callDataSelector == this.executeUserOp.selector
                        && _allowedSelector(vId, bytes4(userOp.callData[4:])),
                    UnauthorizedCallData()
                );
            }
            if (hasScopedExecutionHook) {
                _setValidationScopedExecutionHook(userOpHash, vId, info.scopedExecutionHook);
            }
        }
        (vId, validateUserOpFn) = _checkValidation(vType, vId);
        bytes32 opHash = isReplayable(vMode) ? Lib4337.chainAgnosticUserOpHash(msg.sender, userOp) : userOpHash;
        validationData =
            Lib4337.intersectValidationData(validationData, validateUserOpFn(vId, opHash, userOp, signature));
    }

    /// @notice Executes a user operation with validation-hook context.
    /// @dev Called by the entry point after validateUserOp. Runs pre/post hooks stored transiently
    ///      and delegatecalls the inner calldata (userOp.callData[4:]).
    /// @dev SECURITY: The inner calldata (userOp.callData[4:]) is delegatecalled to `address(this)`
    ///      with no additional selector or target validation. Any function on Kernel (including
    ///      privileged ones like `installModule`, `setRoot`, `execute`) can be invoked this way.
    ///      Authorization relies entirely on `validateUserOp` having approved the outer UserOp.
    /// @param userOp The packed user operation containing the execution calldata.
    /// @param userOpHash The hash of the user operation, used to retrieve the transient validation hook.
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external payable {
        _onlyEntryPointOrSelf();
        (ValidationId vId, IScopedExecutionHook hook) = _validationScopedExecutionHook(userOpHash);
        bytes32 hookId;
        bytes memory context;
        if (address(hook) != SCOPED_EXECUTION_HOOK_NOT_INSTALLED) {
            hookId = _validationScopedExecutionHookId(vId);
            context = hook.preCheck(hookId, msg.sender, msg.value, userOp.callData[4:]);
        }
        (bool success, bytes memory ret) = address(this).delegatecall(userOp.callData[4:]);
        // propagate the revert message
        if (!success) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        if (address(hook) != SCOPED_EXECUTION_HOOK_NOT_INSTALLED) {
            hook.postCheck(hookId, context);
        }
    }

    /// @notice Executes a call according to the given ERC-7579 execution mode.
    /// @param mode The execution mode encoding call type and exec type (see LibERC7579).
    /// @param executionData The ABI-encoded execution data matching the call type.
    function execute(bytes32 mode, bytes calldata executionData) external payable {
        _onlyEntryPointOrSelf();
        _execute(mode, executionData);
    }

    /// @notice Executes a call on behalf of an installed executor module.
    /// @dev The calling executor must be installed.
    /// @param mode The execution mode encoding call type and exec type.
    /// @param executionData The ABI-encoded execution data matching the call type.
    /// @return returnData Array of return data from each executed call.
    function executeFromExecutor(bytes32 mode, bytes calldata executionData)
        external
        payable
        returns (bytes[] memory returnData)
    {
        return _executeFromExecutor(mode, executionData);
    }

    function _executeFromExecutor(bytes32 mode, bytes calldata executionData)
        internal
        returns (bytes[] memory returnData)
    {
        ExecutorConfig storage config = _executorConfig(IExecutor(msg.sender));
        require(config.installed, Unauthorized());
        IScopedExecutionHook hook = config.scopedExecutionHook;
        bytes32 id;
        bytes memory context;
        if (address(hook) != SCOPED_EXECUTION_HOOK_NOT_INSTALLED) {
            id = executorScopedExecutionHookId(msg.sender);
            context = hook.preCheck(id, msg.sender, msg.value, msg.data);
        }
        returnData = _execute(mode, executionData);
        if (address(hook) != SCOPED_EXECUTION_HOOK_NOT_INSTALLED) {
            hook.postCheck(id, context);
        }
    }

    /// @dev SECURITY: When `callType` is `CALLTYPE_DELEGATECALL`, the fallback target executes
    ///      in Kernel's storage context via `delegatecall`. A malicious or buggy fallback module
    ///      can overwrite any Kernel storage slot. Only install trusted, audited fallback modules
    ///      with `CALLTYPE_DELEGATECALL`. Prefer `CALLTYPE_SINGLE` (regular call) when possible.
    function _fallback() internal returns (bytes memory res) {
        /// @solidity memory-safe-assembly
        assembly {
            let s := shr(224, calldataload(0))
            // 0x150b7a02: `onERC721Received(address,address,uint256,bytes)`.
            // 0xf23a6e61: `onERC1155Received(address,address,uint256,uint256,bytes)`.
            // 0xbc197c81: `onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)`.
            if or(eq(s, 0x150b7a02), or(eq(s, 0xf23a6e61), eq(s, 0xbc197c81))) {
                // Assumes `mload(0x40) <= 0xffffffff` to save gas on cleaning lower bytes.
                mstore(0x20, s) // Store `msg.sig`.
                return(0x3c, 0x20) // Return `msg.sig`.
            }
        }

        bytes4 selector = bytes4(msg.data[0:4]);
        SelectorConfig storage $ = _selectorConfig(selector);
        // target must be initialized, and if no scoped execution hook is installed
        // only the entry point may call it (scoped hooks gate direct access).
        require(
            $.target != SELECTOR_NOT_INSTALLED
                && (address($.scopedExecutionHook) != SCOPED_EXECUTION_HOOK_NOT_INSTALLED
                    || msg.sender == address(ENTRYPOINT)),
            InvalidSelector()
        );

        IScopedExecutionHook hook = $.scopedExecutionHook;
        bytes32 id;
        bytes memory context;
        if (address(hook) != SCOPED_EXECUTION_HOOK_NOT_INSTALLED) {
            id = selectorScopedExecutionHookId(selector);
            context = hook.preCheck(id, msg.sender, msg.value, msg.data);
        }

        bool success;
        if ($.callType == CALLTYPE_SINGLE) {
            success = _call($.target, 0, abi.encodePacked(msg.data, msg.sender));
        } else if ($.callType == CALLTYPE_DELEGATECALL) {
            success = _delegateCall($.target, msg.data);
        } else {
            revert InvalidCallType();
        }
        if (!success) {
            _onRevertThrow();
        } else {
            res = _getReturn();
        }
        if (address(hook) != SCOPED_EXECUTION_HOOK_NOT_INSTALLED) {
            hook.postCheck(id, context);
        }
    }

    /// @notice Advances the nonce for a given key, invalidating all lower nonce values.
    /// @param nonceKey The 192-bit nonce key (upper 24 bytes of the 256-bit nonce).
    /// @param seq The new sequence number; must be greater than the current value.
    function setNonce(uint192 nonceKey, uint64 seq) external payable {
        _onlyEntryPointOrSelf();
        _setNonce(nonceKey, seq);
    }

    /// @notice Advances the global minimum nonce, invalidating all nonces below `seq` across all keys.
    /// @param seq The new global minimum sequence number; must be greater than the current value.
    function setValidNonceFrom(uint64 seq) external payable {
        _onlyEntryPointOrSelf();
        _setValidNonceFrom(seq);
    }

    /// @notice Installs a single module per ERC-7579.
    /// @dev The initData is decoded as `InstallModuleDataFormat(bytes installData, bytes internalData)`.
    /// @param moduleType The module type identifier (1=validator, 2=executor, 3=fallback, 5=policy, 6=signer, 11=scoped execution hook).
    /// @param module The address of the module contract to install.
    /// @param initData ABI-encoded `InstallModuleDataFormat` containing install data and internal configuration.
    function installModule(uint256 moduleType, address module, bytes calldata initData) external payable override {
        _onlyEntryPointOrSelf();
        InstallModuleDataFormat calldata imdf = _decodeModuleData(initData);
        _installModule(moduleType, module, imdf.installData, imdf.internalData);
    }

    /// @dev TOB-KERNEL-10: the assembly cast alone does not bind the struct's dynamic fields to the
    ///      declared `initData` bounds — attacker-chosen head offsets could point past it into other
    ///      calldata, so an authority that approved the declared bytes would authorize different
    ///      bytes than Kernel consumes. Require both fields to lie entirely within `initData`.
    function _decodeModuleData(bytes calldata initData) private pure returns (InstallModuleDataFormat calldata imdf) {
        require(initData.length >= 0x40, InvalidDataLength());
        assembly {
            imdf := initData.offset
        }
        bytes calldata installData = imdf.installData;
        bytes calldata internalData = imdf.internalData;
        uint256 initStart;
        uint256 initEnd;
        uint256 aStart;
        uint256 aLength;
        uint256 bStart;
        uint256 bLength;
        assembly {
            initStart := initData.offset
            initEnd := add(initData.offset, initData.length)
            aStart := installData.offset
            aLength := installData.length
            bStart := internalData.offset
            bLength := internalData.length
        }
        require(
            aStart >= initStart && aStart <= initEnd && aLength <= initEnd - aStart && bStart >= initStart
                && bStart <= initEnd && bLength <= initEnd - bStart,
            InvalidDataLength()
        );
    }

    /// @notice Uninstalls a single module per ERC-7579.
    /// @param moduleType The module type identifier.
    /// @param module The address of the module contract to uninstall.
    /// @param initData ABI-encoded `InstallModuleDataFormat` containing uninstall data and internal configuration.
    function uninstallModule(uint256 moduleType, address module, bytes calldata initData) external payable override {
        _onlyEntryPointOrSelf();
        InstallModuleDataFormat calldata imdf = _decodeModuleData(initData);
        _uninstallModule(moduleType, module, imdf.installData, imdf.internalData);
    }

    /// @notice Installs new modules and sets a new root validator, optionally removing the current one.
    /// @dev The first package in `pkg` becomes the new root. If `removeCurrent` is true, the old root
    ///      validator/permission is uninstalled using `uninstallData`.
    /// @param pkg The array of module install packages; must be non-empty.
    /// @param removeCurrent Whether to uninstall the current root validator/permission.
    /// @param uninstallData Data passed to onUninstall for the current root (format depends on root type).
    function setRoot(Install[] calldata pkg, bool removeCurrent, bytes calldata uninstallData) external payable {
        _onlyEntryPointOrSelf();
        require(pkg.length > 0, InvalidInitialization());
        ValidationId vId = _validationStorage().root;
        // Install the new packages first so the new root is guaranteed to be installed
        // by the time `_setRoot` runs its installed-status check.
        _install(pkg);
        _setRoot(pkg[0]);
        if (removeCurrent) {
            ValidationType vType = getType(vId);
            ValidationInfo memory vInfo = _validationStorage().vInfo[vId];
            if (vType == VALIDATION_TYPE_VALIDATOR) {
                bytes calldata validatorUninstallData = uninstallData;
                if (address(vInfo.scopedExecutionHook) != SCOPED_EXECUTION_HOOK_NOT_INSTALLED) {
                    ValidationUninstallData calldata data;
                    assembly {
                        data := uninstallData.offset
                    }
                    require(data.uninstallData.length == 2, InvalidDataLength());
                    validatorUninstallData = data.uninstallData[0];
                    _uninstallScopedExecutionHookWithVid(address(vInfo.scopedExecutionHook), vId);
                    // forge-lint: disable-next-line(unchecked-call)
                    address(vInfo.scopedExecutionHook)
                        .call(abi.encodeWithSelector(IModule.onUninstall.selector, data.uninstallData[1]));
                }
                _uninstallValidator(
                    address(getValidator(vId)),
                    // passing in validatorUninstallData here to use calldata, but it's never used
                    validatorUninstallData,
                    true
                );
                // forge-lint: disable-next-line(unchecked-call)
                address(getValidator(vId))
                    .call(abi.encodeWithSelector(IModule.onUninstall.selector, validatorUninstallData));
            } else if (vType == VALIDATION_TYPE_PERMISSION) {
                ValidationUninstallData calldata data;
                assembly {
                    data := uninstallData.offset
                }
                bytes[] calldata uninstallDataArr = data.uninstallData;
                uint256 hookOffset = address(vInfo.scopedExecutionHook) == SCOPED_EXECUTION_HOOK_NOT_INSTALLED ? 0 : 1;
                require(uninstallDataArr.length == vInfo.policies.length + 1 + hookOffset, InvalidDataLength());
                if (hookOffset == 1) {
                    _uninstallScopedExecutionHookWithVid(address(vInfo.scopedExecutionHook), vId);
                    // forge-lint: disable-next-line(unchecked-call)
                    address(vInfo.scopedExecutionHook)
                        .call(
                            abi.encodeWithSelector(
                                IModule.onUninstall.selector, uninstallDataArr[vInfo.policies.length + 1]
                            )
                        );
                }
                // uninstall policies first
                // NOTE : success is not checked on purpose as we are focusing on removing not actually calling onUninstall
                unchecked {
                    for (uint256 i = vInfo.policies.length; i > 0; i--) {
                        _uninstallPolicyWithVid(vInfo.policies[i - 1], vId);
                        // forge-lint: disable-next-line(unchecked-call)
                        vInfo.policies[i
                                - 1].call(abi.encodeWithSelector(IModule.onUninstall.selector, uninstallDataArr[i - 1]));
                    }
                }

                _uninstallSignerWithVid(vInfo.signer, vId);
                // forge-lint: disable-next-line(unchecked-call)
                vInfo.signer
                    .call(abi.encodeWithSelector(IModule.onUninstall.selector, uninstallDataArr[vInfo.policies.length]));
            } else {
                revert InvalidRootValidation();
            }
        }
    }

    /// @notice Sets the root validation directly to an already-installed ValidationId.
    /// @param vId The ValidationId to set as root (must be an installed validator or permission).
    function setRoot(ValidationId vId) external payable {
        _onlyEntryPointOrSelf();
        _setRoot(vId);
    }

    /// @notice Grants a validation access to specific function selectors.
    /// @param vId The ValidationId to grant selector access to.
    /// @param selectors Packed bytes4 selectors (length must be a multiple of 4).
    function grantAccess(ValidationId vId, bytes calldata selectors) external payable {
        _onlyEntryPointOrSelf();
        _grantAccess(vId, selectors);
    }

    /// @notice Installs modules using a root-signed enable-mode signature (no entry point required).
    /// @dev Verifies the signature against the current root validator, then installs the packages.
    /// @param replayable If true, the signature is verified without chain ID binding.
    /// @param nonce The install nonce to prevent replay.
    /// @param packages The array of module install packages.
    /// @param signature The root validator's signature over the install digest.
    function installModule(bool replayable, uint256 nonce, Install[] calldata packages, bytes calldata signature)
        external
        payable
    {
        // if 7702 or already initialized, use root signature to install module
        require(_verifyInstallSignature(replayable, nonce, packages, signature), InstallSignatureVerificationFailed());
        _install(packages);
    }

    /// @notice Batch-installs multiple modules from the entry point or self.
    /// @param packages The array of module install packages.
    function installModule(Install[] calldata packages) external payable {
        _onlyEntryPointOrSelf();
        _install(packages);
    }

    fallback(bytes calldata) external payable returns (bytes memory) {
        return _fallback();
    }

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    /// @notice Returns whether the given execution mode is supported.
    /// @param mode The ERC-7579 execution mode to check.
    /// @return True if the mode's call type and exec type are supported.
    function supportsExecutionMode(bytes32 mode) external pure override returns (bool) {
        bytes1 callType = LibERC7579.getCallType(mode);
        bytes1 execType = LibERC7579.getExecType(mode);
        if (!(execType == LibERC7579.EXECTYPE_DEFAULT || execType == LibERC7579.EXECTYPE_TRY)) {
            return false;
        }
        if (!(callType == LibERC7579.CALLTYPE_SINGLE || callType == LibERC7579.CALLTYPE_BATCH
                    || callType == LibERC7579.CALLTYPE_DELEGATECALL)) {
            return false;
        }
        return true;
    }

    /// @notice Returns whether the given module type is supported.
    /// @param moduleTypeId The module type identifier.
    /// @return True for validator, executor, fallback, policy, signer, and scoped-execution-hook modules.
    function supportsModule(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR || moduleTypeId == MODULE_TYPE_EXECUTOR
            || moduleTypeId == MODULE_TYPE_FALLBACK || moduleTypeId == MODULE_TYPE_POLICY
            || moduleTypeId == MODULE_TYPE_SIGNER || moduleTypeId == MODULE_TYPE_SCOPED_EXECUTION_HOOK;
    }

    /// @notice Checks whether a specific module is currently installed.
    /// @param moduleTypeId The module type identifier.
    /// @param module The module address to check.
    /// @param additionalContext Selector, permission ID, or scoped execution-hook target context.
    /// @return True if the module is installed for the given type and context.
    function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata additionalContext)
        external
        view
        override
        returns (bool)
    {
        if (moduleTypeId == MODULE_TYPE_VALIDATOR) {
            ValidationId vId = validatorToIdentifier(IValidator(module));
            return _validationStorage().vInfo[vId].installed;
        } else if (moduleTypeId == MODULE_TYPE_EXECUTOR) {
            return _executorConfig(IExecutor(module)).installed;
        } else if (moduleTypeId == MODULE_TYPE_FALLBACK) {
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes4 selector = bytes4(additionalContext);
            return _selectorConfig(selector).target == module;
        } else if (moduleTypeId == MODULE_TYPE_POLICY) {
            // forge-lint: disable-next-line(unsafe-typecast)
            ValidationId vId = permissionToIdentifier(PermissionId.wrap(bytes4(additionalContext)));
            ValidationInfo storage $ = _validationStorage().vInfo[vId];
            for (uint256 i = 0; i < $.policies.length; i++) {
                if ($.policies[i] == module) {
                    return true;
                }
            }
            return false;
        } else if (moduleTypeId == MODULE_TYPE_SIGNER) {
            // forge-lint: disable-next-line(unsafe-typecast)
            ValidationId vId = permissionToIdentifier(PermissionId.wrap(bytes4(additionalContext)));
            ValidationInfo storage $ = _validationStorage().vInfo[vId];
            return module != address(0) && $.signer == module;
        } else if (moduleTypeId == MODULE_TYPE_SCOPED_EXECUTION_HOOK) {
            return module != address(0) && _isScopedExecutionHookInstalled(module, additionalContext);
        } else {
            revert NotImplemented();
        }
    }

    /// @notice Returns the account implementation identifier per ERC-7579.
    /// @return accountImplementationId The implementation ID string.
    function accountId() external pure override returns (string memory accountImplementationId) {
        return "kernel.v0.4";
    }
}
