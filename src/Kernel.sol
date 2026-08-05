// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC7579Account} from "./interfaces/IERC7579Account.sol";
import {IValidator, IExecutor, IHook, IModule} from "./interfaces/IERC7579Modules.sol";
import {ModuleManager, Install} from "./core/ModuleManager.sol";
import {ExecutionManager} from "./core/ExecutionManager.sol";
import {Lib4337} from "./lib/Lib4337.sol";
import {ERC1271} from "./lib/ERC1271.sol";
import {parseNonce, getType, getValidator, validatorToIdentifier, permissionToIdentifier} from "./lib/Utils.sol";
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
    MODULE_TYPE_HOOK,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    HOOK_MODULE_NOT_INSTALLED,
    HOOK_MODULE_INSTALLED_NO_HOOK
} from "./types/Constants.sol";
import {
    ValidationStorage,
    ValidationInfo,
    EnableModeSignature,
    SelectorConfig,
    InstallModuleDataFormat,
    PermissionUninstallData
} from "./types/Structs.sol";

/// @title Kernel
/// @author taek <leekt216@gmail.com>
/// @notice ERC-7579 compliant modular smart account with pluggable validation, execution, and hook modules.
abstract contract Kernel is ModuleManager, ExecutionManager, IERC7579Account {
    IEntryPoint immutable ENTRYPOINT;

    function _onlyEntryPointOrSelf() internal view {
        require(msg.sender == address(ENTRYPOINT) || msg.sender == address(this), Unauthorized());
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
        _onlyEntryPointOrSelf();
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
            // Root did not authorize this install -> surface the failure and install nothing.
            // Compare only the failure field: a valid enable signature may carry nonzero
            // validity bounds, so the full packed word must not be compared against 1.
            // Without this guard, a call to validateUserOp outside the EntryPoint validation
            // phase (where the returned validationData is ignored) would install modules and
            // advance the nonce despite a failed root signature.
            if (uint160(validationData) == 1) {
                return validationData;
            }
            _checkAndIncrementNonce(sig.nonce);
            _install(sig.packages);
            signature = sig.userOpSignature;
        }
        ValidationStorage storage $ = _validationStorage();

        // For non-root validation, check if validation exists before checking selectors
        if (vType != VALIDATION_TYPE_ROOT) {
            require($.vInfo[vId].hook > HOOK_MODULE_NOT_INSTALLED, InvalidVid(vId));
        }

        // Bypass selector + hook handling when:
        //   - vType == ROOT: ROOT is the unconditional last-resort access path. It is
        //     intentionally exempt from selector allow-listing and from validation hooks
        //     so that a misconfigured / compromised hook on a scoped validation cannot
        //     lock the user out of their own account. Users who want hook-monitored
        //     access should reach for it via a non-root validator or permission.
        //   - non-ROOT with leading allow-listed selector AND no hook installed
        //     (HOOK_MODULE_INSTALLED_NO_HOOK sentinel): cheap fast-path that skips the
        //     executeUserOp wrapper because there is nothing for a hook to wrap.
        // Any other case must route through executeUserOp with an allow-listed inner
        // selector, and the validation-scoped hook is attached so executeUserOp's
        // _preHook/_postHook fire around the inner delegatecall.
        if (
            vType == VALIDATION_TYPE_ROOT
                || (_allowedSelector(vId, bytes4(userOp.callData[0:4]))
                    && $.vInfo[vId].hook == HOOK_MODULE_INSTALLED_NO_HOOK)
        ) {
            // No-op, this is cheaper in gas
        } else {
            require(
                bytes4(userOp.callData[0:4]) == this.executeUserOp.selector
                    && _allowedSelector(vId, bytes4(userOp.callData[4:])),
                UnauthorizedCallData()
            );
            _setValidationHook(userOpHash, IHook($.vInfo[vId].hook));
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
        IHook hook = _validationHook(userOpHash);
        bytes memory context = _preHook(hook, userOp.callData[4:]);
        (bool success, bytes memory ret) = address(this).delegatecall(userOp.callData[4:]);
        // propagate the revert message
        if (!success) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        _postHook(hook, context);
    }

    /// @notice Executes a call according to the given ERC-7579 execution mode.
    /// @param mode The execution mode encoding call type and exec type (see LibERC7579).
    /// @param executionData The ABI-encoded execution data matching the call type.
    function execute(bytes32 mode, bytes calldata executionData) external payable {
        _onlyEntryPointOrSelf();
        _execute(mode, executionData);
    }

    /// @notice Executes a call on behalf of an installed executor module.
    /// @dev The calling executor must be installed with a valid hook configuration.
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
        executorHook
        returns (bytes[] memory returnData)
    {
        return _execute(mode, executionData);
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
        // target must be initialized, and if hook is not set only entrypoint can call it
        require(
            $.target != address(0) && ($.hook != IHook(HOOK_MODULE_NOT_INSTALLED) || msg.sender == address(ENTRYPOINT)),
            InvalidSelector()
        );
        bytes memory hookData = _preHook($.hook, msg.data);

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
        _postHook($.hook, hookData);
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
    /// @param moduleType The module type identifier (1=validator, 2=executor, 3=fallback, 4=hook, 5=policy, 6=signer).
    /// @param module The address of the module contract to install.
    /// @param initData ABI-encoded `InstallModuleDataFormat` containing install data and internal configuration.
    function installModule(uint256 moduleType, address module, bytes calldata initData) external payable override {
        _onlyEntryPointOrSelf();
        InstallModuleDataFormat calldata imdf;
        assembly {
            imdf := initData.offset
        }
        _installModule(moduleType, module, imdf.installData, imdf.internalData);
    }

    /// @notice Uninstalls a single module per ERC-7579.
    /// @param moduleType The module type identifier.
    /// @param module The address of the module contract to uninstall.
    /// @param initData ABI-encoded `InstallModuleDataFormat` containing uninstall data and internal configuration.
    function uninstallModule(uint256 moduleType, address module, bytes calldata initData) external payable override {
        _onlyEntryPointOrSelf();
        InstallModuleDataFormat calldata imdf;
        assembly {
            imdf := initData.offset
        }
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
                (bool success,) =
                    address(getValidator(vId)).call(abi.encodeWithSelector(IModule.onUninstall.selector, uninstallData));
                _uninstallValidator(
                    address(getValidator(vId)),
                    // passing in uninstallData here to use calldata, but it's never used
                    uninstallData,
                    success
                );
            } else if (vType == VALIDATION_TYPE_PERMISSION) {
                PermissionUninstallData calldata data;
                assembly {
                    data := uninstallData.offset
                }
                bytes[] calldata uninstallDataArr = data.uninstallData;
                require(uninstallDataArr.length == vInfo.policies.length + 1, InvalidDataLength());
                // uninstall policies first
                // NOTE : success is not checked on purpose as we are focusing on removing not actually calling onUninstall
                unchecked {
                    for (uint256 i = vInfo.policies.length; i > 0; i--) {
                        // forge-lint: disable-next-line(unchecked-call)
                        vInfo.policies[i
                                - 1].call(abi.encodeWithSelector(IModule.onUninstall.selector, uninstallDataArr[i - 1]));
                        _uninstallPolicyWithVid(vInfo.policies[i - 1], vId);
                    }
                }

                // forge-lint: disable-next-line(unchecked-call)
                vInfo.signer
                    .call(
                        abi.encodeWithSelector(
                            IModule.onUninstall.selector, uninstallDataArr[uninstallDataArr.length - 1]
                        )
                    );
                _uninstallSignerWithVid(vInfo.signer, vId);
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
    /// @param moduleTypeId The module type identifier (1-6 are supported).
    /// @return True if the module type is supported.
    function supportsModule(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId < 7 && moduleTypeId != 0;
    }

    /// @notice Checks whether a specific module is currently installed.
    /// @param moduleTypeId The module type identifier.
    /// @param module The module address to check.
    /// @param additionalContext For fallback modules: the bytes4 selector. For policies/signers: the bytes4 PermissionId.
    /// @return True if the module is installed for the given type and context.
    function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata additionalContext)
        external
        view
        override
        returns (bool)
    {
        if (moduleTypeId == MODULE_TYPE_VALIDATOR) {
            ValidationId vId = validatorToIdentifier(IValidator(module));
            return _validationStorage().vInfo[vId].hook != HOOK_MODULE_NOT_INSTALLED;
        } else if (moduleTypeId == MODULE_TYPE_EXECUTOR) {
            return address(_executorConfig(IExecutor(module)).hook) != HOOK_MODULE_NOT_INSTALLED;
        } else if (moduleTypeId == MODULE_TYPE_FALLBACK) {
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes4 selector = bytes4(additionalContext);
            return _selectorConfig(selector).target == module;
        } else if (moduleTypeId == MODULE_TYPE_HOOK) {
            return _hookStorage().enabled[module];
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
            return $.signer == module;
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
