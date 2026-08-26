// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IModule, IValidator, IExecutor, IScopedExecutionHook} from "../interfaces/IERC7579Modules.sol";
import {ValidationManager} from "./ValidationManager.sol";
import {ExecutorManager} from "./ExecutorManager.sol";
import {SelectorManager} from "./SelectorManager.sol";
import {ERC1271} from "../lib/ERC1271.sol";
import {
    InvalidValidationType,
    InvalidNonce,
    NotImplemented,
    PermissionInstallNotFinished,
    InvalidDataLength,
    InvalidScopedExecutionHookTarget,
    ScopedExecutionHookAlreadyInstalled,
    ModuleInstallFailed
} from "../types/Error.sol";
import {ModuleInstalled, ModuleUninstalled} from "../types/Events.sol";
import {Install, ModuleStorage, ExecutorConfig, SelectorConfig} from "../types/Structs.sol";
import {ValidationId, ValidationType, PermissionId} from "../types/Types.sol";
import {Lib4337} from "../lib/Lib4337.sol";
import {getType, validatorToIdentifier, permissionToIdentifier} from "../lib/Utils.sol";
import {
    MODULE_MANAGER_STORAGE_SLOT,
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    INSTALL_PACKAGES_STRUCT_HASH,
    INSTALL_STRUCT_HASH,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    MODULE_TYPE_SCOPED_EXECUTION_HOOK,
    SCOPED_EXECUTION_HOOK_VALIDATION_SCOPE,
    SCOPED_EXECUTION_HOOK_EXECUTOR_SCOPE,
    SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE,
    SELECTOR_NOT_INSTALLED,
    SCOPED_EXECUTION_HOOK_NOT_INSTALLED,
    SCOPED_EXECUTION_HOOK_TARGET_OFFSET,
    SCOPED_EXECUTION_HOOK_VALIDATION_DATA_LENGTH,
    SCOPED_EXECUTION_HOOK_EXECUTOR_DATA_LENGTH,
    SCOPED_EXECUTION_HOOK_SELECTOR_DATA_LENGTH
} from "../types/Constants.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";

/// @title ModuleManager
/// @author taek <leekt216@gmail.com>
/// @notice Composes validation, executor, and selector managers; handles module installation,
///         enable-mode signature verification, nonce management, and ERC-1271 signature flows.
abstract contract ModuleManager is ValidationManager, ExecutorManager, SelectorManager, ERC1271 {
    /// @dev Override this function to integrate an ERC-7484 module registry check.
    function _installModuleCheck(uint256 moduleType, address module) internal virtual {}

    modifier installModuleHook(uint256 moduleType, address module) {
        _installModuleCheck(moduleType, module);
        _;
    }

    /// @notice Returns the ERC-7484 module registry address (reserved for future use).
    /// @return The registry address.
    function registry() external view returns (address) {
        return _moduleStorage().registry;
    }

    /// @notice Returns the global minimum nonce sequence number.
    /// @return The minimum valid nonce sequence.
    function validNonceFrom() external view returns (uint64) {
        return _moduleStorage().nonceValidFrom;
    }

    /// @notice Returns the next valid nonce for the given key, respecting the global minimum.
    /// @param key The 192-bit nonce key.
    /// @return The full 256-bit nonce (key << 64 | seq).
    function nonce(uint192 key) external view returns (uint256) {
        ModuleStorage storage ms = _moduleStorage();
        uint64 seq = ms.nonce[key];
        if (ms.nonceValidFrom > seq) {
            seq = ms.nonceValidFrom;
        }
        return (uint256(key) << 64) + seq;
    }

    function _moduleStorage() internal pure returns (ModuleStorage storage $) {
        assembly {
            $.slot := MODULE_MANAGER_STORAGE_SLOT
        }
    }

    /// @dev Raw (non-nested) ERC-1271 exists so a 7702 account matches the signing behavior of the
    ///      EOA it delegates from. Only the fallback signer is account-bound by construction: its
    ///      key *is* the account address. Installed validators and permissions are not, so they are
    ///      excluded here and must go through the nested EIP-712 flow, which binds the signature to
    ///      this account's domain. Dispatching the raw hash to them would let a signature accepted
    ///      by one account replay against every other account sharing the module.
    function _erc1271Raw(bytes32 hash, bytes calldata signature) internal view override returns (bool) {
        return _erc1271RawAllowed() && _verifyFallbackSignature(hash, signature);
    }

    function _erc1271IsValidSignatureNowCalldata(bytes32 hash, bytes calldata signature)
        internal
        view
        override
        returns (bool result)
    {
        bool rawAllowed = _erc1271RawAllowed();
        if (rawAllowed && _verifyFallbackSignature(hash, signature)) return true;
        if (signature.length == 0) return false;
        ValidationType vType = ValidationType.wrap(bytes1(signature[0]));
        ValidationId vId;
        if (vType == VALIDATION_TYPE_ROOT) {
            vId = _validationStorage().root;
            signature = signature[1:];
        } else if (vType == VALIDATION_TYPE_VALIDATOR) {
            if (signature.length < 21) return false;
            vId = validatorToIdentifier(IValidator(address(bytes20(signature[1:21]))));
            signature = signature[21:];
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            if (signature.length < 5) return false;
            vId = permissionToIdentifier(PermissionId.wrap(bytes4(signature[1:5])));
            signature = signature[5:];
        } else {
            revert InvalidValidationType();
        }
        result = Lib4337.checkValidation(_verifySignature(vId, msg.sender, hash, signature));
    }

    /// @notice Computes the EIP-712 hash of an array of Install packages.
    /// @param packages The install packages to hash.
    /// @return The hash of the packages array.
    function _installHash(Install[] calldata packages) internal pure returns (bytes32) {
        bytes32[] memory buffer = EfficientHashLib.malloc(packages.length);
        unchecked {
            for (uint256 i = 0; i < packages.length; i++) {
                Install calldata pkg = packages[i];
                EfficientHashLib.set(
                    buffer,
                    i,
                    EfficientHashLib.hash(
                        uint256(INSTALL_STRUCT_HASH),
                        pkg.moduleType,
                        uint256(uint160(pkg.module)),
                        uint256(EfficientHashLib.hashCalldata(pkg.moduleData)),
                        uint256(EfficientHashLib.hashCalldata(pkg.internalData))
                    )
                );
            }
        }
        return EfficientHashLib.hash(buffer);
    }

    /// @notice Installs a scoped execution hook for a validation, executor, or selector.
    /// @dev internalData is `[scope | target]`: 22 bytes for a ValidationId,
    ///      21 bytes for an executor address, or 5 bytes for a selector.
    function _installScopedExecutionHook(address hook, bytes calldata internalData, bool installSuccess) internal {
        require(installSuccess && hook.code.length > 0, ModuleInstallFailed());
        bytes1 scope = _scopedExecutionHookScope(internalData);
        if (scope == SCOPED_EXECUTION_HOOK_VALIDATION_SCOPE) {
            require(internalData.length == SCOPED_EXECUTION_HOOK_VALIDATION_DATA_LENGTH, InvalidDataLength());
            ValidationId vId = ValidationId.wrap(
                bytes21(internalData[SCOPED_EXECUTION_HOOK_TARGET_OFFSET:SCOPED_EXECUTION_HOOK_VALIDATION_DATA_LENGTH])
            );
            ValidationType vType = getType(vId);
            require(
                vType == VALIDATION_TYPE_VALIDATOR || vType == VALIDATION_TYPE_PERMISSION,
                InvalidScopedExecutionHookTarget()
            );
            _installValidationScopedExecutionHook(hook, vId, installSuccess);
        } else if (scope == SCOPED_EXECUTION_HOOK_EXECUTOR_SCOPE) {
            require(internalData.length == SCOPED_EXECUTION_HOOK_EXECUTOR_DATA_LENGTH, InvalidDataLength());
            IExecutor executor = IExecutor(
                address(
                    bytes20(
                        internalData[SCOPED_EXECUTION_HOOK_TARGET_OFFSET:SCOPED_EXECUTION_HOOK_EXECUTOR_DATA_LENGTH]
                    )
                )
            );
            ExecutorConfig storage config = _executorConfig(executor);
            require(config.installed, InvalidScopedExecutionHookTarget());
            require(
                address(config.scopedExecutionHook) == SCOPED_EXECUTION_HOOK_NOT_INSTALLED,
                ScopedExecutionHookAlreadyInstalled()
            );
            config.scopedExecutionHook = IScopedExecutionHook(hook);
        } else if (scope == SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE) {
            require(internalData.length == SCOPED_EXECUTION_HOOK_SELECTOR_DATA_LENGTH, InvalidDataLength());
            bytes4 selector =
                bytes4(internalData[SCOPED_EXECUTION_HOOK_TARGET_OFFSET:SCOPED_EXECUTION_HOOK_SELECTOR_DATA_LENGTH]);
            SelectorConfig storage config = _selectorConfig(selector);
            require(config.target != SELECTOR_NOT_INSTALLED, InvalidScopedExecutionHookTarget());
            require(
                address(config.scopedExecutionHook) == SCOPED_EXECUTION_HOOK_NOT_INSTALLED,
                ScopedExecutionHookAlreadyInstalled()
            );
            config.scopedExecutionHook = IScopedExecutionHook(hook);
        } else {
            revert InvalidScopedExecutionHookTarget();
        }
    }

    /// @notice Uninstalls a scoped execution hook from a validation, executor, or selector.
    function _uninstallScopedExecutionHook(address hook, bytes calldata internalData, bool) internal {
        bytes1 scope = _scopedExecutionHookScope(internalData);
        if (scope == SCOPED_EXECUTION_HOOK_VALIDATION_SCOPE) {
            require(internalData.length == SCOPED_EXECUTION_HOOK_VALIDATION_DATA_LENGTH, InvalidDataLength());
            _uninstallScopedExecutionHookWithVid(
                hook,
                ValidationId.wrap(
                    bytes21(
                        internalData[SCOPED_EXECUTION_HOOK_TARGET_OFFSET:SCOPED_EXECUTION_HOOK_VALIDATION_DATA_LENGTH]
                    )
                )
            );
        } else if (scope == SCOPED_EXECUTION_HOOK_EXECUTOR_SCOPE) {
            require(internalData.length == SCOPED_EXECUTION_HOOK_EXECUTOR_DATA_LENGTH, InvalidDataLength());
            ExecutorConfig storage config = _executorConfig(
                IExecutor(
                    address(
                        bytes20(
                            internalData[SCOPED_EXECUTION_HOOK_TARGET_OFFSET:SCOPED_EXECUTION_HOOK_EXECUTOR_DATA_LENGTH]
                        )
                    )
                )
            );
            require(address(config.scopedExecutionHook) == hook, InvalidScopedExecutionHookTarget());
            config.scopedExecutionHook = IScopedExecutionHook(SCOPED_EXECUTION_HOOK_NOT_INSTALLED);
        } else if (scope == SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE) {
            require(internalData.length == SCOPED_EXECUTION_HOOK_SELECTOR_DATA_LENGTH, InvalidDataLength());
            SelectorConfig storage config = _selectorConfig(
                bytes4(internalData[SCOPED_EXECUTION_HOOK_TARGET_OFFSET:SCOPED_EXECUTION_HOOK_SELECTOR_DATA_LENGTH])
            );
            require(address(config.scopedExecutionHook) == hook, InvalidScopedExecutionHookTarget());
            config.scopedExecutionHook = IScopedExecutionHook(SCOPED_EXECUTION_HOOK_NOT_INSTALLED);
        } else {
            revert InvalidScopedExecutionHookTarget();
        }
    }

    function _scopedExecutionHookScope(bytes calldata internalData) private pure returns (bytes1 scope) {
        require(internalData.length > 0, InvalidDataLength());
        scope = bytes1(internalData[0]);
    }

    function _isScopedExecutionHookInstalled(address hook, bytes calldata context) internal view returns (bool) {
        if (context.length == 0) return false;
        bytes1 scope = bytes1(context[0]);
        if (scope == SCOPED_EXECUTION_HOOK_VALIDATION_SCOPE) {
            if (context.length != SCOPED_EXECUTION_HOOK_VALIDATION_DATA_LENGTH) return false;
            ValidationId vId = ValidationId.wrap(
                bytes21(context[SCOPED_EXECUTION_HOOK_TARGET_OFFSET:SCOPED_EXECUTION_HOOK_VALIDATION_DATA_LENGTH])
            );
            return address(_validationStorage().vInfo[vId].scopedExecutionHook) == hook;
        }
        if (scope == SCOPED_EXECUTION_HOOK_EXECUTOR_SCOPE) {
            if (context.length != SCOPED_EXECUTION_HOOK_EXECUTOR_DATA_LENGTH) return false;
            address executor = address(
                bytes20(context[SCOPED_EXECUTION_HOOK_TARGET_OFFSET:SCOPED_EXECUTION_HOOK_EXECUTOR_DATA_LENGTH])
            );
            return address(_executorConfig(IExecutor(executor)).scopedExecutionHook) == hook;
        }
        if (scope == SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE) {
            if (context.length != SCOPED_EXECUTION_HOOK_SELECTOR_DATA_LENGTH) return false;
            return address(
                _selectorConfig(
                bytes4(context[SCOPED_EXECUTION_HOOK_TARGET_OFFSET:SCOPED_EXECUTION_HOOK_SELECTOR_DATA_LENGTH])
            )
                .scopedExecutionHook
            ) == hook;
        }
        return false;
    }

    /// @notice Routes a module installation to the appropriate type-specific handler.
    /// @param moduleType The module type (1=validator, 2=executor, 3=fallback, 5=policy, 6=signer, 11=scoped execution hook).
    /// @param module The module address.
    /// @param moduleData Data forwarded to the module's onInstall callback.
    /// @param internalData Kernel-internal configuration data (format varies by module type).
    function _installModule(uint256 moduleType, address module, bytes calldata moduleData, bytes calldata internalData)
        internal
        installModuleHook(moduleType, module)
    {
        function(address, bytes calldata, bool) hook;
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            hook = _installValidator;
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            hook = _installExecutor;
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            hook = _installSelector;
        } else if (moduleType == MODULE_TYPE_POLICY) {
            hook = _installPolicy;
        } else if (moduleType == MODULE_TYPE_SIGNER) {
            hook = _installSigner;
        } else if (moduleType == MODULE_TYPE_SCOPED_EXECUTION_HOOK) {
            hook = _installScopedExecutionHook;
        } else {
            revert NotImplemented();
        }
        _install(module, moduleData, internalData, hook);
        emit ModuleInstalled(moduleType, module);
    }

    /// @notice Routes a module uninstallation to the appropriate type-specific handler.
    /// @param moduleType The module type.
    /// @param module The module address.
    /// @param moduleData Data forwarded to the module's onUninstall callback.
    /// @param internalData Kernel-internal configuration data.
    function _uninstallModule(
        uint256 moduleType,
        address module,
        bytes calldata moduleData,
        bytes calldata internalData
    ) internal {
        function(address, bytes calldata, bool) hook;
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            hook = _uninstallValidator;
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            hook = _uninstallExecutor;
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            hook = _uninstallSelector;
        } else if (moduleType == MODULE_TYPE_POLICY) {
            hook = _uninstallPolicy;
        } else if (moduleType == MODULE_TYPE_SIGNER) {
            hook = _uninstallSigner;
        } else if (moduleType == MODULE_TYPE_SCOPED_EXECUTION_HOOK) {
            hook = _uninstallScopedExecutionHook;
        } else {
            revert NotImplemented();
        }
        _uninstall(module, moduleData, internalData, hook);
        emit ModuleUninstalled(moduleType, module);
    }

    /// @notice Batch-installs an array of module packages and verifies permission completeness.
    /// @param packages The install packages to process sequentially.
    function _install(Install[] calldata packages) internal {
        unchecked {
            for (uint256 i = 0; i < packages.length; i++) {
                Install calldata pkg = packages[i];
                _installModule(pkg.moduleType, pkg.module, pkg.moduleData, pkg.internalData);
            }
        }

        require(
            ValidationId.unwrap(installingPermission) == bytes21(0)
                || _validationStorage().vInfo[installingPermission].signer != address(0),
            PermissionInstallNotFinished()
        );
    }

    /// @notice Calls a module's onInstall and passes the result to the type-specific handler.
    /// @param module The module address.
    /// @param data Data forwarded to onInstall.
    /// @param internalData Internal configuration data forwarded to the handler.
    /// @param hook The type-specific install handler function.
    function _install(
        address module,
        bytes calldata data,
        bytes calldata internalData,
        function(address, bytes calldata, bool) hook
    ) internal {
        (bool success,) = module.call(abi.encodeWithSelector(IModule.onInstall.selector, data));
        hook(module, internalData, success);
    }

    /// @notice Revokes a module via the type-specific handler, then calls its onUninstall.
    /// @dev Authority is cleared BEFORE the callback: `executeFromExecutor` authorizes on the
    ///      executor's `installed` flag alone, so a callback fired first could reenter it while
    ///      still installed and with its scoped hook already removed. Every uninstall handler
    ///      ignores the success flag, so the callback result is not observed.
    /// @param module The module address.
    /// @param data Data forwarded to onUninstall.
    /// @param internalData Internal configuration data forwarded to the handler.
    /// @param hook The type-specific uninstall handler function.
    function _uninstall(
        address module,
        bytes calldata data,
        bytes calldata internalData,
        function(address, bytes calldata, bool) hook
    ) internal {
        hook(module, internalData, true);
        // forge-lint: disable-next-line(unchecked-call)
        module.call(abi.encodeWithSelector(IModule.onUninstall.selector, data));
    }

    /// @notice Verifies an install signature, increments the nonce, and returns success.
    /// @param replayable If true, uses chain-agnostic hashing.
    /// @param _nonce The install nonce.
    /// @param packages The packages being installed.
    /// @param signature The root validator's signature.
    /// @return success True if the signature is valid and the nonce is correct.
    function _verifyInstallSignature(
        bool replayable,
        uint256 _nonce,
        Install[] calldata packages,
        bytes calldata signature
    ) internal returns (bool success) {
        uint256 validationData = _verifyInstallSignatureRaw(replayable, _nonce, packages, signature);
        _checkAndIncrementNonce(_nonce);
        return Lib4337.checkValidation(validationData);
    }

    /// @notice Sets the global minimum nonce, invalidating all nonces below it.
    /// @param nonceFrom The new minimum nonce value; must exceed the current value.
    function _setValidNonceFrom(uint64 nonceFrom) internal {
        ModuleStorage storage ms = _moduleStorage();
        require(nonceFrom > ms.nonceValidFrom, InvalidNonce());
        ms.nonceValidFrom = nonceFrom;
    }

    /// @notice Sets the nonce for a specific key; must be strictly increasing.
    /// @param nonceKey The 192-bit nonce key.
    /// @param seq The new sequence number; must exceed the current value.
    function _setNonce(uint192 nonceKey, uint64 seq) internal {
        ModuleStorage storage ms = _moduleStorage();
        require(seq > ms.nonce[nonceKey], InvalidNonce());
        ms.nonce[nonceKey] = seq;
    }

    /// @notice Validates and increments the nonce atomically. Reverts if sequence mismatch.
    /// @param _nonce The full 256-bit nonce (key << 64 | seq).
    function _checkAndIncrementNonce(uint256 _nonce) internal virtual {
        // forge-lint: disable-next-line(unsafe-typecast)
        uint192 key = uint192(_nonce >> 64);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 seq = uint64(_nonce);
        ModuleStorage storage ms = _moduleStorage();
        if (ms.nonceValidFrom > ms.nonce[key]) {
            ms.nonce[key] = ms.nonceValidFrom;
        }
        require(ms.nonce[key]++ == seq, InvalidNonce());
    }

    /// @notice Validates a nonce without incrementing. Reverts on sequence mismatch.
    /// @param _nonce The full 256-bit nonce (key << 64 | seq).
    function _checkNonce(uint256 _nonce) internal view virtual {
        // forge-lint: disable-next-line(unsafe-typecast)
        uint192 key = uint192(_nonce >> 64);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 seq = uint64(_nonce);
        ModuleStorage storage ms = _moduleStorage();
        bool result;
        if (ms.nonceValidFrom > ms.nonce[key]) {
            result = seq == ms.nonceValidFrom;
        } else {
            result = ms.nonce[key] == seq;
        }
        require(result, InvalidNonce());
    }

    /// @notice Verifies an install signature without modifying nonce state.
    /// @param replayable If true, uses chain-agnostic EIP-712 hashing.
    /// @param _nonce The install nonce for the digest.
    /// @param packages The packages to include in the digest.
    /// @param signature The root validator's signature.
    /// @return validationData Packed validation result from signature verification.
    function _verifyInstallSignatureRaw(
        bool replayable,
        uint256 _nonce,
        Install[] calldata packages,
        bytes calldata signature
    ) internal view returns (uint256 validationData) {
        ValidationId vId = _validationStorage().root;
        function(bytes32) internal view returns (bytes32) hashTypedData =
            replayable ? _hashTypedDataSansChainId : _hashTypedData;
        _checkNonce(_nonce);
        bytes32 digest =
            hashTypedData(EfficientHashLib.hash(INSTALL_PACKAGES_STRUCT_HASH, bytes32(_nonce), _installHash(packages)));
        return _verifySignature(vId, address(this), digest, signature);
    }
}
