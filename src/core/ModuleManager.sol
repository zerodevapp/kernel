// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IModule, IValidator, IStatelessValidatorWithSender} from "../interfaces/IERC7579Modules.sol";
import {ValidationManager} from "./ValidationManager.sol";
import {ExecutorManager} from "./ExecutorManager.sol";
import {SelectorManager} from "./SelectorManager.sol";
import {ERC1271} from "../lib/ERC1271.sol";
import {
    InvalidValidationType,
    InvalidNonce,
    InvalidValidator,
    InvalidPermissionId,
    InvalidSignature,
    NotImplemented,
    PermissionInstallNotFinished,
    LastSignatureShouldBeSigner
} from "../types/Error.sol";
import {ModuleInstalled, ModuleUninstalled} from "../types/Events.sol";
import {Install, EnableModeSignature, ModuleStorage, PermissionSignature} from "../types/Structs.sol";
import {
    ValidationId,
    ValidationMode,
    ValidationType,
    PermissionId,
    isEnable,
    isEnableReplayable
} from "../types/Types.sol";
import {Lib4337} from "../lib/Lib4337.sol";
import {getType, getValidator, getPermissionId, validatorToIdentifier, permissionToIdentifier} from "../lib/Utils.sol";
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
    MODULE_TYPE_SIGNER
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

    function _erc1271IsValidSignatureNowCalldata(bytes32 hash, bytes calldata signature)
        internal
        view
        override
        returns (bool result)
    {
        // check if fallback signature is allowed
        if (_erc1271RawAllowed()) {
            result = _verifyFallbackSignature(hash, signature);
        }
        if (!result) {
            ValidationMode vMode = ValidationMode.wrap(bytes1(signature[0]));
            ValidationType vType = ValidationType.wrap(bytes1(signature[1]));
            ValidationId vId;
            if (vType == VALIDATION_TYPE_ROOT) {
                vId = _validationStorage().root;
                signature = signature[2:];
            } else if (vType == VALIDATION_TYPE_VALIDATOR) {
                vId = validatorToIdentifier(IValidator(address(bytes20(signature[2:22]))));
                signature = signature[22:];
            } else if (vType == VALIDATION_TYPE_PERMISSION) {
                vId = permissionToIdentifier(PermissionId.wrap(bytes4(signature[2:6])));
                signature = signature[6:];
            } else {
                revert InvalidValidationType();
            }
            uint256 validationData;
            if (isEnable(vMode)) {
                require(vType != VALIDATION_TYPE_ROOT, InvalidValidationType());
                bool enableReplayable = isEnableReplayable(vMode);
                EnableModeSignature calldata sig;
                assembly {
                    sig := signature.offset
                }
                if (!Lib4337.checkValidation(
                        _verifyInstallSignatureRaw(enableReplayable, sig.nonce, sig.packages, sig.enableSignature)
                    )) {
                    // if enable sig is invalid, short circuit
                    return false;
                }
                _checkNonce(sig.nonce);
                return _verifyStatelessSignature(sig.packages, vId, hash, sig.userOpSignature);
            } else {
                validationData = _verifySignature(vId, msg.sender, hash, signature);
            }
            result = Lib4337.checkValidation(validationData);
        }
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

    /// @notice Routes a module installation to the appropriate type-specific handler.
    /// @param moduleType The module type (1=validator, 2=executor, 3=fallback, 5=policy, 6=signer).
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

    /// @notice Calls a module's onUninstall and passes the result to the type-specific handler.
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
        (bool success,) = module.call(abi.encodeWithSelector(IModule.onUninstall.selector, data));
        hook(module, internalData, success);
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

    /// @notice Verifies a stateless signature for enable-mode ERC-1271 flows.
    /// @dev Locates the validator/permission modules in the packages and calls their stateless verify.
    /// @param packages The install packages containing the modules to verify against.
    /// @param vId The validation identifier to use.
    /// @param hash The hash to verify.
    /// @param signature The signature bytes.
    /// @return True if the stateless signature verification succeeds.
    function _verifyStatelessSignature(
        Install[] calldata packages,
        ValidationId vId,
        bytes32 hash,
        bytes calldata signature
    ) internal view returns (bool) {
        ValidationType vType = getType(vId);
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator validator = getValidator(vId);
            uint256 i;
            for (i; i < packages.length; i++) {
                Install calldata pkg = packages[i];
                if (pkg.moduleType == MODULE_TYPE_VALIDATOR && pkg.module == address(validator)) {
                    break;
                }
            }
            require(i < packages.length, InvalidValidator());
            return IStatelessValidatorWithSender(address(validator))
                .validateSignatureWithDataWithSender(msg.sender, hash, signature, packages[i].moduleData);
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            PermissionId pId = getPermissionId(vId);
            PermissionSignature calldata permissionSig;
            assembly {
                permissionSig := signature.offset
            }
            require(permissionSig.signatures.length > 0, InvalidSignature());
            uint256 sigIdx;
            for (uint256 i; i < packages.length; i++) {
                Install calldata pkg = packages[i];
                // Restrict matching to policy (5) / signer (6) modules. Otherwise a
                // package of a different module type (e.g. selector type 3 or hook type 4)
                // whose internalData happens to start with `pId` would be enrolled into the
                // permission's signature chain.
                if (PermissionId.wrap(bytes4(pkg.internalData)) == pId && (pkg.moduleType == 5 || pkg.moduleType == 6))
                {
                    if (sigIdx == permissionSig.signatures.length - 1) {
                        require(pkg.moduleType == MODULE_TYPE_SIGNER, LastSignatureShouldBeSigner());
                        require(IModule(pkg.module).isModuleType(MODULE_TYPE_SIGNER), LastSignatureShouldBeSigner());
                    }
                    bool res = IStatelessValidatorWithSender(pkg.module)
                        .validateSignatureWithDataWithSender(
                            msg.sender,
                            hash,
                            permissionSig.signatures[sigIdx],
                            pkg.moduleData // NOTE: not passing the permissionId as stateless does not need any permissionId
                        );
                    if (!res) {
                        return false;
                    }
                    sigIdx++;
                }
            }
            require(sigIdx == permissionSig.signatures.length, InvalidPermissionId());
            return true;
        } else {
            revert InvalidValidationType();
        }
    }
}
