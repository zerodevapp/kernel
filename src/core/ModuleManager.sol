pragma solidity ^0.8.0;

import {IHook, IExecutor, IModule, IValidator, IStatelessValidatorWithSender} from "../interfaces/IERC7579Modules.sol";
import {ValidationManager} from "./ValidationManager.sol";
import {ExecutorManager} from "./ExecutorManager.sol";
import {HookManager} from "./HookManager.sol";
import {SelectorManager} from "./SelectorManager.sol";
import {ERC1271} from "../lib/ERC1271.sol";
import {InvalidValidationType, InvalidNonce, InvalidValidator, NotImplemented, Unauthorized} from "../types/Error.sol";
import {ModuleInstalled, ModuleUninstalled} from "../types/Events.sol";
import {
    Install,
    Call,
    InstallAndExecute,
    EnableModeSignature,
    ModuleStorage,
    PermissionSignature
} from "../types/Structs.sol";
import {
    ValidationId,
    ValidationMode,
    ValidationType,
    PermissionId,
    isEnable,
    isEnableReplayable
} from "../types/Types.sol";
import {calldataKeccak} from "../lib/Utils.sol";
import {Lib4337} from "../lib/Lib4337.sol";
import {getType, getValidator, getPermissionId, validatorToIdentifier, permissionToIdentifier} from "../lib/Utils.sol";
import {
    MODULE_MANAGER_STORAGE_SLOT,
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION
} from "../types/Constants.sol";

abstract contract ModuleManager is ValidationManager, ExecutorManager, HookManager, SelectorManager, ERC1271 {
    modifier executorHook() {
        IHook hook = _executorConfig(IExecutor(msg.sender)).hook;
        require(address(hook) != address(0), Unauthorized());
        bytes memory hookData = _preHook(hook, msg.data);
        _;
        _postHook(hook, hookData);
    }

    // NOTE : override this to use erc7484 registry
    modifier installModuleHook(uint256 moduleType, address module) virtual {
        _;
    }

    function registry() external view returns (address) {
        return _moduleStorage().registry;
    }

    function validNonceFrom() external view returns (uint64) {
        return _moduleStorage().nonceValidFrom;
    }

    function nonce(uint192 key) external view returns (uint256) {
        uint64 seq = _moduleStorage().nonce[key];
        if (_moduleStorage().nonceValidFrom > seq) {
            seq = _moduleStorage().nonceValidFrom;
        }
        return (uint256(key) << 64) + seq;
    }

    function _hookEnabled(IHook _hook) internal view override(ValidationManager, HookManager) returns (bool) {
        return HookManager._hookEnabled(_hook);
    }

    function _initialized() internal view virtual returns (bool) {
        return _statelessInitializeCheck() || _statefulInitializeCheck();
    }

    function _statelessInitializeCheck() internal view virtual returns (bool) {
        return bytes3(address(this).code) == bytes3(0xef0100);
    }

    function _statefulInitializeCheck() internal view virtual returns (bool) {
        return ValidationId.unwrap(_validationStorage().root) != bytes20(0);
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

    function _installHash(Install[] calldata packages) internal pure returns (bytes32) {
        bytes32[] memory packageHashes = new bytes32[](packages.length);
        unchecked {
            for (uint256 i = 0; i < packages.length; i++) {
                Install calldata pkg = packages[i];
                packageHashes[i] = keccak256(
                    abi.encode(
                        keccak256("Install(uint256 moduleType,address module,bytes moduleData,bytes internalData)"),
                        pkg.moduleType,
                        pkg.module,
                        calldataKeccak(pkg.moduleData),
                        calldataKeccak(pkg.internalData)
                    )
                );
            }
        }
        return keccak256(abi.encodePacked(packageHashes));
    }

    function _installModule(uint256 moduleType, address module, bytes calldata moduleData, bytes calldata internalData)
        internal
        installModuleHook(moduleType, module)
    {
        function(address, bytes calldata, bool) hook;
        if (moduleType == 1) {
            hook = _installValidator;
        } else if (moduleType == 2) {
            hook = _installExecutor;
        } else if (moduleType == 3) {
            hook = _installSelector;
        } else if (moduleType == 4) {
            hook = _installHook;
        } else if (moduleType == 5) {
            hook = _installPolicy;
        } else if (moduleType == 6) {
            hook = _installSigner;
        } else {
            revert NotImplemented();
        }
        _install(module, moduleData, internalData, hook);
        emit ModuleInstalled(moduleType, module);
    }

    function _uninstallModule(
        uint256 moduleType,
        address module,
        bytes calldata moduleData,
        bytes calldata internalData
    ) internal {
        function(address, bytes calldata, bool) hook;
        if (moduleType == 1) {
            hook = _uninstallValidator;
        } else if (moduleType == 2) {
            hook = _uninstallExecutor;
        } else if (moduleType == 3) {
            hook = _uninstallSelector;
        } else if (moduleType == 4) {
            hook = _uninstallHook;
        } else if (moduleType == 5) {
            hook = _uninstallPolicy;
        } else if (moduleType == 6) {
            hook = _uninstallSigner;
        } else {
            revert NotImplemented();
        }
        _uninstall(module, moduleData, internalData, hook);
        emit ModuleUninstalled(moduleType, module);
    }

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
            "Permission Install not finished"
        );
    }

    function _install(
        address module,
        bytes calldata data,
        bytes calldata internalData,
        function(address, bytes calldata, bool) hook
    ) internal {
        (bool success,) = module.call(abi.encodeWithSelector(IModule.onInstall.selector, data));
        hook(module, internalData, success);
    }

    function _uninstall(
        address module,
        bytes calldata data,
        bytes calldata internalData,
        function(address, bytes calldata, bool) hook
    ) internal {
        (bool success,) = module.call(abi.encodeWithSelector(IModule.onUninstall.selector, data));
        hook(module, internalData, success);
    }

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

    function _setValidNonceFrom(uint64 nonceFrom) internal {
        require(nonceFrom > _moduleStorage().nonceValidFrom, InvalidNonce());
        _moduleStorage().nonceValidFrom = nonceFrom;
    }

    function _setNonce(uint192 nonceKey, uint64 seq) internal {
        require(seq > _moduleStorage().nonce[nonceKey], InvalidNonce());
        _moduleStorage().nonce[nonceKey] = seq;
    }

    function _checkAndIncrementNonce(uint256 _nonce) internal virtual returns (bool) {
        uint192 key = uint192(_nonce >> 64);
        uint64 seq = uint64(_nonce);
        if (_moduleStorage().nonceValidFrom > _moduleStorage().nonce[key]) {
            _moduleStorage().nonce[key] = _moduleStorage().nonceValidFrom;
        }
        return _moduleStorage().nonce[key]++ == seq;
    }

    function _checkNonce(uint256 _nonce) internal view virtual returns (bool) {
        uint192 key = uint192(_nonce >> 64);
        uint64 seq = uint64(_nonce);
        if (_moduleStorage().nonceValidFrom > _moduleStorage().nonce[key]) {
            return seq == _moduleStorage().nonceValidFrom;
        }
        return _moduleStorage().nonce[key] == seq;
    }

    function _verifyInstallSignatureRaw(
        bool replayable,
        uint256 _nonce,
        Install[] calldata packages,
        bytes calldata signature
    ) internal view returns (uint256 validationData) {
        ValidationId vId = _validationStorage().root;
        function(bytes32) internal view returns (bytes32) hashTypedData =
            replayable ? _hashTypedDataSansChainId : _hashTypedData;
        require(_checkNonce(_nonce), InvalidNonce());
        bytes32 digest = hashTypedData(
            keccak256(
                abi.encode(
                    keccak256(
                        "InstallPackages(uint256 nonce,Install[] packages)Install(uint256 moduleType,address module,bytes moduleData,bytes internalData)"
                    ),
                    _nonce,
                    _installHash(packages)
                )
            )
        );
        return _verifySignature(vId, address(this), digest, signature);
    }

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
                if (pkg.moduleType == 1 && pkg.module == address(validator)) {
                    break;
                }
            }
            if (packages.length == i) {
                revert InvalidValidator();
            }
            return IStatelessValidatorWithSender(address(validator))
                .validateSignatureWithDataWithSender(msg.sender, hash, signature, packages[i].moduleData);
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            PermissionId pId = getPermissionId(vId);
            PermissionSignature calldata permissionSig;
            assembly {
                permissionSig := signature.offset
            }
            uint256 sigIdx;
            for (uint256 i; i < packages.length; i++) {
                Install calldata pkg = packages[i];
                if (PermissionId.wrap(bytes4(pkg.internalData)) == pId) {
                    if (sigIdx == permissionSig.signatures.length - 1) {
                        require(pkg.moduleType == 6, "last signature should be signer");
                        require(IModule(pkg.module).isModuleType(6), "last signature should be signer");
                    }
                    bool res = IStatelessValidatorWithSender(pkg.module)
                        .validateSignatureWithDataWithSender(
                            msg.sender, hash, abi.encodePacked(pId, permissionSig.signatures[sigIdx]), pkg.moduleData
                        );
                    if (!res) {
                        return false;
                    }
                    sigIdx++;
                }
            }
            require(sigIdx == permissionSig.signatures.length, "signature arr mismatch");
            return true;
        } else {
            revert InvalidValidationType();
        }
    }
}
