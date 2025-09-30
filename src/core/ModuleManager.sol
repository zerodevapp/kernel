pragma solidity ^0.8.0;

import {IHook, IExecutor, IModule} from "../interfaces/IERC7579Modules.sol";
import {ValidationManager} from "./ValidationManager.sol";
import {ExecutorManager} from "./ExecutorManager.sol";
import {HookManager} from "./HookManager.sol";
import {SelectorManager} from "./SelectorManager.sol";
import {ERC1271} from "../lib/ERC1271.sol";
import {InvalidNonce, NotImplemented, Unauthorized} from "../types/Error.sol";
import {ModuleInstalled, ModuleUninstalled} from "../types/Events.sol";
import {Install, Call, InstallAndExecute} from "../types/Structs.sol";
import {ValidationId} from "../types/Types.sol";
import {calldataKeccak} from "../lib/Utils.sol";
import {Lib4337} from "../lib/Lib4337.sol";
import {MODULE_MANAGER_STORAGE_SLOT} from "../types/Constants.sol";

struct ModuleStorage {
    address registry; // Note : not used on vanila kernel but saving the storage slot for future usage
    uint64 nonceValidFrom;
    mapping(uint192 key => uint64) nonce;
}

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
        returns (bool)
    {
        ValidationId vId = ValidationId.wrap(bytes20(signature[0:20]));
        if (vId == ValidationId.wrap(bytes20(0))) {
            vId = _validationStorage().root;
        }
        uint256 validationData = _verifySignature(vId, msg.sender, hash, signature[20:]);
        return Lib4337.checkValidation(validationData);
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

    function _checkNonce(uint256 _nonce) internal virtual returns (bool) {
        uint192 key = uint192(_nonce >> 64);
        uint64 seq = uint64(_nonce);
        if (_moduleStorage().nonceValidFrom > _moduleStorage().nonce[key]) {
            _moduleStorage().nonce[key] = _moduleStorage().nonceValidFrom;
        }
        return _moduleStorage().nonce[key]++ == seq;
    }

    function _verifyInstallSignatureRaw(
        bool replayable,
        uint256 _nonce,
        Install[] calldata packages,
        bytes calldata signature
    ) internal returns (uint256 validationData) {
        ValidationId vId = _validationStorage().root;
        function(bytes32) internal view returns(bytes32) hashTypedData =
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
}
