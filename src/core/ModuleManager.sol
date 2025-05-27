pragma solidity ^0.8.0;

import "../interfaces/IERC7579Modules.sol";
import {ValidationManager} from "./ValidationManager.sol";
import {ExecutorManager} from "./ExecutorManager.sol";
import {HookManager} from "./HookManager.sol";
import {SelectorManager} from "./SelectorManager.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import "../types/Error.sol";
import "../types/Events.sol";
import "../types/Structs.sol";
import "../types/Constants.sol";
import "../types/Types.sol";
import "../lib/Utils.sol";
import "../lib/Lib4337.sol";

struct ModuleStorage {
    mapping(uint192 key => uint64) nonce;
}

abstract contract ModuleManager is ValidationManager, ExecutorManager, HookManager, SelectorManager, EIP712 {
    modifier executorHook() {
        IHook hook = _executorConfig(IExecutor(msg.sender)).hook;
        bytes memory hookData = _preHook(hook);
        _;
        _postHook(hook, hookData);
    }

    function _initialized() internal view returns (bool) {
        return bytes3(address(this).code) == bytes3(0xef0100)
            || ValidationId.unwrap(_validationStorage().root) != bytes20(0);
    }

    function _moduleStorage() internal view returns (ModuleStorage storage $) {
        assembly {
            $.slot := MODULE_MANAGER_STORAGE_SLOT
        }
    }

    function _installHash(Install[] calldata packages) internal pure returns (bytes32) {
        bytes32[] memory packageHashes = new bytes32[](packages.length);
        for (uint256 i = 0; i < packages.length; i++) {
            Install calldata pkg = packages[i];
            packageHashes[i] = keccak256(
                abi.encode(pkg.moduleType, pkg.module, calldataKeccak(pkg.moduleData), calldataKeccak(pkg.internalData))
            );
        }
        return keccak256(abi.encodePacked(packageHashes));
    }

    function _installModule(uint256 moduleType, address module, bytes calldata moduleData, bytes calldata internalData)
        internal
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

    function _verifyExecutionData(
        bytes32 mode,
        bytes calldata callData
    ) internal view returns(bool success) {
    }

    function _verifyInstallSignature(
        bool replayable,
        uint256 nonce,
        Install[] calldata packages,
        bytes calldata signature
    ) internal view returns (bool success) {
        uint256 validationData = _verifyInstallSignatureRaw(replayable, nonce, packages, signature);
        return Lib4337.checkValidation(validationData);
    }

    function _verifyInstallSignatureRaw(
        bool replayable,
        uint256 nonce,
        Install[] calldata packages,
        bytes calldata signature
    ) internal view returns (uint256 validationData) {
        ValidationId vId = _validationStorage().root;
        function(bytes32) internal view returns(bytes32) hashTypedData =
            replayable ? _hashTypedDataSansChainId : _hashTypedData;
        bytes32 digest = hashTypedData(
            keccak256(
                abi.encode(
                    keccak256(
                        "InstallPackages(uint256 nonce,Install[] packages)Install(uint256 moduleType,address module,bytes moduleData,bytes internalData)"
                    ),
                    nonce,
                    _installHash(packages)
                )
            )
        );
        return _verifySignature(vId, address(this), digest, signature);
    }
}
