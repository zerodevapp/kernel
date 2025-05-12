pragma solidity ^0.8.0;

import "../interfaces/IERC7579Modules.sol";
import {ValidationManager} from "./ValidationManager.sol";
import "../types/Error.sol";
import "../types/Events.sol";

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

function calldataKeccak(bytes calldata data) pure returns (bytes32 ret) {
    assembly ("memory-safe") {
        let mem := mload(0x40)
        let len := data.length
        calldatacopy(mem, data.offset, len)
        ret := keccak256(mem, len)
    }
}

contract ModuleManager is ValidationManager {
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
            hook = _installValidatorHook;
        } else {
            revert NotImplemented();
        }
        _install(module, moduleData, internalData, hook);
        emit ModuleInstalled(moduleType, module);
    }

    function _install(Install[] calldata packages) internal {
        for (uint256 i = 0; i < packages.length; i++) {
            Install calldata pkg = packages[i];
            _installModule(pkg.moduleType, pkg.module, pkg.moduleData, pkg.internalData);
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
        // TODO: make sure we use extra safe call
        (bool success,) = module.call(abi.encodeWithSelector(IModule.onUninstall.selector, data));
        hook(module, internalData, success);
    }
}
