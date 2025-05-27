pragma solidity ^0.8.0;

import "../interfaces/IERC7579Modules.sol";
import {ValidationManager} from "./ValidationManager.sol";
import {ExecutorManager} from "./ExecutorManager.sol";
import {HookManager} from "./HookManager.sol";
import {SelectorManager} from "./SelectorManager.sol";
import {ERC1271} from "solady/accounts/ERC1271.sol";
import "../types/Error.sol";
import "../types/Events.sol";
import "../types/Structs.sol";
import "../types/Constants.sol";
import "../types/Types.sol";
import "../lib/Utils.sol";
import "../lib/Lib4337.sol";

struct ModuleStorage {
    uint64 nonceValidFrom;
    mapping(uint192 key => uint64) nonce;
}

abstract contract ModuleManager is ValidationManager, ExecutorManager, HookManager, SelectorManager, ERC1271 {
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

    function _erc1271Signer() internal view override returns (address) {
        return address(1);
    }

    function _installHash(Install[] calldata packages) internal pure returns (bytes32) {
        bytes32[] memory packageHashes = new bytes32[](packages.length);
        unchecked {
            for (uint256 i = 0; i < packages.length; i++) {
                Install calldata pkg = packages[i];
                packageHashes[i] = keccak256(
                    abi.encode(pkg.moduleType, pkg.module, calldataKeccak(pkg.moduleData), calldataKeccak(pkg.internalData))
                );
            }
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


    function _verifyInstallSignature(
        bool replayable,
        uint256 nonce,
        Install[] calldata packages,
        bytes calldata signature
    ) internal returns (bool success) {
        uint256 validationData = _verifyInstallSignatureRaw(replayable, nonce, packages, signature);
        return Lib4337.checkValidation(validationData);
    }

    function _checkNonce(uint256 nonce) internal virtual returns(bool) {
        uint192 key = uint192(nonce >> 64);
        uint64 seq = uint64(nonce);
        return _moduleStorage().nonce[key]++ == seq;
    }

    function _verifyInstallSignatureRaw(
        bool replayable,
        uint256 nonce,
        Install[] calldata packages,
        bytes calldata signature
    ) internal returns (uint256 validationData) {
        ValidationId vId = _validationStorage().root;
        function(bytes32) internal view returns(bytes32) hashTypedData =
            replayable ? _hashTypedDataSansChainId : _hashTypedData;
        _checkNonce(nonce);
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

    // NOTE : heavily motivated by solady's erc7821
    function _verifyExecutionData(
        bytes32 mode,
        bytes calldata executionData
    ) internal returns(bool success) {
        uint256 id = _executionModeId(mode);
        if(id < 2) {
            return true;
        }
        bytes calldata opData;
        Call[] calldata calls;
        assembly {
            // Use inline assembly to extract the calls and optional `opData` efficiently.
            opData.length := 0
            let o := add(executionData.offset, calldataload(executionData.offset))
            calls.offset := add(o, 0x20)
            calls.length := calldataload(o)
            // If the offset of `executionData` allows for `opData`, and the mode supports it.
            if gt(eq(id, 2), gt(0x40, calldataload(executionData.offset))) {
                let q := add(executionData.offset, calldataload(add(0x20, executionData.offset)))
                opData.offset := add(q, 0x20)
                opData.length := calldataload(q)
            }
            // Bounds checking for `executionData` is skipped here for efficiency.
            // This is safe if it is only used as an argument to `execute` externally.
            // If `executionData` used as an argument to other functions externally,
            // please perform the bounds checks via `LibERC7579.decodeBatchAndOpData`
            /// or `abi.decode` in the other functions for safety.
        }
        InstallAndExecute calldata exec;
        assembly {
            exec := opData.offset
        }
        
        success = _verifyInstallAndExecuteSignature(
            mode,
            calls,
            exec
        );

        _install(exec.packages);
    }
    
    // NOTE : heavily motivated by solady's erc7821
    /// @dev 0: invalid mode, 1: no `opData` support, 2: with `opData` support
    function _executionModeId(bytes32 mode) internal view virtual returns (uint256 id) {
        // Only supports atomic batched executions.
        // For the encoding scheme, see: https://eips.ethereum.org/EIPS/eip-7579
        // Bytes Layout:
        // - [0]      ( 1 byte )  `0x01` for batch call.
        // - [1]      ( 1 byte )  `0x00` for revert on any failure.
        // - [2..5]   ( 4 bytes)  Reserved by ERC7579 for future standardization.
        // - [6..9]   ( 4 bytes)  `0x00000000` or `0x78210001` or `0x78210002`.
        // - [10..31] (22 bytes)  Unused. Free for use.
        /// @solidity memory-safe-assembly
        assembly {
            let m := and(shr(mul(22, 8), mode), 0xffff00000000ffffffff)
            id := eq(m, 0x01000000000000000000) // 1.
            id := or(shl(1, eq(m, 0x01000000000078210001)), id) // 2.
        }
    }
    
    function _verifyInstallAndExecuteSignature(
        bytes32 mode,
        Call[] calldata calls,
        InstallAndExecute calldata opData
    ) internal returns (bool) {
        ValidationId vId = _validationStorage().root;
        function(bytes32) internal view returns(bytes32) hashTypedData =
            opData.replayable ? _hashTypedDataSansChainId : _hashTypedData;
        _checkNonce(opData.nonce);
        bytes32 digest = hashTypedData(
            keccak256(
                abi.encode(
                    keccak256(
                        "ExecuteWithInstall(bytes32 mode, bytes execData,uint256 nonce,Install[] packages)Install(uint256 moduleType,address module,bytes moduleData,bytes internalData)"
                    ),
                    mode,
                    keccak256(abi.encode(calls)),
                    opData.nonce,
                    _installHash(opData.packages)
                )
            )
        );
        return Lib4337.checkValidation(_verifySignature(vId, address(this), digest, opData.signature));
    }
}
