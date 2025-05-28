pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IValidator, IExecutor} from "./interfaces/IERC7579Modules.sol";
import {ModuleManager, Install} from "./core/ModuleManager.sol";
import {parseNonce} from "./core/ValidationManager.sol";
import {ExecutionManager} from "./core/ExecutionManager.sol";
import {Lib4337} from "./lib/Lib4337.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import "./types/Types.sol";
import "./types/Error.sol";
import "./types/Events.sol";
import "./types/Constants.sol";
import "./types/Structs.sol";

contract Kernel is ModuleManager, ExecutionManager, UUPSUpgradeable {
    IEntryPoint immutable entryPoint;

    function _onlyEntryPointOrSelf() internal {
        require(msg.sender == address(entryPoint) || msg.sender == address(this), Unauthorized());
    }

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
    }

    function _authorizeUpgrade(address) internal override {
        _onlyEntryPointOrSelf();
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Kernel";
        version = "0.4.0";
    }

    /// authentication
    struct EnableModeSignature {
        uint256 nonce;
        Install[] packages;
        bytes enableSignature;
        bytes userOpSignature;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        payable
        returns (uint256)
    {
        _onlyEntryPointOrSelf();
        uint256 validationData = _processUserOp(userOp, userOpHash);
        assembly {
            if missingAccountFunds {
                pop(call(gas(), caller(), missingAccountFunds, callvalue(), callvalue(), callvalue(), callvalue()))
                //ignore failure (its EntryPoint's job to verify, not account.)
            }
        }
        return validationData;
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
        function(ValidationId, bytes32, PackedUserOperation memory, bytes calldata) returns(uint256) validateUserOpFn;
        (vMode, vType, vId) = parseNonce(userOp.nonce);

        bytes calldata signature = userOp.signature;
        if (isEnable(vMode)) {
            bool enableReplayable = isEnableReplayable(vMode);
            EnableModeSignature calldata sig;
            assembly {
                sig := signature.offset
            }
            validationData = _verifyInstallSignatureRaw(enableReplayable, sig.nonce, sig.packages, sig.enableSignature);
            _install(sig.packages);
            signature = sig.userOpSignature;
        }
        (vId, validateUserOpFn) = _checkValidation(vMode, vType, vId);
        bytes32 opHash = isReplayable(vMode) ? Lib4337.chainAgnosticUserOpHash(msg.sender, userOp) : userOpHash;
        validationData =
            Lib4337.intersectValidationData(validationData, validateUserOpFn(vId, opHash, userOp, signature));
    }

    /// execution
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external payable {
        _onlyEntryPointOrSelf();
        (bool success, bytes memory ret) = address(this).delegatecall(userOp.callData[4:]);
    }

    function execute(bytes32 mode, bytes calldata executionData) external payable {
        _onlyEntryPointOrSelf();
        _execute(mode, executionData);
    }

    function executeFromExecutor(bytes32 mode, bytes calldata executionData) external payable {
        _verifyExecutionData(mode, executionData);
        _executeFromExecutor(mode, executionData);
    }

    function _executeFromExecutor(bytes32 mode, bytes calldata executionData) internal executorHook {
        _execute(mode, executionData);
    }

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
        if ($.target == address(0)) {
            revert InvalidSelector();
        }
        bytes memory hookData;
        if (address($.hook) != address(0)) {
            hookData = _preHook($.hook);
        }

        bool success;
        if ($.callType == CallType.wrap(bytes1(0x00))) {
            success = _call($.target, 0, msg.data);
        } else if ($.callType == CallType.wrap(bytes1(0xff))) {
            success = _delegateCall($.target, msg.data);
        }
        if (!success) {
            _onRevertThrow();
        } else {
            res = _getReturn();
        }
        if (address($.hook) != address(0)) {
            _postHook($.hook, hookData);
        }
    }

    /// management
    struct InstallModuleDataFormat {
        bytes installData;
        bytes internalData;
    }

    function installModule(uint256 moduleType, address module, bytes calldata initData) external payable {
        _onlyEntryPointOrSelf();
        InstallModuleDataFormat calldata imdf;
        assembly {
            imdf := initData.offset
        }
        _installModule(moduleType, module, imdf.installData, imdf.internalData);
    }

    function uninstallModule(uint256 moduleType, address module, bytes calldata initData) external payable {
        _onlyEntryPointOrSelf();
        InstallModuleDataFormat calldata imdf;
        assembly {
            imdf := initData.offset
        }
        _uninstallModule(moduleType, module, imdf.installData, imdf.internalData);
    }

    function setRoot(ValidationId vId) external payable {
        _onlyEntryPointOrSelf();
        _setRoot(vId);
    }

    // NOTE : this ONLY allows root signature, for now
    function installModule(bool replayable, uint256 nonce, Install[] calldata packages, bytes calldata signature)
        external
    {
        if (_initialized()) {
            // if 7702 or already initialized, use root signature to install module
            require(
                _verifyInstallSignature(replayable, nonce, packages, signature), InstallSignatureVerificationFailed()
            );
            _install(packages);
        } else {
            // this is initialize
            // require first package to be the root validator
            require(packages.length > 0);
            Install calldata root = packages[0];
            _install(packages);
            _setRoot(root);
        }
    }

    fallback(bytes calldata) external payable returns (bytes memory) {
        return _fallback();
    }

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    function supportsExecutionMode(bytes32 mode) external view returns (bool) {
        bytes1 callType = LibERC7579.getCallType(mode);
        bytes1 execType = LibERC7579.getExecType(mode);
        if (execType == LibERC7579.EXECTYPE_DEFAULT || execType == LibERC7579.EXECTYPE_TRY) {} else {
            return false;
        }
        if (
            callType == LibERC7579.CALLTYPE_SINGLE || callType == LibERC7579.CALLTYPE_BATCH
                || callType == LibERC7579.CALLTYPE_DELEGATECALL
        ) {} else {
            return false;
        }
        return true;
    }

    function supportsModule(uint256 moduleTypeId) external view returns (bool) {
        return moduleTypeId < 7;
    }

    function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata additionalContext)
        external
        view
        returns (bool)
    {
        if (moduleTypeId == 1) {
            ValidationId vId = ValidationId.wrap(bytes20(module));
            return !(_validationStorage().vInfo[vId].vType == VALIDATION_TYPE_ROOT);
        } else if (moduleTypeId == 2) {
            return address(_executorConfig(IExecutor(module)).hook) != address(0);
        } else if (moduleTypeId == 3) {
            bytes4 selector = bytes4(additionalContext);
            return _selectorConfig(selector).target == module;
        } else if (moduleTypeId == 4) {
            return _hookStorage().enabled[module];
        } else if (moduleTypeId == 5) {
            ValidationId vId = ValidationId.wrap(bytes20(additionalContext));
            ValidationInfo storage $ = _validationStorage().vInfo[vId];
            for (uint256 i = 0; i < $.policies.length; i++) {
                if ($.policies[i] == module) {
                    return true;
                }
            }
            return false;
        } else if (moduleTypeId == 6) {
            ValidationId vId = ValidationId.wrap(bytes20(additionalContext));
            ValidationInfo storage $ = _validationStorage().vInfo[vId];
            return $.signer == module;
        } else {
            revert NotImplemented();
        }
    }

    function accountId() external view returns (string memory accountImplementationId) {
        return "kernel.v0.4";
    }
}
