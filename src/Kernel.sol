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
    CallType,
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
    InstallSignatureVerificationFailed,
    InvalidDataLength,
    InvalidRootValidation
} from "./types/Error.sol";
import {Received} from "./types/Events.sol";
import {VALIDATION_TYPE_ROOT, VALIDATION_TYPE_PERMISSION, VALIDATION_TYPE_VALIDATOR} from "./types/Constants.sol";
import {
    ValidationStorage,
    ValidationInfo,
    EnableModeSignature,
    SelectorConfig,
    InstallModuleDataFormat,
    PermissionUninstallData
} from "./types/Structs.sol";

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

    function initialize(Install[] calldata packages) external payable virtual;

    function _initialize(Install[] calldata packages) internal virtual {
        require(packages.length > 0);
        Install calldata root = packages[0];
        _install(packages);
        _setRoot(root);
    }

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
            _checkAndIncrementNonce(sig.nonce);
            _install(sig.packages);
            signature = sig.userOpSignature;
        }
        ValidationStorage storage $ = _validationStorage();

        // check if the call data is allowed by the validationId
        if (
            vType == VALIDATION_TYPE_ROOT
                || (_allowedSelector(vId, bytes4(userOp.callData[0:4])) && $.vInfo[vId].hook == address(1))
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

    /// execution
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external payable {
        _onlyEntryPointOrSelf();
        bytes memory context = _preHook(_validationHook(userOpHash), userOp.callData[4:]);
        (bool success, bytes memory ret) = address(this).delegatecall(userOp.callData[4:]);
        // propagete the revert message
        if (!success) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        _postHook(_validationHook(userOpHash), context);
    }

    function execute(bytes32 mode, bytes calldata executionData) external payable {
        _onlyEntryPointOrSelf();
        _execute(mode, executionData);
    }

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
        // if the selector is not initialized, revert
        // if the selector is installed but hook is not set, only entrypoint can call it
        if ($.target == address(0) || ($.hook == IHook(address(0)) && msg.sender != address(ENTRYPOINT))) {
            revert InvalidSelector();
        }
        bytes memory hookData;
        // explicitly set to address(1) to skip the hook while allowing anyone to call it
        if (address($.hook) != address(0) && address($.hook) != address(1)) {
            hookData = _preHook($.hook, msg.data);
        }

        bool success;
        if ($.callType == CallType.wrap(bytes1(0x00))) {
            success = _call($.target, 0, abi.encodePacked(msg.data, msg.sender));
        } else if ($.callType == CallType.wrap(bytes1(0xff))) {
            success = _delegateCall($.target, msg.data);
        }
        if (!success) {
            _onRevertThrow();
        } else {
            res = _getReturn();
        }
        if (address($.hook) != address(0) && address($.hook) != address(1)) {
            _postHook($.hook, hookData);
        }
    }

    function setNonce(uint192 nonceKey, uint64 seq) external payable {
        _onlyEntryPointOrSelf();
        _setNonce(nonceKey, seq);
    }

    function setValidNonceFrom(uint64 seq) external payable {
        _onlyEntryPointOrSelf();
        _setValidNonceFrom(seq);
    }

    function installModule(uint256 moduleType, address module, bytes calldata initData) external payable override {
        _onlyEntryPointOrSelf();
        InstallModuleDataFormat calldata imdf;
        assembly {
            imdf := initData.offset
        }
        _installModule(moduleType, module, imdf.installData, imdf.internalData);
    }

    function uninstallModule(uint256 moduleType, address module, bytes calldata initData) external payable override {
        _onlyEntryPointOrSelf();
        InstallModuleDataFormat calldata imdf;
        assembly {
            imdf := initData.offset
        }
        _uninstallModule(moduleType, module, imdf.installData, imdf.internalData);
    }

    // we are going to let array of pkgs to be installed and use first one as root
    function setRoot(Install[] calldata pkg, bool removeCurrent, bytes calldata uninstallData) external payable {
        _onlyEntryPointOrSelf();
        ValidationId vId = _validationStorage().root;
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
        _install(pkg);
    }

    function setRoot(ValidationId vId) external payable {
        _onlyEntryPointOrSelf();
        _setRoot(vId);
    }

    /// @param selectors parse 4 bytes to get selectors
    function grantAccess(ValidationId vId, bytes calldata selectors) external payable {
        _onlyEntryPointOrSelf();
        _grantAccess(vId, selectors);
    }

    // NOTE : this ONLY allows root signature, for now
    function installModule(bool replayable, uint256 nonce, Install[] calldata packages, bytes calldata signature)
        external
        payable
    {
        // if 7702 or already initialized, use root signature to install module
        require(_verifyInstallSignature(replayable, nonce, packages, signature), InstallSignatureVerificationFailed());
        _install(packages);
    }

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

    function supportsModule(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId < 7 && moduleTypeId != 0;
    }

    function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata additionalContext)
        external
        view
        override
        returns (bool)
    {
        if (moduleTypeId == 1) {
            ValidationId vId = validatorToIdentifier(IValidator(module));
            return _validationStorage().vInfo[vId].hook != address(0);
        } else if (moduleTypeId == 2) {
            return address(_executorConfig(IExecutor(module)).hook) != address(0);
        } else if (moduleTypeId == 3) {
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes4 selector = bytes4(additionalContext);
            return _selectorConfig(selector).target == module;
        } else if (moduleTypeId == 4) {
            return _hookStorage().enabled[module];
        } else if (moduleTypeId == 5) {
            // forge-lint: disable-next-line(unsafe-typecast)
            ValidationId vId = permissionToIdentifier(PermissionId.wrap(bytes4(additionalContext)));
            ValidationInfo storage $ = _validationStorage().vInfo[vId];
            for (uint256 i = 0; i < $.policies.length; i++) {
                if ($.policies[i] == module) {
                    return true;
                }
            }
            return false;
        } else if (moduleTypeId == 6) {
            // forge-lint: disable-next-line(unsafe-typecast)
            ValidationId vId = permissionToIdentifier(PermissionId.wrap(bytes4(additionalContext)));
            ValidationInfo storage $ = _validationStorage().vInfo[vId];
            return $.signer == module;
        } else {
            revert NotImplemented();
        }
    }

    function accountId() external pure override returns (string memory accountImplementationId) {
        return "kernel.v0.4";
    }
}
