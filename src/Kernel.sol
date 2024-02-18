pragma solidity ^0.8.0;

import {PackedUserOperation} from "./interfaces/PackedUserOperation.sol";
import {IAccount, ValidationData} from "./interfaces/IAccount.sol";
import {IAccountExecute} from "./interfaces/IAccountExecute.sol";
import {ModeManager, SigMode, SigData, PackedNonce, KernelNonceLib} from "./core/ModeManager.sol";
import {IValidator, IHook, IExecutor} from "./interfaces/IERC7579Modules.sol";
import "./utils/ExecLib.sol";
import "./core/ExecutionHelper.sol";

contract Kernel is IAccount, IAccountExecute, ModeManager, ExecutionHelper {
    error ExecutionReverted();
    error InvalidMode();
    error InvalidValidator();
    error InvalidExecutor();
    // when eip 1153 has been enabled, this can be transient storage

    mapping(bytes32 userOpHash => IHook) public executionHook;

    // root validator cannot and should not be deleted
    IValidator public rootValidator;

    // selector
    struct SelectorConfig {
        // group of this selector action
        bytes4 group; // 4 bytes, shows which group owns this selector, owner group can call this selector
        CallType callType; //1 bytes
        address target; // 20 bytes target will be fallback module, called with delegatecall or call
    }
    mapping(bytes4 selector => SelectorConfig) public selectorConfig;

    // erc7579 plugins
    struct ValidatorConfig {
        bytes4 group;
        IHook hook; // address(1) : hook not required, address(0) : validator not installed
    }

    mapping(IValidator validator => ValidatorConfig) public validatorConfig;

    struct ExecutorConfig {
        IHook hook; // address(1) : hook not required, address(0) : validator not installed
    }

    mapping(IExecutor executor => ExecutorConfig) public executorConfig;

    // validation part

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        payable
        override
        returns (ValidationData validationData)
    {
        // Major change for v2 => v3
        // 1. instead of packing 4 bytes prefix to userOp.signature to determine the mode, v3 uses userOp.nonce's first 2 bytes to check the mode
        // 2. instead of packing 20 bytes in userOp.signature for enable mode to provide the validator address, v3 uses userOp.nonce[2:22]
        // 3. In v2, only 1 plugin validator(aside from root validator) can access the selector.
        //    In v3, you can use more than 1 plugin to use the exact selector, you need to specify the validator address in userOp.nonce[2:22] to use the validator

        // Examples on standard packing of nonce
        // NOTE : we are going to have support for custom modes. In custom mode, you can use up to 22 bytes for the sigData
        // userOp.nonce = mode selector(2bytes) + sigData(20bytes) + 2d nonce key(2bytes) + incremental nonce (8bytes)
        // *2d nonce with 2 bytes key supports up to 65,536 parallel nonces, so i assume it's more than enough
        // if userOp.nonce starts with 0x0000 => root mode
        //      data == will be ignored
        // if userOp.nonce starts with 0x0001 => plugin mode (erc7579)
        //      data == abi.encodePacked(validatorAddress)
        // if userOp.nonce starts with 0x0002 => plugin enable mode (erc7579)
        //      data == abi.encodePacked(validatorAddress)
        // if userOp.nonce starts with 0x0100 => permission mode
        //      **NOTE TO DEREK : i am on the way of making this 7579 native, so it's not implemented yet, planned to be changed,
        //      but leaving this note for now to make sure i implement something
        //      data == abi.encodePacked(permissionId)
        PackedNonce nonce = PackedNonce.wrap(userOp.nonce);
        _checkMode(KernelNonceLib.getMode(nonce), KernelNonceLib.getData(nonce));
        validationData = _doValidation(KernelNonceLib.getMode(nonce), KernelNonceLib.getData(nonce), userOp, userOpHash);
    }

    function _doValidation(SigMode sigMode, SigData sigData, PackedUserOperation calldata op, bytes32 userOpHash)
        internal
        returns (ValidationData validationData)
    {
        IValidator validator;
        if (SigMode.unwrap(sigMode) == bytes2(0)) {
            validator = rootValidator;
        } else if (SigMode.unwrap(sigMode) == bytes2(uint16(1))) {
            validator = IValidator(address(SigData.unwrap(sigData)));
        } else if (SigMode.unwrap(sigMode) == bytes2(uint16(2))) {
            validator = IValidator(address(SigData.unwrap(sigData)));
            //_checkEnableSig();
            //_addValidator();
        } else {
            revert InvalidMode();
        }

        IHook hook = validatorConfig[validator].hook;
        if (address(hook) == address(0)) {
            revert InvalidValidator();
        }
        executionHook[userOpHash] = hook;

        if (address(hook) == address(1)) {
            if (selectorConfig[bytes4(op.callData[0:4])].group != validatorConfig[validator].group) {
                revert InvalidValidator();
            }
        } else {
            if (selectorConfig[bytes4(op.callData[4:8])].group != validatorConfig[validator].group) {
                revert InvalidValidator();
            }
        }
        validationData = ValidationData.wrap(validator.validateUserOp(op, userOpHash));
    }

    // Hook part

    function _doPreHook(IHook hook, bytes calldata callData) internal returns (bytes memory context) {
        context = hook.preCheck(msg.sender, callData);
    }

    function _doPostHook(IHook hook, bytes memory context)
        // bool success, // I would like these to be enabled in erc7579, but let's skip this for now
        // bytes memory result
        internal
    {
        hook.postCheck(context);
    }

    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external payable override {
        // onlyEntrypoint
        bytes memory context;
        IHook hook = executionHook[userOpHash];
        if (address(hook) != address(1)) {
            // removed 4bytes selector
            context = _doPreHook(hook, userOp.callData[4:]);
        }

        (bool success, bytes memory ret) = address(this).delegatecall(userOp.callData);

        if (address(hook) != address(1)) {
            _doPostHook(hook, context);
        } else if (!success) {
            revert ExecutionReverted();
        }
    }

    function executeFromExecutor(ExecMode execMode, bytes calldata executionCalldata)
        external
        payable
        returns (bytes[] memory returnData)
    {
        // no modifier needed
        IHook hook = executorConfig[IExecutor(msg.sender)].hook;
        if (address(hook) == address(0)) {
            revert InvalidExecutor();
        }
        bytes memory context;
        if (address(hook) != address(1)) {
            context = _doPreHook(hook, msg.data);
        }
        returnData = _execute(execMode, executionCalldata);
        if (address(hook) != address(1)) {
            _doPostHook(hook, context);
        }
    }

    function execute(ExecMode execMode, bytes calldata executionCalldata) external payable {
        // onlyEntrypointOrSelf
        _execute(execMode, executionCalldata);
    }
}
