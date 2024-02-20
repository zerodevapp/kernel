pragma solidity ^0.8.0;

import {PackedUserOperation} from "./interfaces/PackedUserOperation.sol";
import {IAccount, ValidationData} from "./interfaces/IAccount.sol";
import {IAccountExecute} from "./interfaces/IAccountExecute.sol";
import {ModeManager, SigMode, SigData, PackedNonce, KernelNonceLib} from "./core/ModeManager.sol";
import {IValidator, IHook, IExecutor} from "./interfaces/IERC7579Modules.sol";
import "./utils/ExecLib.sol";

contract Kernel is IAccount, IAccountExecute, ModeManager {
    error ExecutionReverted();
    error InvalidMode();
    error InvalidValidator();
    error InvalidExecutor();
    error InvalidFallback();
    error InvalidCallType();

    error OnlyExecuteUserOp();
    error InvalidSignature();

    // NOTE : when eip 1153 has been enabled, this can be transient storage
    mapping(bytes32 userOpHash => IHook) public executionHook;

    // root validator cannot and should not be deleted
    IValidator public rootValidator;

    // CHECK is it better to have a group config?
    // erc7579 plugins
    struct ValidatorConfig {
        bytes4 group;
        IHook hook; // address(1) : hook not required, address(0) : validator not installed
    }

    mapping(IValidator validator => ValidatorConfig) public validatorConfig;

    function _installValidator(
        IValidator validator,
        bytes4 group,
        IHook hook,
        bytes calldata data,
        bytes calldata hookData
    ) internal {
        if (address(hook) == address(0)) {
            hook = IHook(address(1));
        }
        validatorConfig[validator] = ValidatorConfig({group: group, hook: hook});
        validator.onInstall(data);
        if (address(hook) != address(1)) {
            hook.onInstall(hookData);
        }
    }

    struct ExecutorConfig {
        bytes4 group;
        IHook hook; // address(1) : hook not required, address(0) : validator not installed
    }

    mapping(IExecutor executor => ExecutorConfig) public executorConfig;

    function _installExecutor(IExecutor executor, bytes4 group, IHook hook, bytes calldata data) internal {
        executorConfig[executor] = ExecutorConfig({group: group, hook: hook});
        executor.onInstall(data);
    }

    struct SelectorConfig {
        bytes4 group; // group of this selector action
        IHook hook; // 20 bytes for hook address
        CallType callType; //1 bytes
        address target; // 20 bytes target will be fallback module, called with delegatecall or call
    }

    mapping(bytes4 selector => SelectorConfig) public selectorConfig;

    function _installSelector(bytes4 selector, bytes4 group, IHook hook, CallType callType, address target) internal {
        selectorConfig[selector] = SelectorConfig({group: group, hook: hook, callType: callType, target: target});
        // TODO : how should i "INSTALL" the delegatecall?
    }

    fallback() external payable {
        SelectorConfig memory config = selectorConfig[msg.sig];
        if (address(config.hook) == address(0)) {
            revert InvalidFallback();
        }
        bytes memory context;
        if (address(config.hook) != address(1)) {
            context = _doPreHook(config.hook, msg.data);
        }
        // do fallback execute
        if (config.callType == CALLTYPE_SINGLE) {
            ExecLib._execute(config.target, msg.value, msg.data);
        } else if (config.callType == CALLTYPE_DELEGATECALL) {
            ExecLib._executeDelegatecall(config.target, msg.data);
        } else {
            revert InvalidCallType();
        }

        if (address(config.hook) != address(1)) {
            _doPostHook(config.hook, context);
        }
    }

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
        // TODO : if userOp.nonce starts with 0x0100 => permission mode
        //      but leaving this note for now to make sure i implement something
        //      data == abi.encodePacked(permissionId) (bytes4)
        PackedNonce nonce = PackedNonce.wrap(userOp.nonce);
        _checkMode(KernelNonceLib.getMode(nonce), KernelNonceLib.getData(nonce));
        validationData = _doValidation(KernelNonceLib.getMode(nonce), KernelNonceLib.getData(nonce), userOp, userOpHash);
    }

    function _parseEnableSig(bytes calldata signature)
        internal
        pure
        returns (
            bytes4 group,
            IHook hook,
            bytes calldata validatorData,
            bytes calldata hookData,
            bytes calldata enableSig,
            bytes calldata userOpSig
        )
    {
        group = bytes4(signature[0:4]);
        hook = IHook(address(bytes20(signature[4:24])));
        assembly {
            validatorData.offset := add(add(signature.offset,32), calldataload(add(signature.offset,24)))
            validatorData.length := calldataload(sub(validatorData.offset, 32))
            hookData.offset := add(add(signature.offset,32), calldataload(add(signature.offset,56)))
            hookData.length := calldataload(sub(hookData.offset, 32))
            enableSig.offset := add(add(signature.offset,32), calldataload(add(signature.offset,88)))
            enableSig.length := calldataload(sub(enableSig.offset, 32))
            userOpSig.offset := add(add(signature.offset,32), calldataload(add(signature.offset,120)))
            userOpSig.length := calldataload(sub(userOpSig.offset, 32))
        }
    }

    function _checkEnableSig(
        IValidator validator,
        bytes4 group,
        IHook hook,
        bytes calldata validatorData,
        bytes calldata hookData,
        bytes calldata enableSig
    ) internal {
        // struct Enable {
        //     address validator,
        //     bytes4  group,
        //     address hook,
        //     bytes validatorData,
        //     bytes hookData
        // }
        bytes32 hash;
        _checkSignature(rootValidator, address(this), hash, enableSig);
    }

    function _checkSignature(IValidator validator, address caller, bytes32 hash, bytes calldata sig) internal {
        bytes4 result = validator.isValidSignatureWithSender(caller, hash, sig);
        if(result != 0x1626ba7e) {
            revert InvalidSignature();
        }
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
            (
                bytes4 group,
                IHook hook,
                bytes calldata validatorData,
                bytes calldata hookData,
                bytes calldata enableSig,
                bytes calldata userOpSig
            ) = _parseEnableSig(op.signature);
            _checkEnableSig(validator, group, hook, validatorData, hookData, enableSig);
            _installValidator(validator, group, hook, validatorData, hookData);
        } else {
            revert InvalidMode();
        }

        IHook execHook = validatorConfig[validator].hook;
        if (address(execHook) == address(0)) {
            revert InvalidValidator();
        }
        executionHook[userOpHash] = execHook;

        if (address(execHook) == address(1)) {
            // does not require hook
            if (selectorConfig[bytes4(op.callData[0:4])].group != validatorConfig[validator].group) {
                revert InvalidValidator();
            }
        } else {
            // requires hook
            if (selectorConfig[bytes4(op.callData[4:8])].group != validatorConfig[validator].group) {
                revert InvalidValidator();
            }
            if (bytes4(op.callData[0:4]) != this.executeUserOp.selector) {
                revert OnlyExecuteUserOp();
            }
        }
        validationData = ValidationData.wrap(validator.validateUserOp(op, userOpHash));
    }

    // --- Hook ---
    // Hook is activated on these scenarios
    // - on 4337 flow, userOp.calldata starts with executeUserOp.selector && validator requires hook
    // - executeFromExecutor() is invoked and executor requires hook
    // - when fallback function has been invoked and fallback requires hook => native functions will not invoke hook
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

    // --- Execution ---
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external payable override {
        // onlyEntrypoint
        bytes memory context;
        IHook hook = executionHook[userOpHash];
        if (address(hook) != address(1)) {
            // removed 4bytes selector
            context = _doPreHook(hook, userOp.callData[4:]);
        }

        (bool success, bytes memory ret) = address(this).delegatecall(userOp.callData[4:]);

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
        // no modifier needed, checking if msg.sender is registered executor will replace the modifier
        IHook hook = executorConfig[IExecutor(msg.sender)].hook;
        if (address(hook) == address(0)) {
            revert InvalidExecutor();
        }
        bytes memory context;
        if (address(hook) != address(1)) {
            context = _doPreHook(hook, msg.data);
        }
        returnData = ExecLib._execute(execMode, executionCalldata);
        if (address(hook) != address(1)) {
            _doPostHook(hook, context);
        }
    }

    function execute(ExecMode execMode, bytes calldata executionCalldata) external payable {
        // onlyEntrypointOrSelf
        ExecLib._execute(execMode, executionCalldata);
    }
}
