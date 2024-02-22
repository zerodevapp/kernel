pragma solidity ^0.8.0;

import {PackedUserOperation} from "./interfaces/PackedUserOperation.sol";
import {IAccount, ValidationData} from "./interfaces/IAccount.sol";
import {IEntryPoint} from "./interfaces/IEntryPoint.sol";
import {IAccountExecute} from "./interfaces/IAccountExecute.sol";
import {
    ValidationManager,
    ValidatorMode,
    ValidatorIdentifier,
    ValidatorLib,
    ValidatorType,
    TYPE_SUDO
} from "./core/PermissionManager.sol";
import {HookManager} from "./core/HookManager.sol";
import {ExecutorManager} from "./core/ExecutorManager.sol";
import {SelectorManager} from "./core/SelectorManager.sol";
import {IValidator, IHook, IExecutor} from "./interfaces/IERC7579Modules.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {ExecLib, ExecMode, CallType, CALLTYPE_SINGLE, CALLTYPE_DELEGATECALL} from "./utils/ExecLib.sol";

contract Kernel is IAccount, IAccountExecute, ValidationManager, HookManager, ExecutorManager, SelectorManager {
    IEntryPoint public immutable entrypoint;

    constructor(IEntryPoint _entrypoint) {
        entrypoint = _entrypoint;
        rootValidator = ValidatorIdentifier.wrap(bytes21(abi.encodePacked(hex"deadbeef")));
    }

    modifier onlyEntryPoint() {
        require(msg.sender == address(entrypoint), "only entrypoint");
        _;
    }

    modifier onlyEntryPointOrSelf() {
        require(msg.sender == address(entrypoint) || msg.sender == address(this), "only entrypoint or self");
        _;
    }

    function initialize(
        ValidatorIdentifier _rootValidator,
        IHook hook,
        bytes calldata validatorData,
        bytes calldata hookData
    ) external {
        require(ValidatorIdentifier.unwrap(rootValidator) == bytes21(0), "already initialized");
        rootValidator = _rootValidator;
        ValidatorConfig memory config = ValidatorConfig({
            group: bytes4(0),
            validFrom: uint48(0),
            validUntil: uint48(0),
            nonce: uint32(0),
            hook: hook
        });
        _installValidator(_rootValidator, config, validatorData, hookData);
    }

    error ExecutionReverted();
    error InvalidExecutor();
    error InvalidFallback();
    error InvalidCallType();
    error OnlyExecuteUserOp();

    // NOTE : when eip 1153 has been enabled, this can be transient storage
    mapping(bytes32 userOpHash => IHook) public executionHook;

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Kernel";
        version = "3.0.0-beta";
    }

    receive() external payable {}

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
        onlyEntryPoint
        returns (ValidationData validationData)
    {
        // ONLY ENTRYPOINT
        // Major change for v2 => v3
        // 1. instead of packing 4 bytes prefix to userOp.signature to determine the mode, v3 uses userOp.nonce's first 2 bytes to check the mode
        // 2. instead of packing 20 bytes in userOp.signature for enable mode to provide the validator address, v3 uses userOp.nonce[2:22]
        // 3. In v2, only 1 plugin validator(aside from root validator) can access the selector.
        //    In v3, you can use more than 1 plugin to use the exact selector, you need to specify the validator address in userOp.nonce[2:22] to use the validator

        (ValidatorMode vMode, ValidatorType vType, ValidatorIdentifier vId) = ValidatorLib.decode(userOp.nonce);
        if (vType == TYPE_SUDO) {
            vId = rootValidator;
        }
        validationData = _doValidation(vMode, vId, userOp, userOpHash);
        IHook execHook = validatorConfig[vId].hook;
        if (address(execHook) == address(0)) {
            revert InvalidValidator();
        }
        executionHook[userOpHash] = execHook;

        if (address(execHook) == address(1)) {
            // does not require hook
            if (vType != TYPE_SUDO && selectorConfig[bytes4(userOp.callData[0:4])].group != validatorConfig[vId].group)
            {
                revert InvalidValidator();
            }
        } else {
            // requires hook
            if (vType != TYPE_SUDO && selectorConfig[bytes4(userOp.callData[4:8])].group != validatorConfig[vId].group)
            {
                revert InvalidValidator();
            }
            if (bytes4(userOp.callData[0:4]) != this.executeUserOp.selector) {
                revert OnlyExecuteUserOp();
            }
        }

        assembly {
            if missingAccountFunds {
                pop(call(gas(), caller(), missingAccountFunds, callvalue(), callvalue(), callvalue(), callvalue()))
                //ignore failure (its EntryPoint's job to verify, not account.)
            }
        }
    }

    // --- Execution ---
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        onlyEntryPoint
    {
        bytes memory context;
        IHook hook = executionHook[userOpHash];
        if (address(hook) != address(1)) {
            // removed 4bytes selector
            context = _doPreHook(hook, userOp.callData[4:]);
        }

        (bool success,) = address(this).delegatecall(userOp.callData[4:]);

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

    function execute(ExecMode execMode, bytes calldata executionCalldata) external payable onlyEntryPointOrSelf {
        ExecLib._execute(execMode, executionCalldata);
    }
}
