pragma solidity ^0.8.0;

import {PackedUserOperation} from "./interfaces/PackedUserOperation.sol";
import {IAccount, ValidationData} from "./interfaces/IAccount.sol";
import {IEntryPoint} from "./interfaces/IEntryPoint.sol";
import {IAccountExecute} from "./interfaces/IAccountExecute.sol";
import {IERC7579Account} from "./interfaces/IERC7579Account.sol";
import {
    ValidationManager,
    ValidationMode,
    ValidationId,
    ValidatorLib,
    ValidationType,
    VALIDATION_TYPE_SUDO,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION
} from "./core/PermissionManager.sol";
import {HookManager} from "./core/HookManager.sol";
import {ExecutorManager} from "./core/ExecutorManager.sol";
import {SelectorManager} from "./core/SelectorManager.sol";
import {IValidator, IHook, IExecutor, IFallback} from "./interfaces/IERC7579Modules.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {ExecLib, ExecMode, CallType, CALLTYPE_SINGLE, CALLTYPE_DELEGATECALL} from "./utils/ExecLib.sol";

bytes32 constant ERC1967_IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

contract Kernel is IAccount, IAccountExecute, IERC7579Account, ValidationManager, HookManager, ExecutorManager {
    error ExecutionReverted();
    error InvalidExecutor();
    error InvalidFallback();
    error InvalidCallType();
    error OnlyExecuteUserOp();
    error InvalidModuleType();
    error InvalidCaller();

    event Received(address sender, uint256 amount);

    IEntryPoint public immutable entrypoint;

    constructor(IEntryPoint _entrypoint) {
        entrypoint = _entrypoint;
        _validatorStorage().rootValidator = ValidationId.wrap(bytes21(abi.encodePacked(hex"deadbeef")));
    }

    modifier onlyEntryPoint() {
        if (msg.sender != address(entrypoint)) {
            revert InvalidCaller();
        }
        _;
    }

    modifier onlyEntryPointOrSelf() {
        if (msg.sender != address(entrypoint) && msg.sender != address(this)) {
            revert InvalidCaller();
        }
        _;
    }

    modifier onlyEntryPointOrSelfOrRoot() {
        IValidator validator = ValidatorLib.getValidator(_validatorStorage().rootValidator);
        if (
            msg.sender != address(entrypoint) && msg.sender != address(this) // do rootValidator hook
        ) {
            if (validator.isModuleType(4)) {
                bytes memory ret = IHook(address(validator)).preCheck(msg.sender, msg.data);
                _;
                IHook(address(validator)).postCheck(ret);
            } else {
                revert InvalidCaller();
            }
        } else {
            _;
        }
    }

    function initialize(ValidationId _rootValidator, IHook hook, bytes calldata validatorData, bytes calldata hookData)
        external
    {
        ValidationStorage storage vs = _validatorStorage();
        require(ValidationId.unwrap(vs.rootValidator) == bytes21(0), "already initialized");
        require(ValidationId.unwrap(_rootValidator) != bytes21(0), "invalid validator");
        vs.rootValidator = _rootValidator;
        ValidationConfig memory config = ValidationConfig({
            group: bytes4(0),
            validFrom: uint48(0),
            validUntil: uint48(0),
            nonce: uint32(1),
            hook: hook
        });
        vs.currentNonce = 1;
        _installValidation(_rootValidator, config, validatorData, hookData);
        vs.currentNonce++;
    }

    // NOTE : when eip 1153 has been enabled, this can be transient storage
    mapping(bytes32 userOpHash => IHook) public executionHook;

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Kernel";
        version = "3.0.0-beta";
    }

    function _doFallback2771(IFallback fallbackHandler) internal returns (bool success, bytes memory result) {
        assembly {
            function allocate(length) -> pos {
                pos := mload(0x40)
                mstore(0x40, add(pos, length))
            }

            let calldataPtr := allocate(calldatasize())
            calldatacopy(calldataPtr, 0, calldatasize())

            // The msg.sender address is shifted to the left by 12 bytes to remove the padding
            // Then the address without padding is stored right after the calldata
            let senderPtr := allocate(20)
            mstore(senderPtr, shl(96, caller()))

            // Add 20 bytes for the address appended add the end
            success := call(gas(), fallbackHandler, 0, calldataPtr, add(calldatasize(), 20), 0, 0)

            result := allocate(returndatasize())
            returndatacopy(result, 0, returndatasize())
        }
    }

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    fallback() external payable {
        SelectorConfig memory config = _selectorConfig(msg.sig);
        if (address(config.hook) == address(0)) {
            (IFallback fallbackHandler, IHook hook) = _fallbackConfig();
            if (address(fallbackHandler) == address(0)) {
                revert InvalidFallback();
            }
            if (address(hook) != address(1)) {
                bytes memory context = _doPreHook(hook, msg.data);
                (bool success, bytes memory result) = _doFallback2771(fallbackHandler);
                _doPostHook(hook, context, success, result);
            } else {
                (bool success, bytes memory result) = _doFallback2771(fallbackHandler);
                if (!success) {
                    assembly {
                        revert(add(result, 0x20), mload(result))
                    }
                } else {
                    assembly {
                        return(add(result, 0x20), mload(result))
                    }
                }
            }
        } else {
            // action installed
            bytes memory context;
            if (address(config.hook) != address(1)) {
                context = _doPreHook(config.hook, msg.data);
            }
            // execute action
            (bool success, bytes memory ret) = ExecLib._executeDelegatecall(config.target, msg.data);
            if (address(config.hook) != address(1)) {
                _doPostHook(config.hook, context, success, ret);
            }
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
        ValidationStorage storage vs = _validatorStorage();
        // ONLY ENTRYPOINT
        // Major change for v2 => v3
        // 1. instead of packing 4 bytes prefix to userOp.signature to determine the mode, v3 uses userOp.nonce's first 2 bytes to check the mode
        // 2. instead of packing 20 bytes in userOp.signature for enable mode to provide the validator address, v3 uses userOp.nonce[2:22]
        // 3. In v2, only 1 plugin validator(aside from root validator) can access the selector.
        //    In v3, you can use more than 1 plugin to use the exact selector, you need to specify the validator address in userOp.nonce[2:22] to use the validator

        (ValidationMode vMode, ValidationType vType, ValidationId vId) = ValidatorLib.decodeNonce(userOp.nonce);
        if (vType == VALIDATION_TYPE_SUDO) {
            vId = vs.rootValidator;
        }
        validationData = _doValidation(vMode, vId, userOp, userOpHash);
        IHook execHook = vs.validatorConfig[vId].hook;
        if (address(execHook) == address(0)) {
            revert InvalidValidator();
        }
        executionHook[userOpHash] = execHook;

        if (address(execHook) == address(1)) {
            // does not require hook
            if (
                vType != VALIDATION_TYPE_SUDO
                    && _selectorConfig(bytes4(userOp.callData[0:4])).group != vs.validatorConfig[vId].group
            ) {
                revert InvalidValidator();
            }
        } else {
            // requires hook
            if (
                vType != VALIDATION_TYPE_SUDO
                    && _selectorConfig(bytes4(userOp.callData[4:8])).group != vs.validatorConfig[vId].group
            ) {
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
        (bool success, bytes memory ret) = ExecLib._executeDelegatecall(address(this), userOp.callData[4:]);
        if (address(hook) != address(1)) {
            _doPostHook(hook, context, success, ret);
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
        IHook hook = _executorConfig(IExecutor(msg.sender)).hook;
        if (address(hook) == address(0)) {
            revert InvalidExecutor();
        }
        bytes memory context;
        if (address(hook) != address(1)) {
            context = _doPreHook(hook, msg.data);
        }
        returnData = ExecLib._execute(execMode, executionCalldata);
        if (address(hook) != address(1)) {
            _doPostHook(hook, context, true, abi.encode(returnData));
        }
    }

    function execute(ExecMode execMode, bytes calldata executionCalldata) external payable onlyEntryPointOrSelfOrRoot {
        ExecLib._execute(execMode, executionCalldata);
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4) {
        (ValidationId vId, bytes calldata sig) = ValidatorLib.decodeSignature(signature);
        (IValidator validator, ValidationData valdiationData, bytes calldata validatorSig) =
            _checkSignaturePolicy(vId, msg.sender, hash, sig);
        bytes32 wrappedHash = _toWrappedHash(hash);
        return validator.isValidSignatureWithSender(msg.sender, wrappedHash, validatorSig);
    }

    function installModule(uint256 moduleType, address module, bytes calldata initData)
        external
        payable
        override
        onlyEntryPointOrSelfOrRoot
    {
        if (moduleType == 1) {
            ValidationStorage storage vs = _validatorStorage();
            ValidationId vId = ValidatorLib.validatorToIdentifier(IValidator(module));
            ValidationConfig memory config = ValidationConfig({
                group: bytes4(initData[0:4]),
                nonce: vs.currentNonce++,
                hook: IHook(address(bytes20(initData[4:24]))),
                validFrom: uint48(bytes6(initData[24:30])),
                validUntil: uint48(bytes6(initData[30:36]))
            });
            bytes calldata validatorData;
            bytes calldata hookData;
            assembly {
                validatorData.offset := add(add(initData.offset, 68), calldataload(add(initData.offset, 36)))
                validatorData.length := calldataload(sub(validatorData.offset, 32))
                hookData.offset := add(add(initData.offset, 68), calldataload(add(initData.offset, 68)))
                hookData.length := calldataload(sub(hookData.offset, 32))
            }
            _installValidation(vId, config, validatorData, hookData);
        } else if (moduleType == 2) {
            // executor
            _installExecutor(
                IExecutor(module), bytes4(initData[0:4]), IHook(address(bytes20(initData[4:24]))), initData[24:]
            );
        } else if (moduleType == 3) {
            _installFallback(
                IFallback(module),
                IHook(address(bytes20(initData[0:20]))),
                initData[20:20], // TODO : fallbackData
                initData[20:]
            );
        } else if (moduleType == 6) {
            // action
            _installSelector(
                bytes4(initData[0:4]),
                bytes4(initData[4:8]),
                address(bytes20(initData[8:28])),
                IHook(address(bytes20(initData[28:48]))),
                initData[48:]
            );
        } else {
            revert InvalidModuleType();
        }
    }

    function uninstallModule(uint256 moduleType, address module, bytes calldata deInitData) external payable override {
        // TODO
    }

    function supportsModule(uint256 moduleTypeId) external pure override returns (bool) {
        if (moduleTypeId < 7) {
            return true;
        } else {
            return false;
        }
    }

    function isModuleInstalled(uint256 moduleType, address module, bytes calldata additionalContext)
        external
        view
        override
        returns (bool)
    {
        if (moduleType == 1) {
            return
                _validatorStorage().validatorConfig[ValidatorLib.validatorToIdentifier(IValidator(module))].nonce != 0;
        } else if (moduleType == 2) {
            return address(_executorConfig(IExecutor(module)).hook) != address(0);
        } else if (moduleType == 3) {
            (IFallback fallbackHandler,) = _fallbackConfig();
            return fallbackHandler == IFallback(module);
        } else if (moduleType == 6) {
            return _selectorConfig(bytes4(additionalContext[0:4])).target == module;
        } else {
            return false;
        }
    }

    function accountId() external pure override returns (string memory accountImplementationId) {
        return "kernel.advanced.v3.0.0-beta";
    }

    function supportsExecutionMode(ExecMode) external pure override returns (bool) {
        return true;
    }
}
