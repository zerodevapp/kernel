// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Importing external libraries and contracts
import {EIP712} from "solady/utils/EIP712.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {Compatibility} from "./abstract/Compatibility.sol";
import {KernelStorage} from "./abstract/KernelStorage.sol";
import {_intersectValidationData} from "./utils/KernelHelper.sol";
import {IKernelValidator} from "./interfaces/IKernelValidator.sol";

import {
    KERNEL_NAME,
    KERNEL_VERSION,
    VALIDATOR_APPROVED_STRUCT_HASH,
    KERNEL_STORAGE_SLOT_1,
    SIG_VALIDATION_FAILED
} from "./common/Constants.sol";
import {Operation} from "./common/Enums.sol";
import {WalletKernelStorage, Call, ExecutionDetail} from "./common/Structs.sol";
import {ValidationData, ValidAfter, ValidUntil, parseValidationData, packValidationData} from "./common/Types.sol";

/// @title Kernel
/// @author taek<leekt216@gmail.com>
/// @notice wallet kernel for extensible wallet functionality
contract Kernel is EIP712, Compatibility, KernelStorage {
    string public constant name = KERNEL_NAME;

    string public constant version = KERNEL_VERSION;

    /// @dev Sets up the EIP712 and KernelStorage with the provided entry point
    constructor(IEntryPoint _entryPoint) KernelStorage(_entryPoint) {}

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return (name, version);
    }

    /// @notice Accepts incoming Ether transactions and calls from the EntryPoint contract
    /// @dev This function will delegate any call to the appropriate executor based on the function signature.
    fallback() external payable {
        bytes4 sig = msg.sig;
        address executor = getKernelStorage().execution[sig].executor;
        if (msg.sender != address(entryPoint) && !_checkCaller()) {
            revert NotAuthorizedCaller();
        }
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), executor, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /// @notice Executes a function call to an external contract
    /// @param to The address of the target contract
    /// @param value The amount of Ether to send
    /// @param data The call data to be sent
    /// @dev operation is deprecated param, use executeBatch for batched transaction
    function execute(address to, uint256 value, bytes memory data, Operation _operation) external payable {
        if (msg.sender != address(entryPoint) && msg.sender != address(this) && !_checkCaller()) {
            revert NotAuthorizedCaller();
        }
        if (_operation != Operation.Call) {
            revert DeprecatedOperation();
        }
        assembly {
            let success := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch success
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /// @notice Executes a function call to an external contract batched
    /// @param calls The calls to be executed, in order
    /// @dev operation deprecated param, use executeBatch for batched transaction
    function executeBatch(Call[] memory calls) external payable {
        if (msg.sender != address(entryPoint) && !_checkCaller()) {
            revert NotAuthorizedCaller();
        }
        uint256 len = calls.length;
        for (uint256 i = 0; i < len;) {
            Call memory call = calls[i];
            address to = call.to;
            uint256 value = call.value;
            bytes memory data = call.data;
            assembly {
                let success := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
                returndatacopy(0, 0, returndatasize())
                switch success
                case 0 { revert(0, returndatasize()) }
                default { i := add(i, 1) }
            }
        }
    }

    /// @notice Validates a user operation based on its mode
    /// @dev This function will validate user operation and be called by EntryPoint
    /// @param _userOp The user operation to be validated
    /// @param userOpHash The hash of the user operation
    /// @param missingAccountFunds The funds needed to be reimbursed
    /// @return validationData The data used for validation
    function validateUserOp(UserOperation calldata _userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        payable
        virtual
        returns (ValidationData validationData)
    {
        if (msg.sender != address(entryPoint)) {
            revert NotEntryPoint();
        }
        bytes calldata userOpSignature;
        uint256 userOpEndOffset;
        assembly {
            userOpEndOffset := add(calldataload(0x04), 0x24)
            userOpSignature.offset := add(calldataload(add(userOpEndOffset, 0x120)), userOpEndOffset)
            userOpSignature.length := calldataload(sub(userOpSignature.offset, 0x20))
        }
        // mode based signature
        bytes4 mode = bytes4(userOpSignature[0:4]); // mode == 00..00 use validators
        // mode == 0x00000000 use sudo validator
        if (mode == 0x00000000) {
            // sudo mode (use default validator)
            if (missingAccountFunds != 0) {
                assembly {
                    pop(call(gas(), caller(), missingAccountFunds, callvalue(), callvalue(), callvalue(), callvalue()))
                }
                //ignore failure (its EntryPoint's job to verify, not account.)
            }
            // short circuit here for default validator
            return _validateUserOp(_userOp, userOpHash, missingAccountFunds);
        }

        UserOperation memory userOp = _userOp;

        // mode == 0x00000001 use given validator
        // mode == 0x00000002 enable validator
        IKernelValidator validator;
        bytes32 storage_slot_1;
        assembly {
            storage_slot_1 := sload(KERNEL_STORAGE_SLOT_1)
        }
        if (mode & (storage_slot_1 << 224) != 0x00000000) {
            revert DisabledMode();
        } else if (mode == 0x00000001) {
            bytes calldata userOpCallData;
            assembly {
                userOpCallData.offset := add(calldataload(add(userOpEndOffset, 0x40)), userOpEndOffset)
                userOpCallData.length := calldataload(sub(userOpCallData.offset, 0x20))
            }
            ExecutionDetail storage detail = getKernelStorage().execution[bytes4(userOpCallData[0:4])];
            validator = detail.validator;
            userOpSignature = userOpSignature[4:];
            validationData = packValidationData(detail.validAfter, detail.validUntil);
        } else if (mode == 0x00000002) {
            bytes calldata userOpCallData;
            assembly {
                userOpCallData.offset := add(calldataload(add(userOpEndOffset, 0x40)), userOpEndOffset)
                userOpCallData.length := calldataload(sub(userOpCallData.offset, 0x20))
            }
            // use given validator
            // userOpSignature[4:10] = validAfter,
            // userOpSignature[10:16] = validUntil,
            // userOpSignature[16:36] = validator address,
            (validator, validationData, userOpSignature) =
                _approveValidator(bytes4(userOpCallData[0:4]), userOpSignature);
        } else {
            return SIG_VALIDATION_FAILED;
        }
        if (missingAccountFunds != 0) {
            assembly {
                pop(call(gas(), caller(), missingAccountFunds, callvalue(), callvalue(), callvalue(), callvalue()))
            }
            //ignore failure (its EntryPoint's job to verify, not account.)
        }
        userOp.signature = userOpSignature;
        validationData =
            _intersectValidationData(validationData, validator.validateUserOp(userOp, userOpHash, missingAccountFunds));
        return validationData;
    }

    function _approveValidator(bytes4 sig, bytes calldata signature)
        internal
        returns (IKernelValidator validator, ValidationData validationData, bytes calldata validationSig)
    {
        unchecked {
            validator = IKernelValidator(address(bytes20(signature[16:36])));
            uint256 cursor = 88;
            uint256 length = uint256(bytes32(signature[56:88])); // this is enableDataLength
            bytes calldata enableData;
            assembly {
                enableData.offset := add(signature.offset, cursor)
                enableData.length := length
                cursor := add(cursor, length) // 88 + enableDataLength
            }
            length = uint256(bytes32(signature[cursor:cursor + 32])); // this is enableSigLength
            assembly {
                cursor := add(cursor, 32)
            }
            bytes32 enableDigest = _hashTypedData(
                keccak256(
                    abi.encode(
                        VALIDATOR_APPROVED_STRUCT_HASH,
                        bytes4(sig),
                        uint256(bytes32(signature[4:36])),
                        address(bytes20(signature[36:56])),
                        keccak256(enableData)
                    )
                )
            );
            validationData = _intersectValidationData(
                _validateSignature(enableDigest, signature[cursor:cursor + length]),
                ValidationData.wrap(
                    uint256(bytes32(signature[4:36]))
                        & 0xffffffffffffffffffffffff0000000000000000000000000000000000000000
                )
            );
            assembly {
                cursor := add(cursor, length)
                validationSig.offset := add(signature.offset, cursor)
                validationSig.length := sub(signature.length, cursor)
            }
            getKernelStorage().execution[sig] = ExecutionDetail({
                validAfter: ValidAfter.wrap(uint48(bytes6(signature[4:10]))),
                validUntil: ValidUntil.wrap(uint48(bytes6(signature[10:16]))),
                executor: address(bytes20(signature[36:56])),
                validator: IKernelValidator(address(bytes20(signature[16:36])))
            });
            validator.enable(enableData);
        }
    }

    function validateSignature(bytes32 hash, bytes calldata signature) public view returns(ValidationData) {
        return _validateSignature(hash, signature);
    }

    /// @notice Checks if a signature is valid
    /// @dev This function checks if a signature is valid based on the hash of the data signed.
    /// @param hash The hash of the data that was signed
    /// @param signature The signature to be validated
    /// @return The magic value 0x1626ba7e if the signature is valid, otherwise returns 0xffffffff.
    function isValidSignature(bytes32 hash, bytes calldata signature) public view returns (bytes4) {
        ValidationData validationData = validateSignature(hash, signature);
        (ValidAfter validAfter, ValidUntil validUntil, address result) = parseValidationData(validationData);
        if (ValidAfter.unwrap(validAfter) > block.timestamp) {
            return 0xffffffff;
        }
        if (ValidUntil.unwrap(validUntil) < block.timestamp) {
            return 0xffffffff;
        }
        if (result != address(0)) {
            return 0xffffffff;
        }

        return 0x1626ba7e;
    }

    function _checkCaller() internal view returns (bool) {
        if (_validCaller(msg.sender, msg.data)) {
            return true;
        }
        bytes4 sig = msg.sig;
        ExecutionDetail storage detail = getKernelStorage().execution[sig];
        if (
            address(detail.validator) == address(0)
                || (ValidUntil.unwrap(detail.validUntil) != 0 && ValidUntil.unwrap(detail.validUntil) < block.timestamp)
                || ValidAfter.unwrap(detail.validAfter) > block.timestamp
        ) {
            return false;
        } else {
            return detail.validator.validCaller(msg.sender, msg.data);
        }
    }

    function _validateUserOp(UserOperation calldata _op, bytes32 _opHash, uint256 _missingFunds)
        internal
        virtual
        returns (ValidationData)
    {
        address validator;
        UserOperation memory op = _op;
        op.signature = _op.signature[4:]; // since this is only called on default validator
        assembly {
            validator := shr(80, sload(KERNEL_STORAGE_SLOT_1))
        }
        return IKernelValidator(validator).validateUserOp(op, _opHash, _missingFunds);
    }

    function _validateSignature(bytes32 _hash, bytes calldata _signature)
        internal
        view
        virtual
        returns (ValidationData)
    {
        address validator;
        assembly {
            validator := shr(80, sload(KERNEL_STORAGE_SLOT_1))
        }
        return IKernelValidator(validator).validateSignature(_hash, _signature);
    }

    function _validCaller(address _caller, bytes calldata _data) internal view virtual returns (bool) {
        address validator;
        assembly {
            validator := shr(80, sload(KERNEL_STORAGE_SLOT_1))
        }
        return IKernelValidator(validator).validCaller(_caller, _data);
    }
}
