// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Importing external libraries and contracts
import "solady/utils/EIP712.sol";
import "solady/utils/ECDSA.sol";
import "account-abstraction/core/Helpers.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import "./abstract/Compatibility.sol";
import "./abstract/KernelStorage.sol";
import "./utils/KernelHelper.sol";

enum Operation {
    Call,
    DelegateCall
}

bytes32 constant VALIDATOR_APPROVED_STRUCT_HASH = 0x3ce406685c1b3551d706d85a68afdaa49ac4e07b451ad9b8ff8b58c3ee964176;

/// @title Kernel
/// @author taek<leekt216@gmail.com>
/// @notice wallet kernel for extensible wallet functionality
contract Kernel is EIP712, Compatibility, KernelStorage {
    string public constant name = "Kernel";

    string public constant version = "0.2.1";

    error NotEntryPoint();
    error DisabledMode();

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
    /// @dev The type of operation (call or delegatecall) is specified as an argument.
    /// @param to The address of the target contract
    /// @param value The amount of Ether to send
    /// @param data The call data to be sent
    /// @param operation The type of operation (call or delegatecall)
    function execute(address to, uint256 value, bytes calldata data, Operation operation) external payable {
        if (msg.sender != address(entryPoint) && !_checkCaller()) {
            revert NotAuthorizedCaller();
        }
        bytes memory callData = data;
        if (operation == Operation.DelegateCall) {
            assembly {
                let success := delegatecall(gas(), to, add(callData, 0x20), mload(callData), 0, 0)
                returndatacopy(0, 0, returndatasize())
                switch success
                case 0 { revert(0, returndatasize()) }
                default { return(0, returndatasize()) }
            }
        } else {
            assembly {
                let success := call(gas(), to, value, add(callData, 0x20), mload(callData), 0, 0)
                returndatacopy(0, 0, returndatasize())
                switch success
                case 0 { revert(0, returndatasize()) }
                default { return(0, returndatasize()) }
            }
        }
    }

    /// @notice Validates a user operation based on its mode
    /// @dev This function will validate user operation and be called by EntryPoint
    /// @param userOp The user operation to be validated
    /// @param userOpHash The hash of the user operation
    /// @param missingAccountFunds The funds needed to be reimbursed
    /// @return validationData The data used for validation
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        payable
        returns (uint256 validationData)
    {
        if (msg.sender != address(entryPoint)) {
            revert NotEntryPoint();
        }
        WalletKernelStorage storage kernelStorage = getKernelStorage();
        // mode based signature
        bytes4 mode = bytes4(userOp.signature[0:4]); // mode == 00..00 use validators
        if (mode & kernelStorage.disabledMode != 0x00000000) {
            revert DisabledMode();
        }
        // mode == 0x00000000 use sudo validator
        // mode == 0x00000001 use given validator
        // mode == 0x00000002 enable validator
        UserOperation memory op = userOp;
        IKernelValidator validator;
        if (mode == 0x00000000) {
            // sudo mode (use default validator)
            op.signature = userOp.signature[4:];
            validator = kernelStorage.defaultValidator;
        } else if (mode == 0x00000001) {
            bytes4 sig = bytes4(userOp.callData[0:4]);
            ExecutionDetail storage detail = kernelStorage.execution[sig];
            validator = detail.validator;
            if (address(validator) == address(0)) {
                validator = kernelStorage.defaultValidator;
            }
            op.signature = userOp.signature[4:];
            validationData = (uint256(detail.validAfter) << 160) | (uint256(detail.validUntil) << (208));
        } else if (mode == 0x00000002) {
            bytes4 sig = bytes4(userOp.callData[0:4]);
            // use given validator
            // userOp.signature[4:10] = validUntil,
            // userOp.signature[10:16] = validAfter,
            // userOp.signature[16:36] = validator address,
            validator = IKernelValidator(address(bytes20(userOp.signature[16:36])));
            bytes calldata enableData;
            bytes calldata remainSig;
            (validationData, enableData, remainSig) = _approveValidator(sig, userOp.signature);
            validator.enable(enableData);
            op.signature = remainSig;
        } else {
            return SIG_VALIDATION_FAILED;
        }
        if (missingAccountFunds != 0) {
            assembly {
                pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0))
            }
            //ignore failure (its EntryPoint's job to verify, not account.)
        }
        validationData =
            _intersectValidationData(validationData, validator.validateUserOp(op, userOpHash, missingAccountFunds));
        return validationData;
    }

    function _approveValidator(bytes4 sig, bytes calldata signature)
        internal
        returns (uint256 validationData, bytes calldata enableData, bytes calldata validationSig)
    {
        unchecked {
            uint256 enableDataLength = uint256(bytes32(signature[56:88]));
            enableData = signature[88:88 + enableDataLength];
            uint256 enableSignatureLength = uint256(bytes32(signature[88 + enableDataLength:120 + enableDataLength]));
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
                getKernelStorage().defaultValidator.validateSignature(
                    enableDigest, signature[120 + enableDataLength:120 + enableDataLength + enableSignatureLength]
                ),
                uint256(bytes32(signature[4:36])) & (uint256(type(uint96).max) << 160)
            );
            validationSig = signature[120 + enableDataLength + enableSignatureLength:];
            getKernelStorage().execution[sig] = ExecutionDetail({
                executor: address(bytes20(signature[36:56])),
                validator: IKernelValidator(address(bytes20(signature[16:36]))),
                validUntil: uint48(bytes6(signature[4:10])),
                validAfter: uint48(bytes6(signature[10:16]))
            });
            return (validationData, signature[88:88 + enableDataLength], validationSig);
        }
    }

    /// @notice Checks if a signature is valid
    /// @dev This function checks if a signature is valid based on the hash of the data signed.
    /// @param hash The hash of the data that was signed
    /// @param signature The signature to be validated
    /// @return The magic value 0x1626ba7e if the signature is valid, otherwise returns 0xffffffff.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        uint256 validationData = getKernelStorage().defaultValidator.validateSignature(hash, signature);
        ValidationData memory data = _parseValidationData(validationData);
        if (data.validAfter > block.timestamp) {
            return 0xffffffff;
        }
        if (data.validUntil < block.timestamp) {
            return 0xffffffff;
        }
        if (data.aggregator != address(0)) {
            return 0xffffffff;
        }

        return 0x1626ba7e;
    }

    function _checkCaller() internal view returns (bool) {
        if (getKernelStorage().defaultValidator.validCaller(msg.sender, msg.data)) {
            return true;
        }
        bytes4 sig = msg.sig;
        ExecutionDetail storage detail = getKernelStorage().execution[sig];
        if (
            address(detail.validator) == address(0) || (detail.validUntil != 0 && detail.validUntil < block.timestamp)
                || detail.validAfter > block.timestamp
        ) {
            return false;
        } else {
            return detail.validator.validCaller(msg.sender, msg.data);
        }
    }
}
