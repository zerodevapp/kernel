// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "account-abstraction/core/Helpers.sol";
import "account-abstraction/interfaces/IAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import "./utils/Exec.sol";
import "./abstract/Compatibility.sol";
import "./abstract/KernelStorage.sol";
import "./utils/KernelHelper.sol";

/// @title Kernel
/// @author taek<leekt216@gmail.com>
/// @notice wallet kernel for minimal wallet functionality
contract Kernel is IAccount, EIP712, Compatibility, KernelStorage {
    error InvalidNonce();
    error InvalidSignatureLength();
    error QueryResult(bytes result);

    string public constant name = "Kernel";

    string public constant version = "0.0.2";

    constructor(IEntryPoint _entryPoint) EIP712(name, version) KernelStorage(_entryPoint) {}

    fallback() external payable {
        require(msg.sender == address(entryPoint), "account: not from entrypoint");
        bytes4 sig = msg.sig;
        address facet = getKernelStorage().execution[sig].executor;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /// @notice execute function call to external contract
    /// @dev this function will execute function call to external contract
    /// @param to target contract address
    /// @param value value to be sent
    /// @param data data to be sent
    /// @param operation operation type (call or delegatecall)
    function execute(address to, uint256 value, bytes calldata data, Operation operation) external {
        require(msg.sender == address(entryPoint), "account: not from entrypoint");
        bool success;
        bytes memory ret;
        if (operation == Operation.DelegateCall) {
            (success, ret) = Exec.delegateCall(to, data);
        } else {
            (success, ret) = Exec.call(to, value, data);
        }
        if (!success) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    /// @notice validate user operation
    /// @dev this function will validate user operation and be called by EntryPoint
    /// @param userOp user operation
    /// @param userOpHash user operation hash
    /// @param missingAccountFunds funds needed to be reimbursed
    /// @return validationData validation data
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        require(msg.sender == address(entryPoint), "account: not from entryPoint");
        // mode based signature
        bytes4 mode = bytes4(userOp.signature[0:4]); // mode == 00..00 use validators
        if (mode & getKernelStorage().disabledMode != 0x00000000) {
            // disabled mode
            return SIG_VALIDATION_FAILED;
        }
        // mode == 0x00000000 use sudo validator
        // mode & 0x00000001 == 0x00000001 use given validator
        // mode & 0x00000002 == 0x00000002 enable validator
        if (mode == 0x00000000) {
            // sudo mode (use default validator)
            UserOperation memory op = userOp;
            op.signature = userOp.signature[4:];
            validationData = getKernelStorage().defaultValidator.validateUserOp(op, userOpHash, missingAccountFunds);
        } else {
            UserOperation memory op = userOp;
            bytes4 sig = bytes4(userOp.callData[0:4]);
            if (mode == 0x00000000) {
                IKernelValidator validator = getKernelStorage().execution[sig].validator;
                if (address(validator) == address(0)) {
                    validator = getKernelStorage().defaultValidator;
                }
            } else if (mode & 0x00000001 == 0x00000001) {
                // use given validator
                // userOp.signature[4:10] = validUntil,
                // userOp.signature[10:16] = validAfter,
                // userOp.signature[16:36] = validator address,
                IKernelValidator validator = IKernelValidator(address(bytes20(userOp.signature[16:36])));
                bytes calldata enableData;
                (validationData, enableData, op.signature) = _approveValidator(sig, userOp.signature);
                if (mode & 0x00000002 == 0x00000002) {
                    validator.enable(enableData);
                }
                validationData = _intersectValidationData(
                    validationData, validator.validateUserOp(op, userOpHash, missingAccountFunds)
                );
            } else {
                return SIG_VALIDATION_FAILED;
            }
        }
        if (missingAccountFunds > 0) {
            // we are going to assume signature is valid at this point
            (bool success,) = msg.sender.call{value: missingAccountFunds}("");
            (success);
            return validationData;
        }
    }

    function _approveValidator(bytes4 sig, bytes calldata signature)
        internal
        view
        returns (uint256 validationData, bytes calldata enableData, bytes calldata validationSig)
    {
        uint256 enableDataLength = uint256(bytes32(signature[36:68]));
        enableData = signature[68:68 + enableDataLength];
        uint256 enableSignatureLength = uint256(bytes32(signature[68 + enableDataLength:100 + enableDataLength]));
        bytes32 enableDigest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256("ValidatorApproved(bytes4 sig,uint256 validatorData,bytes enableData)"),
                    bytes4(sig),
                    uint256(bytes32(signature[4:36])),
                    keccak256(enableData)
                )
            )
        );
        validationData = _intersectValidationData(
            getKernelStorage().defaultValidator.validateSignature(
                enableDigest, signature[100 + enableDataLength:100 + enableDataLength + enableSignatureLength]
            ),
            uint256(bytes32(signature[4:36])) & (uint256(type(uint96).max) << 160)
        );
        validationSig = signature[76 + enableDataLength + enableSignatureLength:];
        return (validationData, signature[68:68 + enableDataLength], validationSig);
    }

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
}
