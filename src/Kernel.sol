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

/// @title Kernel
/// @author taek<leekt216@gmail.com>
/// @notice wallet kernel for minimal wallet functionality
/// @dev supports only 1 owner, multiple validators
contract Kernel is IAccount, EIP712, Compatibility, KernelStorage {
    error InvalidNonce();
    error InvalidSignatureLength();
    error QueryResult(bytes result);

    string public constant name = "Kernel";

    string public constant version = "0.0.2";

    constructor(IEntryPoint _entryPoint) EIP712(name, version) KernelStorage(_entryPoint) {}

    fallback() external payable {
        // should we do entrypoint check here?
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
        require(
            msg.sender == address(entryPoint),
            "account: not from entrypoint"
        );
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
        bytes4 sig = bytes4(userOp.callData[0:4]);
        IKernelValidator validator = getKernelStorage().execution[sig].validator;
        if(address(validator) == address(0)) {
            validator = getKernelStorage().defaultValidator;
        }
        // mode based signature
        bytes4 mode = bytes4(userOp.signature[0:4]); // mode == 00..00 use validators

        if(mode == 0x00000000) {
            // use validators
            // validate signature
            UserOperation memory op = userOp;
            op.signature = userOp.signature[4:];
            validator.validateUserOp(op, userOpHash, missingAccountFunds);
        } else if(mode == 0x00000001) {
            // enable validator
            IKernelValidator newValidator = IKernelValidator(address(bytes20(userOp.signature[4:20])));
            uint48 validUntil = uint48(bytes6(userOp.signature[20:26]));
            uint48 validAfter = uint48(bytes6(userOp.signature[26:32]));
            uint256 enableDataLength = uint256(bytes32(userOp.signature[32:64]));
            bytes calldata enableData = userOp.signature[64:64+enableDataLength];
            uint256 enableSignatureLength = uint256(bytes32(userOp.signature[64+enableDataLength:96+enableDataLength]));
            bytes calldata enableSignature = userOp.signature[96+enableDataLength:96+enableDataLength+enableSignatureLength];
            bytes32 enableDigest = _hashTypedDataV4(keccak256(abi.encode(
                keccak256("EnableValidator(bytes4 sig,address newValidator,uint48 validUntil,uint48 validAfter,bytes enableData)"),
                sig,
                newValidator,
                validUntil,
                validAfter,
                keccak256(enableData)
            )));
            validationData = getKernelStorage().defaultValidator.validateSignature(
                enableDigest,
                enableSignature
            );
            ValidationData memory data = _parseValidationData(validationData);
            if(data.aggregator != address(0)) {
                return SIG_VALIDATION_FAILED;
            }
            validator.enable(enableData);
            // // validate signature
            UserOperation memory op = userOp;
            op.signature = userOp.signature[68+enableDataLength+enableSignatureLength:];
            validationData = validator.validateUserOp(op, userOpHash, missingAccountFunds);
        } else if(mode == 0x00000002) {
            // sudo mode (use default validator)
            UserOperation memory op = userOp;
            op.signature = userOp.signature[4:];
            validationData = getKernelStorage().defaultValidator.validateUserOp(op, userOpHash, missingAccountFunds);
        } else {
            return SIG_VALIDATION_FAILED;
        }
        if (missingAccountFunds > 0) {
            // we are going to assume signature is valid at this point
            (bool success,) = msg.sender.call{value: missingAccountFunds}("");
            (success);
            return validationData;
        }
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        uint256 validationData = getKernelStorage().defaultValidator.validateSignature(hash, signature);
        ValidationData memory data = _parseValidationData(validationData);
        if(data.validAfter > block.timestamp) {
            return 0xffffffff;
        }
        if(data.validUntil < block.timestamp) {
            return 0xffffffff;
        }
        if(data.aggregator != address(0)) {
            return 0xffffffff;
        }

        return 0x1626ba7e;
    }
}
