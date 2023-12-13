// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {IKernelValidator} from "../interfaces/IKernelValidator.sol";
import {ValidationData} from "../common/Types.sol";
import {SIG_VALIDATION_FAILED} from "../common/Constants.sol";

struct ECDSATypedValidatorStorage {
    address owner;
}

/// @author @KONFeature
/// @title ECDSATypedValidator
/// @notice This validator uses the ECDSA curve to validate signatures.
/// @notice It's using EIP-712 format signature to validate user operations signature & classic signature
contract ECDSATypedValidator is IKernelValidator, EIP712 {
    /// @notice The type hash used for kernel user op validation
    bytes32 constant USER_OP_TYPEHASH = keccak256("AllowUserOp(address owner,address kernelWallet,bytes32 userOpHash)");
    /// @notice The type hash used for kernel signature validation
    bytes32 constant SIGNATURE_TYPEHASH = keccak256("KernelSignature(address owner,address kernelWallet,bytes32 hash)");

    /// @notice Emitted when the owner of a kernel is changed.
    event OwnerChanged(address indexed kernel, address newOwner);

    /* -------------------------------------------------------------------------- */
    /*                                   Storage                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice The validator storage of a kernel.
    mapping(address kernel => ECDSATypedValidatorStorage validatorStorage) private ecdsaValidatorStorage;

    /* -------------------------------------------------------------------------- */
    /*                               EIP-712 Methods                              */
    /* -------------------------------------------------------------------------- */

    /// @dev Get the current name & version of the validator, used for the EIP-712 domain separator from Solady
    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("Kernel:ECDSATypedValidator", "1.0.0");
    }

    /// @dev Tell to solady that the current name & version of the validator won't change, so no need to recompute the eip-712 domain separator
    function _domainNameAndVersionMayChange() internal pure override returns (bool) {
        return false;
    }

    /// @dev Export the current domain seperator
    function getDomainSeperator() public view returns (bytes32) {
        return _domainSeparator();
    }

    /* -------------------------------------------------------------------------- */
    /*                          Kernel validator Methods                          */
    /* -------------------------------------------------------------------------- */

    /// @dev Enable this validator for a given `kernel` (msg.sender)
    function enable(bytes calldata _data) external payable override {
        address owner = address(bytes20(_data[0:20]));
        ecdsaValidatorStorage[msg.sender].owner = owner;
        emit OwnerChanged(msg.sender, owner);
    }

    /// @dev Disable this validator for a given `kernel` (msg.sender)
    function disable(bytes calldata) external payable override {
        delete ecdsaValidatorStorage[msg.sender];
    }

    /// @dev Validate a `_userOp` using a EIP-712 signature, signed by the owner of the kernel account who is the `_userOp` sender
    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        override
        returns (ValidationData validationData)
    {
        // Get the owner for the given kernel account
        address owner = ecdsaValidatorStorage[_userOp.sender].owner;

        // Build the full message hash to check against
        bytes32 typedDataHash =
            _hashTypedData(keccak256(abi.encode(USER_OP_TYPEHASH, owner, _userOp.sender, _userOpHash)));

        // Validate the typed data hash signature
        if (owner == ECDSA.recover(typedDataHash, _userOp.signature)) {
            // If that worked, return a valid validation data
            return ValidationData.wrap(0);
        }

        // If not, return a failed validation data
        return SIG_VALIDATION_FAILED;
    }

    /// @dev Validate a `_signature` of the `_hash` ofor the given `kernel` (msg.sender)
    function validateSignature(bytes32 _hash, bytes calldata signature) public view override returns (ValidationData) {
        // Get the owner for the given kernel account
        address owner = ecdsaValidatorStorage[msg.sender].owner;

        // Build the full message hash to check against
        bytes32 typedDataHash = _hashTypedData(keccak256(abi.encode(SIGNATURE_TYPEHASH, owner, msg.sender, _hash)));

        // Validate the typed data hash signature
        if (owner == ECDSA.recover(typedDataHash, signature)) {
            // If that worked, return a valid validation data
            return ValidationData.wrap(0);
        }

        // If not, return a failed validation data
        return SIG_VALIDATION_FAILED;
    }

    /// @dev Check if the caller is a valid signer for this kernel account
    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        return ecdsaValidatorStorage[msg.sender].owner == _caller;
    }

    /* -------------------------------------------------------------------------- */
    /*                             Public view methods                            */
    /* -------------------------------------------------------------------------- */

    /// @dev Get the owner of a given `kernel`
    function getOwner(address _kernel) public view returns (address) {
        return ecdsaValidatorStorage[_kernel].owner;
    }
}
