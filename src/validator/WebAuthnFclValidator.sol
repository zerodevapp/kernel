// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {IKernelValidator} from "../interfaces/IKernelValidator.sol";
import {ValidationData} from "../common/Types.sol";
import {SIG_VALIDATION_FAILED} from "../common/Constants.sol";
import {WebAuthnFclVerifier} from "../utils/WebAuthnFclVerifier.sol";

/// @dev Storage layout for a kernel in the WebAuthnValidator contract.
struct WebAuthnFclValidatorStorage {
    /// @dev The `x` coord of the secp256r1 public key used to sign the user operation.
    uint256 x;
    /// @dev The `y` coord of the secp256r1 public key used to sign the user operation.
    uint256 y;
}

/// @author @KONFeature
/// @title WebAuthnFclValidator
/// @notice Kernel validator used to validated user operations via WebAuthn signature (using P256 under the hood)
/// @notice Using the awesome FreshCryptoLib: https://github.com/rdubois-crypto/FreshCryptoLib/
/// @notice Inspired by the cometh Gnosis Safe signer: https://github.com/cometh-game/p256-signer
contract WebAuthnFclValidator is IKernelValidator {
    /// @dev Event emitted when the public key signing the WebAuthN user operation is changed for a given `kernel`.
    event WebAuthnPublicKeyChanged(address indexed kernel, uint256 x, uint256 y);

    /// @dev Mapping of kernel address to each webAuthn specific storage
    mapping(address kernel => WebAuthnFclValidatorStorage webAuthnStorage) private webAuthnValidatorStorage;

    /// @dev The address of the p256 verifier contract (should be 0x100 on the RIP-7212 compliant chains)
    /// @dev To follow up for the deployment: https://forum.polygon.technology/t/pip-27-precompiled-for-secp256r1-curve-support/13049
    address public immutable P256_VERIFIER;

    /// @dev Simple constructor, setting the P256 verifier address
    constructor(address _p256Verifier) {
        P256_VERIFIER = _p256Verifier;
    }

    /// @dev Disable this validator for a given `kernel` (msg.sender)
    function disable(bytes calldata) external payable override {
        delete webAuthnValidatorStorage[msg.sender];
    }

    /// @dev Enable this validator for a given `kernel` (msg.sender)
    function enable(bytes calldata _data) external payable override {
        // Extract the x & y coordinates of the public key from the `_data` bytes
        (uint256 x, uint256 y) = abi.decode(_data, (uint256, uint256));
        // Update the pub key data
        WebAuthnFclValidatorStorage storage kernelValidatorStorage = webAuthnValidatorStorage[msg.sender];
        kernelValidatorStorage.x = x;
        kernelValidatorStorage.y = y;
        // Emit the update event
        emit WebAuthnPublicKeyChanged(msg.sender, x, y);
    }

    /// @dev Validate a `_userOp` using a WebAuthn Signature for the kernel account who is the `_userOp` sender
    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        override
        returns (ValidationData validationData)
    {
        WebAuthnFclValidatorStorage memory kernelValidatorStorage = webAuthnValidatorStorage[_userOp.sender];

        // Perform a check against the direct userOpHash, if ok consider the user op as validated
        if (_checkSignature(kernelValidatorStorage, _userOpHash, _userOp.signature)) {
            return ValidationData.wrap(0);
        }

        return SIG_VALIDATION_FAILED;
    }

    /// @dev Validate a `_signature` of the `_hash` ofor the given `kernel` (msg.sender)
    function validateSignature(bytes32 _hash, bytes calldata _signature)
        public
        view
        override
        returns (ValidationData)
    {
        WebAuthnFclValidatorStorage memory kernelValidatorStorage = webAuthnValidatorStorage[msg.sender];

        // Check the validity againt the hash directly
        if (_checkSignature(kernelValidatorStorage, _hash, _signature)) {
            return ValidationData.wrap(0);
        }

        // Otherwise, all good
        return SIG_VALIDATION_FAILED;
    }

    /// @notice Validates the given `_signature` againt the `_hash` for the given `kernel` (msg.sender)
    /// @param _kernelValidatorStorage The kernel storage replication (helping us to fetch the X & Y points of the public key)
    /// @param _hash The hash signed
    /// @param _signature The signature
    function _checkSignature(
        WebAuthnFclValidatorStorage memory _kernelValidatorStorage,
        bytes32 _hash,
        bytes calldata _signature
    ) private view returns (bool isValid) {
        return WebAuthnFclVerifier._verifyWebAuthNSignature(
            P256_VERIFIER, _hash, _signature, _kernelValidatorStorage.x, _kernelValidatorStorage.y
        );
    }

    /// @dev Check if the caller is a valid signer, this don't apply to the WebAuthN validator, since it's using a public key
    function validCaller(address, bytes calldata) external pure override returns (bool) {
        revert NotImplemented();
    }

    /* -------------------------------------------------------------------------- */
    /*                             Public view methods                            */
    /* -------------------------------------------------------------------------- */

    /// @dev Get the owner of a given `kernel`
    function getPublicKey(address _kernel) public view returns (uint256 x, uint256 y) {
        // Compute the storage slot
        WebAuthnFclValidatorStorage storage kernelValidatorStorage = webAuthnValidatorStorage[_kernel];

        // Access it for x and y
        x = kernelValidatorStorage.x;
        y = kernelValidatorStorage.y;
    }
}
