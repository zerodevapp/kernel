// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {IKernelValidator} from "../interfaces/IKernelValidator.sol";
import {ValidationData} from "../common/Types.sol";
import {SIG_VALIDATION_FAILED} from "../common/Constants.sol";
import {P256} from "p256-verifier/P256.sol";

/// @title P256Validator
/// @notice This validator uses the P256 curve to validate signatures.
contract P256Validator is IKernelValidator {
    /// @notice Emitted when a bad key is provided.
    error BadKey();

    /// @notice Emitted when the public key of a kernel is changed.
    event P256PublicKeysChanged(address indexed kernel, PublicKey newKeys);

    /// @notice The P256 public key of a kernel.
    struct PublicKey {
        uint256 x;
        uint256 y;
    }

    /// @notice The P256 public keys of a kernel.
    mapping(address kernel => PublicKey PublicKey) public p256PublicKey;

    /// @notice Enable this validator for a kernel account.
    /// @dev The kernel account need to be the `msg.sender`.
    /// @dev The public key is encoded as `abi.encode(PublicKey)` inside the data, so (uint256,uint256).
    function enable(bytes calldata _data) external payable override {
        PublicKey memory key = abi.decode(_data, (PublicKey));
        if (key.x == 0 || key.y == 0) {
            revert BadKey();
        }
        // Update the key (so a sstore)
        p256PublicKey[msg.sender] = key;
        // And emit the event
        emit P256PublicKeysChanged(msg.sender, key);
    }

    /// @notice Disable this validator for a kernel account.
    /// @dev The kernel account need to be the `msg.sender`.
    function disable(bytes calldata) external payable override {
        delete p256PublicKey[msg.sender];
    }

    /// @notice Validate a user operation.
    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        override
        returns (ValidationData validationData)
    {
        (uint256 r, uint256 s) = abi.decode(_userOp.signature, (uint256, uint256));
        PublicKey memory key = p256PublicKey[_userOp.sender];
        bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
        if (P256.verifySignature(hash, r, s, key.x, key.y)) {
            return ValidationData.wrap(0);
        }
        if (!P256.verifySignature(_userOpHash, r, s, key.x, key.y)) {
            return SIG_VALIDATION_FAILED;
        }
    }

    /// @notice Validate a signature.
    function validateSignature(bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (ValidationData)
    {
        (uint256 r, uint256 s) = abi.decode(signature, (uint256, uint256));
        PublicKey memory key = p256PublicKey[msg.sender];
        if (P256.verifySignature(hash, r, s, key.x, key.y)) {
            return ValidationData.wrap(0);
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        if (!P256.verifySignature(ethHash, r, s, key.x, key.y)) {
            return SIG_VALIDATION_FAILED;
        }
        return ValidationData.wrap(0);
    }

    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        revert NotImplemented();
    }
}
