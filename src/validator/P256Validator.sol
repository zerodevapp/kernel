// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {IKernelValidator} from "../interfaces/IKernelValidator.sol";
import {ValidationData} from "../common/Types.sol";
import {SIG_VALIDATION_FAILED} from "../common/Constants.sol";
import {P256} from "p256-verifier/P256.sol";

contract P256Validator is IKernelValidator {
    uint256 constant n =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    event P256PublicKeysChanged(address indexed kernel, PublicKey indexed oldKeys, PublicKey indexed newKeys);

    struct PublicKey {
        uint256 x;
        uint256 y;
    }

    error BadKey();

    mapping(address => PublicKey) public p256PublicKey;

    function enable(bytes calldata _data) external payable override {
        PublicKey memory key = abi.decode(_data, (PublicKey));
        //throw custom error if key[0] or key[1] is 0, or if key[0] or key[1] is greater than n
        if (key.x == 0 || key.y == 0 || key.x > n || key.y > n) {
            revert BadKey();
        }
        PublicKey memory oldKey = p256PublicKey[msg.sender];
        p256PublicKey[msg.sender] = key;
        emit P256PublicKeysChanged(msg.sender, oldKey, key);
    }

    function disable(bytes calldata) external payable override {
        delete p256PublicKey[msg.sender];
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256) external payable override returns (ValidationData validationData) {
        (uint256 r, uint256 s) = abi.decode(_userOp.signature, (uint256, uint256));
        PublicKey memory key = p256PublicKey[_userOp.sender];
        bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
        if (P256.verifySignatureAllowMalleability(hash, r, s, key.x, key.y)) {
            return ValidationData.wrap(0);
        } 
        if (!P256.verifySignatureAllowMalleability(_userOpHash, r, s, key.x, key.y)) {
            return SIG_VALIDATION_FAILED;
        }
    }

    function validateSignature(bytes32 hash, bytes calldata signature) external view override returns (ValidationData) {
        (uint256 r, uint256 s) = abi.decode(signature, (uint256, uint256));
        PublicKey memory key = p256PublicKey[msg.sender];
        if (P256.verifySignatureAllowMalleability(hash, r, s, key.x, key.y)) {
            return ValidationData.wrap(0);
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        if (!P256.verifySignatureAllowMalleability(ethHash, r, s, key.x, key.y)) {
            return SIG_VALIDATION_FAILED;
        }
        return ValidationData.wrap(0);
    }

    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        revert NotImplemented();
    }
}
