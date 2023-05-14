// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IValidator.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "forge-std/console.sol";

struct ECDSAValidatorStorage {
    address owner;
}

uint256 constant SIG_VALIDATION_FAILED = 1;

contract ECDSAValidator is IKernelValidator {
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);

    mapping(address => ECDSAValidatorStorage) public ecdsaValidatorStorage;

    function disable(bytes calldata) external override {
        delete ecdsaValidatorStorage[msg.sender];
    }

    function enable(bytes calldata _data) external override {
        address owner = address(bytes20(_data[0:20]));
        address oldOwner = ecdsaValidatorStorage[msg.sender].owner;
        ecdsaValidatorStorage[msg.sender].owner = owner;
        emit OwnerChanged(oldOwner, owner);
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        view
        override
        returns (uint256 validationData)
    {
        address owner = ecdsaValidatorStorage[_userOp.sender].owner;
        if (owner == ECDSA.recover(_userOpHash, _userOp.signature)) {
            return 0;
        }

        bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
        address recovered = ECDSA.recover(hash, _userOp.signature);
        if (owner != recovered) {
            return SIG_VALIDATION_FAILED;
        }
    }

    function validateSignature(bytes32 hash, bytes calldata signature) public view override returns (uint256) {
        address owner = ecdsaValidatorStorage[msg.sender].owner;
        return owner == ECDSA.recover(hash, signature) ? 0 : 1;
    }
}
