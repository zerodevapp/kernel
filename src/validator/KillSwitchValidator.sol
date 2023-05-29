// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IValidator.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "src/utils/KernelHelper.sol";
import "account-abstraction/core/Helpers.sol";
import "src/Kernel.sol";
import "./ECDSAValidator.sol";

struct KillSwitchValidatorStorage {
    address owner;
    address guardian;
    uint48 pausedUntil;
}

contract KillSwitchValidator is IKernelValidator {
    mapping(address => KillSwitchValidatorStorage) public killSwitchValidatorStorage;

    function enable(bytes calldata enableData) external override {
        killSwitchValidatorStorage[msg.sender].owner = address(bytes20(enableData[0:20]));
        killSwitchValidatorStorage[msg.sender].guardian = address(bytes20(enableData[20:40]));
    }

    function disable(bytes calldata) external override {
        delete killSwitchValidatorStorage[msg.sender];
    }

    function validateSignature(bytes32 hash, bytes calldata signature) external view override returns (uint256) {
        KillSwitchValidatorStorage storage validatorStorage = killSwitchValidatorStorage[msg.sender];
        return _packValidationData(
            validatorStorage.owner != ECDSA.recover(hash, signature), 0, validatorStorage.pausedUntil
        );
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        override
        returns (uint256)
    {
        address signer;
        bytes calldata signature;
        KillSwitchValidatorStorage storage validatorStorage = killSwitchValidatorStorage[_userOp.sender];
        if (_userOp.signature.length == 6 + 20 + 65) {
            require(bytes4(_userOp.callData[0:4]) != KernelStorage.disableMode.selector);
            signer = validatorStorage.guardian;
            uint48 pausedUntil = uint48(bytes6(_userOp.signature[0:6]));
            require(pausedUntil > validatorStorage.pausedUntil, "KillSwitchValidator: invalid pausedUntil");
            killSwitchValidatorStorage[_userOp.sender].pausedUntil = pausedUntil;
            signature = _userOp.signature[6:71];
        } else {
            signer = killSwitchValidatorStorage[_userOp.sender].owner;
            signature = _userOp.signature;
        }
        if (signer == ECDSA.recover(_userOpHash, signature)) {
            // address(0) attack has been resolved in ECDSA library
            return _packValidationData(false, 0, validatorStorage.pausedUntil);
        }

        bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
        address recovered = ECDSA.recover(hash, signature);
        if (signer != recovered) {
            return SIG_VALIDATION_FAILED;
        }
        return _packValidationData(false, 0, validatorStorage.pausedUntil);
    }
}
