// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {IKernel} from "../interfaces/IKernel.sol";
import {_intersectValidationData} from "../utils/KernelHelper.sol";
import {WalletKernelStorage, ExecutionDetail} from "../common/Structs.sol";
import {IKernelValidator} from "../interfaces/IKernelValidator.sol";
import {ValidationData, ValidAfter, ValidUntil, packValidationData, parseValidationData} from "../common/Types.sol";
import {KillSwitchAction} from "../executor/KillSwitchAction.sol";
import {SIG_VALIDATION_FAILED} from "../common/Constants.sol";

struct KillSwitchValidatorStorage {
    address guardian;
    IKernelValidator validator;
    ValidAfter pausedUntil;
    bytes4 disableMode;
}

contract KillSwitchValidator is IKernelValidator {
    mapping(address => KillSwitchValidatorStorage) public killSwitchValidatorStorage;

    function enable(bytes calldata enableData) external payable override {
        killSwitchValidatorStorage[msg.sender].guardian = address(bytes20(enableData[0:20]));
    }

    function disable(bytes calldata) external payable override {
        delete killSwitchValidatorStorage[msg.sender];
    }

    function validateSignature(bytes32, bytes calldata) external pure override returns (ValidationData) {
        revert NotImplemented();
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        override
        returns (ValidationData)
    {
        KillSwitchValidatorStorage storage validatorStorage = killSwitchValidatorStorage[msg.sender]; // should use msg.sender to prevent others from changing storage
        ValidAfter pausedUntil = validatorStorage.pausedUntil;
        ValidationData validationData;
        if (address(validatorStorage.validator) != address(0)) {
            // check for validator at first
            try validatorStorage.validator.validateUserOp(_userOp, _userOpHash, 0) returns (ValidationData res) {
                validationData = res;
            } catch {
                validationData = SIG_VALIDATION_FAILED;
            }
            (,, address result) = parseValidationData(validationData);
            if (result != address(1)) {
                // if signature verification has not been failed, return with the result
                ValidationData delayedData = packValidationData(pausedUntil, ValidUntil.wrap(0));
                return _intersectValidationData(validationData, delayedData);
            } else if (bytes4(_userOp.callData[0:4]) == KillSwitchAction.toggleKillSwitch.selector) {
                bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
                address recovered = ECDSA.recover(hash, _userOp.signature);
                if (validatorStorage.guardian == recovered) {
                    return packValidationData(ValidAfter.wrap(0), ValidUntil.wrap(0));
                }
            }
        }
        if (_userOp.signature.length == 71) {
            // save data to this storage
            validatorStorage.pausedUntil = ValidAfter.wrap(uint48(bytes6(_userOp.signature[0:6])));
            validatorStorage.validator = IKernel(msg.sender).getDefaultValidator();
            validatorStorage.disableMode = IKernel(msg.sender).getDisabledMode();
            bytes32 hash = ECDSA.toEthSignedMessageHash(keccak256(bytes.concat(_userOp.signature[0:6], _userOpHash)));
            address recovered = ECDSA.recover(hash, _userOp.signature[6:]);
            if (validatorStorage.guardian != recovered) {
                return SIG_VALIDATION_FAILED;
            }
            return packValidationData(pausedUntil, ValidUntil.wrap(0));
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    function validCaller(address, bytes calldata) external pure override returns (bool) {
        revert NotImplemented();
    }
}
