// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IValidator.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "src/utils/KernelHelper.sol";
import "account-abstraction/core/Helpers.sol";
import "src/Kernel.sol";
import { WalletKernelStorage, ExecutionDetail} from "src/abstract/KernelStorage.sol";
import "./ECDSAValidator.sol";
import {KillSwitchAction} from "src/executor/KillSwitchAction.sol";

struct KillSwitchValidatorStorage {
    address guardian;
    IKernelValidator validator;
    uint48 pausedUntil;
    bytes4 disableMode;
}

contract KillSwitchValidator is IKernelValidator {
    mapping(address => KillSwitchValidatorStorage) public killSwitchValidatorStorage;

    function enable(bytes calldata enableData) external override {
        killSwitchValidatorStorage[msg.sender].guardian = address(bytes20(enableData[0:20]));
    }

    function disable(bytes calldata) external override {
        delete killSwitchValidatorStorage[msg.sender];
    }

    function validateSignature(bytes32 hash, bytes calldata signature) external view override returns (uint256) {
        KillSwitchValidatorStorage storage validatorStorage = killSwitchValidatorStorage[msg.sender];
        uint256 res = validatorStorage.validator.validateSignature(hash,signature);
        uint48 pausedUntil = validatorStorage.pausedUntil;
        ValidationData memory validationData = _parseValidationData(res);
        if(validationData.aggregator != address(1)) { // if signature verification has not been failed, return with the result
            uint256 delayedData = _packValidationData(false, 0, pausedUntil);
            return _packValidationData(_intersectTimeRange(res, delayedData));
        }
        return SIG_VALIDATION_FAILED;
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        override
        returns (uint256)
    {
        KillSwitchValidatorStorage storage validatorStorage = killSwitchValidatorStorage[_userOp.sender];
        uint48 pausedUntil = validatorStorage.pausedUntil;
        uint256 validationResult = 0;
        if(address(validatorStorage.validator) != address(0)){ // if validator != address(0), it means toggle switch is on
            // check for validator at first
            try validatorStorage.validator.validateUserOp(_userOp, _userOpHash, pausedUntil) returns (uint256 res) {
                validationResult = res;
            } catch {
                validationResult = SIG_VALIDATION_FAILED;
            }
            ValidationData memory validationData = _parseValidationData(validationResult);
            if(validationData.aggregator != address(1)) { // if signature verification has not been failed, return with the result
                uint256 delayedData = _packValidationData(false, 0, pausedUntil);
                return _packValidationData(_intersectTimeRange(validationResult, delayedData));
            } else if(bytes4(_userOp.callData[0:4]) == KillSwitchAction.toggleKillSwitch.selector) {
                bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
                address recovered = ECDSA.recover(hash, _userOp.signature);
                if (validatorStorage.guardian == recovered) {
                    return 0;
                }
            }
        }
        if(_userOp.signature.length == 71) {
            // save data to this storage
            validatorStorage.pausedUntil = uint48(bytes6(_userOp.signature[0:6]));
            validatorStorage.validator = KernelStorage(msg.sender).getDefaultValidator();
            validatorStorage.disableMode = KernelStorage(msg.sender).getDisabledMode();
            bytes32 hash = ECDSA.toEthSignedMessageHash(keccak256(bytes.concat(_userOp.signature[0:6],_userOpHash)));
            address recovered = ECDSA.recover(hash, _userOp.signature[6:]);
            if (validatorStorage.guardian != recovered) {
                return SIG_VALIDATION_FAILED;
            }
            return _packValidationData(false, 0, pausedUntil);
        }
        return SIG_VALIDATION_FAILED;
    }
}
